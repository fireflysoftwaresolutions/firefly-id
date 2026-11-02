#!/usr/bin/env python3
"""Prevalidate new hosted fixture passwords with the pinned native denylist; never start a service."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'org.firefly-id.password-preflight'
JAVA_SOURCE = ROOT / 'tooling/SyntheticPasswordDenylist.java'
DENYLIST = ROOT / 'config/password-blacklist.txt'


def require(value, message):
    if not value:
        raise ValueError(message)


def command(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=180, **kwargs)
    require(result.returncode == 0, 'Owned password preflight operation refused')
    return result.stdout


def hosted():
    require(all(os.environ.get(key) == value for key, value in (
        ('GITHUB_ACTIONS', 'true'), ('RUNNER_ENVIRONMENT', 'github-hosted'), ('RUNNER_OS', 'Linux'))),
        'Password preflight requires GitHub-hosted Linux Actions')
    require(not any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
        'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS')),
        'Runtime overrides refused for owned password preflight')
    run = os.environ.get('GITHUB_RUN_ID', '') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch(r'[0-9]+-[0-9]+', run), 'Hosted attempt identity required')
    require(json.loads(command(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}']))
            == 'unix:///var/run/docker.sock', 'Local hosted Docker required')
    return run


def pinned_image():
    return json.loads((ROOT / 'deploy/images.lock.json').read_text())['keycloak']['image']


def validate_container(owner, actual):
    require(actual['Id'] == owner['container_id'] and actual['Name'] == '/' + owner['container']
            and actual['Image'] == owner['image_id'] and actual['Config']['Image'] == owner['image']
            and actual['Config'].get('Labels', {}).get(LABEL) == owner['run'], 'Owned pinned container mismatch')
    require(actual['State']['Status'] == 'created' and not actual['State']['Running']
            and actual['HostConfig']['NetworkMode'] == 'none' and not actual['Mounts'],
            'Only the owned unstarted extraction container is admitted')


def inspect_container(owner):
    actual = json.loads(command(['docker', 'inspect', owner['container']]))[0]
    validate_container(owner, actual)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(directory):
    result = {}
    for folder, suffix in (('libraries', '.jar'), ('classes', '.class')):
        base = directory / folder
        require(base.is_dir() and not base.is_symlink(), 'Owned native files missing')
        for path in base.iterdir():
            require(path.is_file() and not path.is_symlink() and path.suffix == suffix,
                    'Unexpected owned native file')
            result[str(path.relative_to(directory))] = digest(path)
        require(any(name.startswith(folder + '/') for name in result), 'Empty native file inventory')
    return result


def match(directory, values):
    require(0 < len(values) <= 64 and all(isinstance(value, str) and 0 < len(value) <= 128
            and all(32 <= ord(char) <= 126 for char in value) for value in values), 'Bounded fixture candidates required')
    classpath = str(directory / 'classes') + os.pathsep + str(directory / 'libraries/*')
    result = subprocess.run(['java', '-cp', classpath, 'SyntheticPasswordDenylist', str(DENYLIST.parent)],
                            input=('\n'.join(values) + '\n').encode(), capture_output=True, timeout=30)
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and len(lines) == len(values)
            and all(line in (b'ACCEPT', b'REJECT') for line in lines), 'Native password matcher refused')
    return [line == b'ACCEPT' for line in lines]


def prepare():
    run = hosted()
    directory = ROOT / '.state' / ('password-preflight-' + run)
    require(not directory.exists() and not directory.is_symlink() and not (ROOT / '.state').is_symlink(),
            'Fresh password preflight state required')
    image = pinned_image()
    command(['docker', 'pull', image])
    image_id = json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
    name = 'ff-password-preflight-' + run
    existing = subprocess.run(['docker', 'inspect', name], capture_output=True)
    require(existing.returncode != 0, 'Existing extraction container refused')
    directory.mkdir(parents=True, mode=0o700)
    owner = {'run': run, 'root': str(directory), 'container': name, 'image': image, 'image_id': image_id}
    # This container is never started or removed; the hosted runner owns its eventual disposal.
    owner['container_id'] = command(['docker', 'create', '--name', name, '--label', LABEL + '=' + run,
        '--network', 'none', '--entrypoint', '/bin/false', image]).decode().strip()
    inspect_container(owner)
    (directory / 'ownership.json').write_text(json.dumps(owner))
    command(['docker', 'cp', name + ':/opt/keycloak/lib/lib/main', str(directory / 'libraries')])
    (directory / 'classes').mkdir(mode=0o700)
    command(['javac', '-cp', str(directory / 'libraries/*'), '-d', str(directory / 'classes'), str(JAVA_SOURCE)])
    baseline = DENYLIST.read_text().splitlines()
    require(baseline and not any(match(directory, baseline)), 'Native baseline denylist sanity check refused')
    owner.update(files=inventory(directory), denylist_sha256=digest(DENYLIST), source_sha256=digest(JAVA_SOURCE))
    (directory / 'ownership.json').write_text(json.dumps(owner))
    print('Prepared owned native password preflight; no service or database started.')


def load_checker():
    run = hosted()
    directory = ROOT / '.state' / ('password-preflight-' + run)
    require(directory.resolve() == directory and not directory.is_symlink()
            and not any(path.is_symlink() for path in directory.rglob('*')), 'Canonical owned password preflight required')
    owner = json.loads((directory / 'ownership.json').read_text())
    require(owner['run'] == run and owner['root'] == str(directory)
            and owner['container'] == 'ff-password-preflight-' + run and owner['image'] == pinned_image(),
            'Password preflight ownership mismatch')
    inspect_container(owner)
    require(owner['files'] == inventory(directory) and owner['denylist_sha256'] == digest(DENYLIST)
            and owner['source_sha256'] == digest(JAVA_SOURCE), 'Native matcher inputs changed')
    return lambda candidate: match(directory, [candidate])[0]


if __name__ == '__main__':
    os.umask(0o077)
    try:
        prepare()
    except Exception:
        raise SystemExit('Owned native password preflight refused; no credentials or raw diagnostics emitted.')
