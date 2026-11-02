#!/usr/bin/env python3
"""Prevalidate new hosted fixture passwords with the pinned native denylist; never start a service."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import traceback
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'org.firefly-id.password-preflight'
JAVA_SOURCE = ROOT / 'tooling/SyntheticPasswordDenylist.java'
DENYLIST = ROOT / 'config/password-blacklist.txt'
PHASE = 'HOSTED_GUARDS'
LAST_PROCESS = None
LIBRARIES = None
PHASES = {'HOSTED_GUARDS', 'FRESH_STATE', 'IMAGE_PULL', 'IMAGE_INSPECT', 'CONTAINER_ABSENCE',
          'CONTAINER_CREATE', 'CONTAINER_INSPECT', 'LIBRARY_EXTRACTION', 'LIBRARY_INSPECTION',
          'BOOT_LIBRARY_EXTRACTION',
          'NATIVE_COMPILATION', 'BASELINE_MATCH', 'RECEIPT_WRITE', 'READY', 'RECEIPT_READ',
          'INPUT_INTEGRITY', 'CANDIDATE_MATCH'}


def process_diagnostic(result):
    output = (result.stdout + result.stderr).decode(errors='replace')
    markers = {'error: cannot find symbol': 'COMPILER_MISSING_SYMBOL',
               'package org.keycloak.policy does not exist': 'COMPILER_NATIVE_POLICY_MISSING',
               'package com.google.common.hash does not exist': 'COMPILER_GUAVA_MISSING',
               'has private access in': 'COMPILER_PRIVATE_ACCESS',
               'class file has wrong version': 'COMPILER_CLASS_VERSION',
               'Could not find or load main class': 'JAVA_MAIN_MISSING',
               'PREFLIGHT_ERROR:LINKAGE': 'JAVA_LINKAGE', 'PREFLIGHT_ERROR:IO': 'JAVA_IO',
               'PREFLIGHT_ERROR:ARGUMENT': 'JAVA_ARGUMENT', 'PREFLIGHT_ERROR:OTHER': 'JAVA_OTHER'}
    return {'returnCode': result.returncode if -128 <= result.returncode <= 255 else None,
            'stdoutLines': min(len(result.stdout.splitlines()), 1000),
            'stderrLines': min(len(result.stderr.splitlines()), 1000),
            'categories': sorted({category for marker, category in markers.items() if marker in output})}


def failure_summary(failure):
    names = {'ValueError', 'KeyError', 'TypeError', 'FileNotFoundError', 'PermissionError', 'TimeoutExpired', 'BadZipFile'}
    return {'status': 'FAILED', 'phase': PHASE if PHASE in PHASES else 'UNKNOWN',
            'failureKind': type(failure).__name__ if type(failure).__name__ in names else 'OTHER',
            'sourceLines': [frame.lineno for frame in traceback.extract_tb(failure.__traceback__)
                            if Path(frame.filename).resolve() == Path(__file__).resolve()][-6:],
            'process': LAST_PROCESS, 'libraries': LIBRARIES}


def save_summary(summary):
    directory = ROOT / '.work/password-preflight'
    require(directory.resolve() == directory and not directory.is_symlink(), 'Canonical evidence path required')
    directory.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(directory / 'summary.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as stream:
        stream.write(json.dumps(summary, indent=2) + '\n')


def inspect_libraries(directory):
    expected = {'NATIVE_FACTORY': 'org/keycloak/policy/DenylistPasswordPolicyProviderFactory.class',
                'NATIVE_FILE_MATCHER': 'org/keycloak/policy/DenylistPasswordPolicyProviderFactory$FileBasedPasswordDenylist.class',
                'GUAVA_BLOOM': 'com/google/common/hash/BloomFilter.class', 'JBOSS_LOGGING': 'org/jboss/logging/Logger.class'}
    jars = []
    for folder in ('boot-libraries', 'libraries'):
        base = directory / folder
        require(base.is_dir() and not base.is_symlink(), 'Owned native library directory required')
        jars.extend(base.iterdir())
    found = set()
    for path in jars:
        require(path.is_file() and not path.is_symlink() and path.suffix == '.jar', 'Unexpected native library file')
        with zipfile.ZipFile(path) as archive:
            found.update(set(archive.namelist()) & set(expected.values()))
    return {'jarCount': len(jars), 'classesPresent': {name: path in found for name, path in expected.items()}}


def require_native_libraries(directory):
    global LIBRARIES
    LIBRARIES = inspect_libraries(directory)
    require(all(LIBRARIES['classesPresent'].values()), 'Required pinned native classes are missing')


def native_classpath(directory):
    return os.pathsep.join(str(directory / path) for path in ('classes', 'boot-libraries/*', 'libraries/*'))


def require(value, message):
    if not value:
        raise ValueError(message)


def command(arguments, **kwargs):
    global LAST_PROCESS
    result = subprocess.run(arguments, capture_output=True, timeout=180, **kwargs)
    LAST_PROCESS = process_diagnostic(result)
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
    for folder, suffix in (('libraries', '.jar'), ('boot-libraries', '.jar'), ('classes', '.class')):
        base = directory / folder
        require(base.is_dir() and not base.is_symlink(), 'Owned native files missing')
        for path in base.iterdir():
            require(path.is_file() and not path.is_symlink() and path.suffix == suffix,
                    'Unexpected owned native file')
            result[str(path.relative_to(directory))] = digest(path)
        require(any(name.startswith(folder + '/') for name in result), 'Empty native file inventory')
    return result


def match(directory, values):
    global LAST_PROCESS
    require(0 < len(values) <= 64 and all(isinstance(value, str) and 0 < len(value) <= 128
            and all(32 <= ord(char) <= 126 for char in value) for value in values), 'Bounded fixture candidates required')
    classpath = native_classpath(directory)
    result = subprocess.run(['java', '-cp', classpath, 'SyntheticPasswordDenylist', str(DENYLIST.parent)],
                            input=('\n'.join(values) + '\n').encode(), capture_output=True, timeout=30)
    LAST_PROCESS = process_diagnostic(result)
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and len(lines) == len(values)
            and all(line in (b'ACCEPT', b'REJECT') for line in lines), 'Native password matcher refused')
    return [line == b'ACCEPT' for line in lines]


def prepare():
    global PHASE, LIBRARIES
    PHASE = 'HOSTED_GUARDS'
    run = hosted()
    PHASE = 'FRESH_STATE'
    directory = ROOT / '.state' / ('password-preflight-' + run)
    require(not directory.exists() and not directory.is_symlink() and not (ROOT / '.state').is_symlink(),
            'Fresh password preflight state required')
    image = pinned_image()
    PHASE = 'IMAGE_PULL'
    command(['docker', 'pull', image])
    PHASE = 'IMAGE_INSPECT'
    image_id = json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
    name = 'ff-password-preflight-' + run
    PHASE = 'CONTAINER_ABSENCE'
    existing = subprocess.run(['docker', 'inspect', name], capture_output=True)
    require(existing.returncode != 0, 'Existing extraction container refused')
    directory.mkdir(parents=True, mode=0o700)
    owner = {'run': run, 'root': str(directory), 'container': name, 'image': image, 'image_id': image_id}
    # This container is never started or removed; the hosted runner owns its eventual disposal.
    PHASE = 'CONTAINER_CREATE'
    owner['container_id'] = command(['docker', 'create', '--name', name, '--label', LABEL + '=' + run,
        '--network', 'none', '--entrypoint', '/bin/false', image]).decode().strip()
    PHASE = 'CONTAINER_INSPECT'
    inspect_container(owner)
    (directory / 'ownership.json').write_text(json.dumps(owner))
    PHASE = 'LIBRARY_EXTRACTION'
    command(['docker', 'cp', name + ':/opt/keycloak/lib/lib/main', str(directory / 'libraries')])
    PHASE = 'BOOT_LIBRARY_EXTRACTION'
    inspect_container(owner)
    command(['docker', 'cp', name + ':/opt/keycloak/lib/lib/boot', str(directory / 'boot-libraries')])
    PHASE = 'LIBRARY_INSPECTION'
    require_native_libraries(directory)
    (directory / 'classes').mkdir(mode=0o700)
    PHASE = 'NATIVE_COMPILATION'
    command(['javac', '-cp', native_classpath(directory), '-d', str(directory / 'classes'), str(JAVA_SOURCE)])
    PHASE = 'BASELINE_MATCH'
    baseline = DENYLIST.read_text().splitlines()
    require(baseline and not any(match(directory, baseline)), 'Native baseline denylist sanity check refused')
    PHASE = 'RECEIPT_WRITE'
    owner.update(files=inventory(directory), denylist_sha256=digest(DENYLIST), source_sha256=digest(JAVA_SOURCE))
    (directory / 'ownership.json').write_text(json.dumps(owner))
    PHASE = 'READY'
    save_summary({'status': 'PASSED', 'phase': PHASE, 'baselineEntriesRejected': len(baseline), 'libraries': LIBRARIES})
    print('Prepared owned native password preflight; no service or database started.')


def load_checker():
    global PHASE
    PHASE = 'HOSTED_GUARDS'
    run = hosted()
    PHASE = 'RECEIPT_READ'
    directory = ROOT / '.state' / ('password-preflight-' + run)
    require(directory.resolve() == directory and not directory.is_symlink()
            and not any(path.is_symlink() for path in directory.rglob('*')), 'Canonical owned password preflight required')
    owner = json.loads((directory / 'ownership.json').read_text())
    require(owner['run'] == run and owner['root'] == str(directory)
            and owner['container'] == 'ff-password-preflight-' + run and owner['image'] == pinned_image(),
            'Password preflight ownership mismatch')
    inspect_container(owner)
    PHASE = 'INPUT_INTEGRITY'
    require(owner['files'] == inventory(directory) and owner['denylist_sha256'] == digest(DENYLIST)
            and owner['source_sha256'] == digest(JAVA_SOURCE), 'Native matcher inputs changed')
    def check(candidate):
        global PHASE
        PHASE = 'CANDIDATE_MATCH'
        try:
            return match(directory, [candidate])[0]
        except Exception as failure:
            save_summary(failure_summary(failure))
            raise
    return check


if __name__ == '__main__':
    os.umask(0o077)
    try:
        prepare()
    except Exception as failure:
        summary = failure_summary(failure)
        save_summary(summary)
        print(json.dumps(summary))
        raise SystemExit('Owned native password preflight refused; no credentials or raw diagnostics emitted.')
