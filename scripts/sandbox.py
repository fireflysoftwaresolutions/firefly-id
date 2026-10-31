#!/usr/bin/env python3
"""Bounded sandbox lifecycle. Stop preserves data; deletion is deliberately absent."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MIN_FREE = 12 * 1024 ** 3


def require_local_endpoint(endpoint):
    parsed = urlsplit(endpoint)
    if parsed.scheme != 'unix' or parsed.netloc or not parsed.path.startswith('/'):
        raise RuntimeError('This sandbox requires a local Unix Docker socket. Remote contexts and TCP endpoints are not supported; no Docker mutation was performed.')


def check_local_engine():
    # DOCKER_CONTEXT takes precedence over DOCKER_HOST in the Docker CLI.
    if not os.environ.get('DOCKER_CONTEXT') and os.environ.get('DOCKER_HOST'):
        endpoint = os.environ['DOCKER_HOST']
    else:
        command = ['docker', 'context', 'inspect']
        if os.environ.get('DOCKER_CONTEXT'):
            command.append(os.environ['DOCKER_CONTEXT'])
        inspected = subprocess.run(command, text=True, capture_output=True, check=True, timeout=10)
        endpoint = json.loads(inspected.stdout)[0]['Endpoints']['docker']['Host']
    require_local_endpoint(endpoint)


def check_capacity(free):
    if free < MIN_FREE:
        raise RuntimeError(f'At least 12 GiB free disk is required; available: {free / 1024 ** 3:.2f} GiB. No Docker action was performed. No automatic cleanup is permitted.')


def load_owned_state(state):
    if state.is_symlink():
        raise RuntimeError('State must be a real owned directory, not a symlink.')
    owner = json.loads((state / 'ownership.json').read_text())
    if (owner.get('mode') != 'sandbox' or
            owner.get('created_by') != 'firefly-id/scripts/generate.py' or
            not re.fullmatch(r'firefly-id-sandbox-[a-f0-9]{10}', owner.get('project', '')) or
            owner.get('compose') != str(state / 'compose.json')):
        raise RuntimeError('Ownership marker does not identify this generated sandbox.')
    config = (state / 'compose.json').read_bytes()
    if hashlib.sha256(config).hexdigest() != owner.get('compose_sha256'):
        raise RuntimeError('Generated Compose changed; refusing lifecycle actions on untracked resources.')
    if json.loads(config).get('name') != owner['project']:
        raise RuntimeError('Compose project differs from ownership marker.')
    return owner


def run(command, timeout=30):
    subprocess.run(command, check=True, timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['preflight', 'pull', 'up', 'status', 'stop'])
    parser.add_argument('--state', type=Path, default=ROOT / '.state/sandbox')
    args = parser.parse_args()
    state = args.state.absolute()
    try:
        owner = load_owned_state(state)
        if args.action in ('preflight', 'pull', 'up'):
            check_capacity(shutil.disk_usage(state).free)
            if not all((Path(owner['theme_dir']) / kind / 'theme.properties').is_file()
                       for kind in ('login', 'account', 'admin', 'email', 'welcome')):
                raise RuntimeError('Built theme is missing; run python3 tooling/build_theme.py first.')
        check_local_engine()
        base = ['docker', 'compose', '--project-name', owner['project'], '-f', owner['compose']]
        if args.action == 'preflight':
            run(['docker', 'info', '--format', '{{.ServerVersion}}'])
            run(base + ['config', '--quiet'])
            print('Capacity and Compose syntax checks passed. Runtime acceptance is separate.')
        elif args.action == 'pull':
            run(base + ['pull'], timeout=600)
        elif args.action == 'up':
            run(base + ['config', '--quiet'])
            run(base + ['up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '180'], timeout=210)
        elif args.action == 'status':
            run(base + ['ps', '--format', 'json'])
        elif args.action == 'stop':
            run(base + ['stop', '--timeout', '30'], timeout=45)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
