#!/usr/bin/env python3
"""Observe an owned sandbox startup failure without publishing its private logs."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('startup_sandbox', ROOT / 'scripts/sandbox.py')
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)

EXCEPTIONS = {
    'BindException', 'BuildException', 'CertificateException', 'ClassNotFoundException',
    'ConfigurationException', 'DeploymentException', 'IllegalArgumentException',
    'IllegalStateException', 'JDBCConnectionException', 'ModelDuplicateException',
    'NoClassDefFoundError', 'NullPointerException', 'OutOfMemoryError', 'PersistenceException',
    'PSQLException', 'RuntimeException', 'ServiceConfigurationError', 'SQLException',
    'SQLGrammarException', 'SSLException', 'SSLHandshakeException', 'TemplateException',
    'TemplateNotFoundException',
}
STATES = {'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'}
STATE_FORMAT = ('{"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                '"status":{{json .State.Status}},"exit_code":{{json .State.ExitCode}},'
                '"oom_killed":{{json .State.OOMKilled}}}')


def capture(command, limit=65536, timeout=10):
    """Keep only bounded bytes; neither child stream is inherited by the caller."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    content = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError()
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                break
            available = limit - len(content)
            content.extend(chunk[:available])
            if len(chunk) > available:
                truncated = True
                break
        if not truncated:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise TimeoutError() from None
            if process.returncode:
                raise RuntimeError('CAPTURE_FAILED')
        return bytes(content), truncated
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        process.stdout.close()


def classify(logs):
    pattern = r'(?<![\w$])(?:[\w$]+\.)*(' + '|'.join(sorted(EXCEPTIONS)) + r')(?![\w$])'
    classes = sorted(set(re.findall(pattern, logs)))
    observed = set(classes)
    causes = set()
    groups = {
        'MEMORY_ALLOCATION_FAILURE': {'OutOfMemoryError'},
        'DATABASE_FAILURE': {'PSQLException', 'SQLException', 'SQLGrammarException', 'JDBCConnectionException'},
        'REALM_IMPORT_FAILURE': {'ModelDuplicateException'},
        'CONFIGURATION_FAILURE': {'ConfigurationException'},
        'AUGMENTATION_FAILURE': {'BuildException', 'DeploymentException'},
        'LISTENER_BIND_FAILURE': {'BindException'},
        'TLS_FAILURE': {'SSLException', 'SSLHandshakeException', 'CertificateException'},
        'THEME_FAILURE': {'TemplateException', 'TemplateNotFoundException'},
        'PROVIDER_LOADING_FAILURE': {'ServiceConfigurationError', 'NoClassDefFoundError', 'ClassNotFoundException'},
    }
    for category, kinds in groups.items():
        if observed & kinds:
            causes.add(category)
    if re.search(r'failed to import realm', logs, re.IGNORECASE):
        causes.add('REALM_IMPORT_FAILURE')
    if re.search(r'unknown option|unmatched argument', logs, re.IGNORECASE):
        causes.add('CONFIGURATION_FAILURE')
    if not causes:
        causes.add('UNKNOWN_STARTUP_FAILURE' if logs.strip() else 'EMPTY_LOG_WINDOW')
    return {'causes': sorted(causes), 'exception_classes': classes}


def report(source):
    return {'schema_version': 1, 'scope': 'Owned synthetic Keycloak startup observations only',
            'source': source if isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source) else None,
            'collection_status': 'UNAVAILABLE', 'causes': [], 'exception_classes': [],
            'process': None, 'log_truncated': False}


def collect(state, source):
    result = report(source)
    phase = 'OWNERSHIP_REFUSED'
    try:
        owner = sandbox.load_owned_state(state)
        phase = 'LOCAL_ENGINE_REFUSED'
        sandbox.check_local_engine()
        phase = 'CONTAINER_RESOLUTION_FAILED'
        command = ['docker', 'compose', '--project-name', owner['project'], '-f', owner['compose'],
                   'ps', '--all', '--quiet', 'keycloak']
        content, truncated = capture(command, limit=4096)
        container = content.decode('utf-8').strip()
        if truncated or not re.fullmatch('[0-9a-f]{64}', container):
            raise ValueError()
        phase = 'CONTAINER_INSPECTION_FAILED'
        content, truncated = capture(['docker', 'inspect', '--format', STATE_FORMAT, container], limit=8192)
        metadata = json.loads(content)
        if truncated or not isinstance(metadata, dict):
            raise ValueError()
        phase = 'CONTAINER_OWNERSHIP_REFUSED'
        if metadata.get('project') != owner['project'] or metadata.get('service') != 'keycloak':
            raise ValueError()
        phase = 'CONTAINER_INSPECTION_FAILED'
        if (metadata.get('status') not in STATES or type(metadata.get('exit_code')) is not int
                or not 0 <= metadata['exit_code'] <= 255 or type(metadata.get('oom_killed')) is not bool):
            raise ValueError()
        result['process'] = {key: metadata[key] for key in ('status', 'exit_code', 'oom_killed')}
        phase = 'LOG_COLLECTION_FAILED'
        content, result['log_truncated'] = capture(['docker', 'logs', '--tail', '120', container])
        result.update(classify(content.decode('utf-8', errors='replace')))
        if result['process']['oom_killed']:
            result['causes'] = sorted(set(result['causes']) | {'OOM_KILLED'})
        result['collection_status'] = 'COLLECTED'
    except Exception:
        result['causes'] = [phase]
        if phase in {'OWNERSHIP_REFUSED', 'LOCAL_ENGINE_REFUSED', 'CONTAINER_OWNERSHIP_REFUSED'}:
            result['collection_status'] = 'REFUSED'
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError()


def main():
    source = os.environ.get('GITHUB_SHA')
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument('--state', type=Path, default=ROOT / '.state/sandbox')
        args = parser.parse_args()
        result = collect(args.state.absolute(), source)
    except Exception:
        result = report(source)
        result['causes'] = ['INPUT_INVALID']
    try:
        output = ROOT / '.work/startup-diagnostics'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    except OSError:
        result = report(source)
        result['causes'] = ['SUMMARY_WRITE_FAILED']
    print(json.dumps(result, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
