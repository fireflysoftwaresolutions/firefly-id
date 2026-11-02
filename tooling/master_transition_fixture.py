#!/usr/bin/env python3
"""Hosted synthetic master qualification; exact import and retained transition are separate experiments."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('privileged_profile', ROOT / 'tooling/privileged_profile.py')
profile = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(profile)
LABEL = 'org.firefly-id.master-transition'
ORIGIN = 'https://id.firefly.test:8443'
PHASE = 'initialization'
PROFILE_DIAGNOSTIC = None


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_owner(root, directory, owner, run_id):
    require(re.fullmatch(r'[0-9]+-[0-9]+', run_id), 'Hosted attempt identity required')
    expected = root / '.state' / ('master-' + run_id)
    require(directory == expected and directory.resolve() == expected and not directory.is_symlink(), 'Owned canonical state path required')
    project = 'ff-master-' + run_id
    require(owner.get('run') == run_id and owner.get('root') == str(expected)
            and owner.get('kind') == 'master-transition' and owner.get('project') == project, 'State ownership mismatch')
    allowed = {project + '-' + kind for kind in ('postgres', 'mailpit', 'retained', 'imported', 'export', 'import')}
    require(isinstance(owner.get('containers'), list) and set(owner['containers']) <= allowed, 'Container ownership mismatch')
    require(not any(path.is_symlink() for path in directory.rglob('*')), 'Symlink inside owned state refused')
    return owner


def profile_diagnostic(document, failure):
    gates = {
        'Unsupported realm fields refused': 'UNSUPPORTED_REALM_FIELDS',
        'Realm extension attributes require explicit review': 'REALM_ATTRIBUTES',
        'Unsupported client fields refused': 'UNSUPPORTED_CLIENT_FIELDS',
        'Unsupported client attributes refused': 'CLIENT_ATTRIBUTES',
        'Only native signing-key components are supported': 'COMPONENTS',
        'Custom flow topology requires explicit review': 'FLOW_TOPOLOGY',
        'Unsupported authenticator extension refused': 'AUTHENTICATOR_PROVIDER',
        'Custom authenticator configuration requires explicit review': 'AUTHENTICATOR_CONFIG',
        'Custom client policy/profile execution requires separate review': 'CLIENT_POLICIES',
        'Unsupported required-action provider refused': 'REQUIRED_ACTION_PROVIDER',
        'Alternate authorization features are unsupported': 'ALTERNATE_AUTHORIZATION',
        'Client alternate grant or service account must already be disabled': 'CLIENT_ALTERNATE_GRANTS',
        'Offline access is outside this profile': 'OFFLINE_ACCESS',
        'Other interactive clients must already be disabled': 'INTERACTIVE_CLIENTS',
        'Existing permanent password and two-factor WebAuthn enrollment required': 'PRE_ENROLLED_CREDENTIALS',
        'Outstanding user required actions must be resolved before transition': 'OUTSTANDING_USER_ACTIONS',
        'Exact administrative console origin and redirect required': 'CONSOLE_ORIGINS',
        'Effective flow execution topology differs': 'FLOW_READBACK',
        'Effective client controls differ': 'CLIENT_READBACK',
        'Effective required actions differ': 'ACTION_READBACK',
        'Signing component inventory differs': 'SIGNING_COMPONENT_READBACK',
    }
    upstream_fields = {'userManagedAccessAllowed', 'defaultSignatureAlgorithm', 'maxSecondaryAuthFailures',
                       'otpPolicyCodeReusable', 'localizationTexts', 'webAuthnPolicyPasswordlessMediation',
                       'adminPermissionsClient', 'applications', 'applicationScopeMappings', 'defaultRoles',
                       'clientTemplates', 'social', 'socialProviders', 'userCacheEnabled', 'realmCacheEnabled'}
    known_attributes = {'frontendUrl', 'cibaBackchannelTokenDeliveryMode', 'cibaAuthRequestedUserHint',
                        'oauth2DeviceCodeLifespan', 'oauth2DevicePollingInterval', 'parRequestUriLifespan',
                        'clientOfflineSessionIdleTimeout', 'clientSessionMaxLifespan', 'clientSessionIdleTimeout'}
    message = str(failure)
    result = {'gate': gates.get(message, 'UNCLASSIFIED'),
              'unsupportedRealmFieldCount': len(set(document) - profile.REALM_FIELDS),
              'knownUnsupportedRealmFields': sorted((set(document) - profile.REALM_FIELDS) & upstream_fields),
              'realmAttributeCount': len(document.get('attributes') or {}),
              'knownRealmAttributes': sorted(set(document.get('attributes') or {}) & known_attributes)}
    for prefix in ('Preserved realm setting differs: ', 'Effective realm control differs: '):
        if message.startswith(prefix) and message[len(prefix):] in profile.REALM_FIELDS:
            result.update(gate='REALM_READBACK', field=message[len(prefix):])
    return result


def candidate_receipt(directory):
    path = directory / 'candidate.json'
    require(path.is_file() and not path.is_symlink(), 'Exact regular candidate file required')
    content = path.read_bytes()
    require(profile.parse_document(content).get('realm') == 'master', 'Master candidate required')
    return {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}


def verify_candidate(directory, receipt):
    require(candidate_receipt(directory) == receipt, 'Exact generated candidate changed')


def verify_effective(candidate, effective, retirement_window=None):
    # Partial export omits users; identity/credential/role retention is checked independently.
    checked = dict(effective, users=candidate['users'])
    console = next(client for client in candidate['clients'] if client['clientId'] == 'security-admin-console')
    profile.prerequisites(checked, 'master', console['webOrigins'][0])
    def canonical(value, ignored=frozenset()):
        if isinstance(value, dict):
            return {key: canonical(item, ignored) for key, item in value.items() if key not in ignored}
        if isinstance(value, list):
            return sorted((canonical(item, ignored) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
        return value
    special = {'users', 'authenticationFlows', 'requiredActions', 'clients', 'components', 'keycloakVersion'}
    for key in (set(candidate) | set(effective)) - special:
        if key == 'notBefore' and retirement_window is not None:
            value = effective.get(key)
            require(isinstance(value, int) and value >= candidate.get(key, 0)
                    and retirement_window['minimum'] <= value <= retirement_window['maximum'], 'Retirement watermark outside measured operation')
            continue
        require(canonical(candidate.get(key)) == canonical(effective.get(key)), 'Preserved realm setting differs: ' + key)
    # Signing private-key values may be redacted by the admin partial-export endpoint.
    def components(document):
        result = json.loads(json.dumps(document.get('components', {})))
        for component in result.get('org.keycloak.keys.KeyProvider', []):
            component.get('config', {}).pop('privateKey', None)
        return canonical(result)
    require(components(candidate) == components(effective), 'Signing component inventory differs')
    expected = profile.controls(profile.origin_host('https://' + candidate['webAuthnPolicyRpId']))
    for key in expected:
        if key in ('authenticationFlows', 'requiredActions'):
            continue
        require(effective.get(key) == candidate[key], 'Effective realm control differs: ' + key)
    def flows(document):
        result = {}
        for item in document.get('authenticationFlows', []):
            require(item['alias'] not in result, 'Duplicate effective flow')
            steps = sorted(item.get('authenticationExecutions', []), key=lambda value: value['priority'])
            result[item['alias']] = [item.get('providerId'), item.get('topLevel'), item.get('builtIn'), [
                {key: execution.get(key) for key in ('authenticator', 'authenticatorFlow', 'requirement', 'priority', 'flowAlias', 'authenticatorConfig')}
                for execution in steps]]
        return result
    require(flows(candidate) == flows(effective), 'Effective flow execution topology differs')
    def actions(document):
        values = document.get('requiredActions', [])
        require(len({item['alias'] for item in values}) == len(values), 'Duplicate effective action')
        return {item['alias']: {key: item.get(key, {} if key == 'config' else None)
                               for key in ('providerId', 'enabled', 'defaultAction', 'priority', 'config')} for item in values}
    require(actions(candidate) == actions(effective), 'Effective required actions differ')
    client_keys = ('id', 'enabled', 'protocol', 'publicClient', 'bearerOnly', 'standardFlowEnabled',
                   'directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled', 'authorizationServicesEnabled',
                   'authenticationFlowBindingOverrides', 'attributes', 'redirectUris', 'webOrigins',
                   'defaultClientScopes', 'optionalClientScopes', 'fullScopeAllowed', 'consentRequired', 'clientAuthenticatorType',
                   'protocolMappers', 'notBefore', 'frontchannelLogout', 'registeredNodes', 'rootUrl', 'adminUrl', 'baseUrl', 'type')
    def clients(document):
        values = document.get('clients', [])
        require(len({item['clientId'] for item in values}) == len(values), 'Duplicate effective client')
        result = {}
        for item in values:
            normalized = {}
            for key in client_keys:
                default = {} if key in ('attributes', 'authenticationFlowBindingOverrides') else [] if key in (
                    'redirectUris', 'webOrigins', 'defaultClientScopes', 'optionalClientScopes') else False if key == 'authorizationServicesEnabled' else None
                value = item.get(key, default)
                normalized[key] = canonical(value, frozenset({'id'}) if key == 'protocolMappers' else frozenset())
            result[item['clientId']] = normalized
        return result
    require(clients(candidate) == clients(effective), 'Effective client controls differ')


def verify_retained(before, after):
    for key in set(before) - {'events', 'adminEvents'}:
        require(before[key] == after[key], 'Retained identity material changed: ' + key)
    for key in ('events', 'adminEvents'):
        require(before[key] and set(before[key]) <= set(after[key]), 'Retained audit rows disappeared: ' + key)


def require_hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'Owned hosted Linux runner required')
    require(not any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')),
            'Docker override refused')
    endpoint = subprocess.check_output(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], text=True)
    require(json.loads(endpoint) == 'unix:///var/run/docker.sock', 'Local hosted Docker required')


def state():
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    directory = ROOT / '.state' / ('master-' + run_id)
    owner = json.loads((directory / 'ownership.json').read_text())
    return directory, validate_owner(ROOT, directory, owner, run_id)


def private_write(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as stream:
        stream.write(value)


def save_owner(directory, owner):
    private_write(directory / 'ownership.json', json.dumps(owner))


def run(command, directory, label, *, input=None, env=None):
    global PHASE
    PHASE = label
    with (directory / 'logs' / (label + '.log')).open('ab') as output:
        result = subprocess.run(command, input=input, stdout=output, stderr=subprocess.STDOUT, env=env)
    require(result.returncode == 0, 'Owned lifecycle phase refused')


def inspect_container(owner, kind):
    name = owner['project'] + '-' + kind
    require(name in owner['containers'], 'Container not owned by receipt')
    result = subprocess.run(['docker', 'inspect', name], capture_output=True)
    require(result.returncode == 0, 'Owned container missing')
    actual = json.loads(result.stdout)[0]
    require(actual['Config'].get('Labels', {}).get(LABEL) == owner['run'], 'Container ownership label mismatch')
    require(actual['Config']['Image'] == images()[kind if kind in ('postgres', 'mailpit') else 'keycloak']['image'], 'Pinned owned image required')
    if kind == 'mailpit':
        bindings = actual['HostConfig']['PortBindings']
        require(all(bindings.get(str(port) + '/tcp') == [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]
                    for port in (1025, 8025)), 'Owned loopback mail transport required')
    elif kind == 'postgres':
        require(actual['HostConfig']['PortBindings'].get('5432/tcp') == [{'HostIp': '127.0.0.1', 'HostPort': '5432'}], 'Loopback database binding required')
    else:
        require(actual['HostConfig']['NetworkMode'] == 'host', 'Owned local native network required')
        database = 'master_imported' if kind in ('import', 'imported') else 'master_retained'
        require('KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/' + database in actual['Config']['Env'], 'Owned database binding mismatch')
        mounts = {item['Destination']: item['Source'] for item in actual['Mounts']}
        require(mounts.get('/run/tls') == owner['root'] + '/tls' and mounts.get('/run/exchange') == owner['root'] + '/exchange'
                and mounts.get('/opt/keycloak/providers') == owner['root'] + '/providers', 'Owned native mounts mismatch')
    return name, actual


def stop_kind(directory, owner, kind):
    name, actual = inspect_container(owner, kind)
    if actual['State']['Running']:
        run(['docker', 'stop', '--time', '30', name], directory, kind + '-stop')


def psql(directory, owner, sql, database='postgres'):
    name, _ = inspect_container(owner, 'postgres')
    result = subprocess.run(['docker', 'exec', '-i', name, 'psql', '-X', '-U', 'postgres', '-d', database,
                             '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=sqlstate', '-At'], input=sql.encode(), capture_output=True)
    require(result.returncode == 0, 'Owned database operation refused')
    return result.stdout.decode().strip()


def wait_ready(directory):
    context = ssl.create_default_context(cafile=str(directory / 'tls/ca.crt'))
    for _ in range(120):
        try:
            with urllib.request.urlopen(ORIGIN + '/realms/master/.well-known/openid-configuration', context=context, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(1)
    raise ValueError('Owned TLS readiness deadline')


def prepare():
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    require(re.fullmatch(r'[0-9]+-[0-9]+', run_id), 'Hosted attempt identity required')
    directory = ROOT / '.state' / ('master-' + run_id)
    require(not directory.exists() and not directory.is_symlink() and not (ROOT / '.state').is_symlink(), 'Fresh state required')
    for port in (5432, 8443, 1025, 8025):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    directory.mkdir(parents=True, mode=0o700)
    for name in ('logs', 'tls', 'providers', 'exchange'):
        (directory / name).mkdir(mode=0o700)
    owner = {'run': run_id, 'root': str(directory), 'kind': 'master-transition',
             'project': 'ff-master-' + run_id, 'containers': [], 'phase': 'prepared'}
    save_owner(directory, owner)
    credentials = {key: secrets.token_urlsafe(32) for key in ('postgres', 'database', 'bootstrap', 'ordinary', 'emergency')}
    private_write(directory / 'credentials.json', json.dumps(credentials))
    private_write(directory / 'postgres.env', 'POSTGRES_PASSWORD=' + credentials['postgres'] + '\n')
    private_write(directory / 'keycloak.env', 'KC_DB_PASSWORD=' + credentials['database'] + '\nKC_BOOTSTRAP_ADMIN_PASSWORD=' + credentials['bootstrap'] + '\n')
    tls = directory / 'tls'
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt'),
         '-subj', '/CN=Owned Master Fixture CA', '-days', '2', '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], directory, 'tls-ca')
    run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls / 'server.key'), '-out', str(tls / 'server.csr'),
         '-subj', '/CN=id.firefly.test'], directory, 'tls-request')
    private_write(tls / 'server.ext', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:id.firefly.test,IP:127.0.0.1\n')
    run(['openssl', 'x509', '-req', '-in', str(tls / 'server.csr'), '-CA', str(tls / 'ca.crt'), '-CAkey', str(tls / 'ca.key'),
         '-CAcreateserial', '-out', str(tls / 'server.crt'), '-days', '2', '-extfile', str(tls / 'server.ext')], directory, 'tls-sign')
    jar = ROOT / 'extensions/native-recovery/target/firefly-id-native-recovery-26.10.1-SNAPSHOT.jar'
    require(jar.is_file(), 'Built native provider required')
    import shutil
    shutil.copyfile(jar, directory / 'providers' / jar.name)
    # Only this fresh run's mount tree is traversable to the pinned image UID. Secrets stay 0600.
    for path in (directory, tls, directory / 'providers'):
        path.chmod(0o755)
    for path in (tls / 'ca.crt', tls / 'server.crt', directory / 'providers' / jar.name):
        path.chmod(0o644)
    (tls / 'server.key').chmod(0o600)
    run(['sudo', 'chown', '1000:0', str(tls / 'server.key'), str(directory / 'exchange')], directory, 'owned-mount-owner')
    run(['sudo', 'chown', '1000:' + str(os.getgid()), str(directory / 'exchange')], directory, 'owned-exchange-group')
    run(['sudo', 'chmod', '770', str(directory / 'exchange')], directory, 'owned-exchange-access')
    run(['sudo', 'tee', '-a', '/etc/hosts'], directory, 'owned-hostname', input=b'\n127.0.0.1 id.firefly.test\n')
    nss = Path.home() / '.pki/nssdb'; nss.mkdir(parents=True, exist_ok=True)
    if not (nss / 'cert9.db').exists():
        run(['certutil', '-N', '-d', 'sql:' + str(nss), '--empty-password'], directory, 'browser-trust-create')
    run(['certutil', '-A', '-d', 'sql:' + str(nss), '-n', 'master-' + run_id, '-t', 'C,,', '-i', str(tls / 'ca.crt')], directory, 'browser-trust')
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write('NODE_EXTRA_CA_CERTS=' + str(tls / 'ca.crt') + '\n')


def images():
    return json.loads((ROOT / 'deploy/images.lock.json').read_text())


def create_container(directory, owner, kind, command):
    name = owner['project'] + '-' + kind
    require(name not in owner['containers'], 'Refusing to adopt an existing container receipt')
    result = subprocess.run(['docker', 'inspect', name], capture_output=True)
    require(result.returncode != 0, 'Refusing an existing container name')
    owner['containers'].append(name); save_owner(directory, owner)
    run(['docker', 'run', '--name', name, '--label', LABEL + '=' + owner['run']] + command, directory, kind + '-create')
    inspect_container(owner, kind)


def native_command(directory, kind, database, command):
    require(database in ('master_retained', 'master_imported'), 'Only owned databases admitted')
    return (['--detach'] if kind in ('retained', 'imported') else []) + [
        '--network', 'host', '--env-file', str(directory / 'keycloak.env'), '--env', 'KC_DB=postgres',
        '--env', 'KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/' + database, '--env', 'KC_DB_USERNAME=master_fixture',
        '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-bootstrap', '--env', 'KC_HTTP_ENABLED=false',
        '--env', 'KC_HTTP_HOST=127.0.0.1', '--env', 'KC_HTTPS_PORT=8443', '--env', 'KC_HOSTNAME=' + ORIGIN,
        '--env', 'KC_HOSTNAME_STRICT=true', '--env', 'KC_HTTPS_CERTIFICATE_FILE=/run/tls/server.crt',
        '--env', 'KC_HTTPS_CERTIFICATE_KEY_FILE=/run/tls/server.key', '--env', 'KC_LOG_LEVEL=warn',
        '--env', 'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m', '--volume', str(directory / 'tls') + ':/run/tls:ro',
        '--volume', str(directory / 'providers') + ':/opt/keycloak/providers:ro',
        '--volume', str(ROOT / 'dist/themes') + ':/opt/keycloak/themes:ro',
        '--volume', str(directory / 'exchange') + ':/run/exchange',
        '--add-host', 'id.firefly.test:127.0.0.1', images()['keycloak']['image']] + command


def start():
    directory, owner = state(); credentials = json.loads((directory / 'credentials.json').read_text())
    require(owner['phase'] == 'prepared', 'Fresh prepared fixture required')
    create_container(directory, owner, 'postgres', ['--detach', '--publish', '127.0.0.1:5432:5432',
                     '--env-file', str(directory / 'postgres.env'), images()['postgres']['image']])
    name, _ = inspect_container(owner, 'postgres')
    for _ in range(90):
        if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'], capture_output=True).returncode == 0:
            break
        time.sleep(1)
    else:
        raise ValueError('Postgres readiness deadline')
    psql(directory, owner, "CREATE ROLE master_fixture LOGIN PASSWORD '" + credentials['database'] + "'; CREATE DATABASE master_retained OWNER master_fixture; CREATE DATABASE master_imported OWNER master_fixture;")
    create_container(directory, owner, 'mailpit', ['--detach', '--publish', '127.0.0.1:1025:1025',
                     '--publish', '127.0.0.1:8025:8025', images()['mailpit']['image']])
    create_container(directory, owner, 'retained', native_command(directory, 'retained', 'master_retained', ['start']))
    wait_ready(directory); owner['phase'] = 'enrollment'; save_owner(directory, owner)


def snapshot(directory, owner):
    tables = {'users': 'user_entity', 'credentials': 'credential', 'roles': 'user_role_mapping',
              'events': 'event_entity', 'adminEvents': 'admin_event_entity', 'roleDefinitions': 'keycloak_role',
              'roleComposites': 'composite_role', 'groups': 'keycloak_group', 'groupMembership': 'user_group_membership',
              'groupRoles': 'group_role_mapping', 'userAttributes': 'user_attribute', 'requiredActions': 'user_required_action'}
    result = {}
    for key, table in tables.items():
        # Full row hashes remain private. Equality proves credential hashes and stored key counters survive.
        query = "SELECT coalesce(json_agg(h ORDER BY h),'[]'::json) FROM (SELECT md5(row_to_json(t)::text) h FROM " + table + " t) q;"
        result[key] = json.loads(psql(directory, owner, query, 'master_retained'))
    return result


def export_candidate():
    global PHASE, PROFILE_DIAGNOSTIC
    directory, owner = state(); require(owner['phase'] == 'enrollment', 'Enrollment phase required')
    private_write(directory / 'retained-before.json', json.dumps(snapshot(directory, owner)))
    stop_kind(directory, owner, 'retained')
    create_container(directory, owner, 'export', native_command(directory, 'export', 'master_retained',
                     ['export', '--realm', 'master', '--users', 'realm_file', '--file', '/run/exchange/source.json']))
    source = directory / 'exchange/source.json'
    run(['sudo', 'chown', str(os.getuid()) + ':' + str(os.getgid()), str(source)], directory, 'export-private-owner')
    source.chmod(0o600)
    PHASE = 'actual-export-prerequisites'
    document = profile.parse_document(source.read_bytes())
    try:
        profile.prerequisites(document, 'master', ORIGIN)
    except (ValueError, TypeError, KeyError) as failure:
        PROFILE_DIAGNOSTIC = profile_diagnostic(document, failure)
        raise
    run([sys.executable, str(ROOT / 'tooling/privileged_profile.py'), 'generate', '--input', str(source),
         '--realm', 'master', '--origin', ORIGIN, '--acknowledge-master', '--output', str(directory / 'candidate.json')], directory, 'exact-profile-generation')
    receipt = candidate_receipt(directory); private_write(directory / 'candidate-receipt.json', json.dumps(receipt))
    # The read-only mounted import copy must be byte-identical to the generator output.
    target = directory / 'exchange/candidate.json'
    with target.open('xb') as output:
        output.write((directory / 'candidate.json').read_bytes())
    target.chmod(0o640)
    run(['sudo', 'chown', '1000:' + str(os.getgid()), str(target)], directory, 'candidate-import-owner')
    owner['phase'] = 'candidate'; save_owner(directory, owner)


def import_start():
    directory, owner = state(); require(owner['phase'] == 'candidate', 'Exact candidate phase required')
    verify_candidate(directory, json.loads((directory / 'candidate-receipt.json').read_text()))
    require((directory / 'exchange/candidate.json').read_bytes() == (directory / 'candidate.json').read_bytes(), 'Mounted import differs from generated candidate')
    require(psql(directory, owner, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';", 'master_imported') == '0', 'Import database must be empty')
    create_container(directory, owner, 'import', native_command(directory, 'import', 'master_imported',
                     ['import', '--file', '/run/exchange/candidate.json', '--override', 'false']))
    create_container(directory, owner, 'imported', native_command(directory, 'imported', 'master_imported', ['start']))
    wait_ready(directory); owner['phase'] = 'imported'; save_owner(directory, owner)


def retained_start():
    directory, owner = state(); require(owner['phase'] == 'imported', 'Imported qualification phase required')
    stop_kind(directory, owner, 'imported')
    name, _ = inspect_container(owner, 'retained'); run(['docker', 'start', name], directory, 'retained-resume')
    wait_ready(directory); owner['phase'] = 'retained'; save_owner(directory, owner)


def restart():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    name, _ = inspect_container(owner, 'retained'); run(['docker', 'restart', name], directory, 'retained-restart')
    wait_ready(directory)


def verify_state():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    before = json.loads((directory / 'retained-before.json').read_text())
    after = snapshot(directory, owner)
    verify_retained(before, after)
    print(json.dumps({'retainedCounts': {key: len(value) for key, value in before.items()}}))


def bounded_events(rows):
    types = {'LOGIN', 'LOGIN_ERROR', 'UPDATE_CREDENTIAL', 'UPDATE_CREDENTIAL_ERROR', 'REGISTER', 'REGISTER_ERROR',
             'CUSTOM_REQUIRED_ACTION', 'CUSTOM_REQUIRED_ACTION_ERROR', 'CODE_TO_TOKEN', 'CODE_TO_TOKEN_ERROR'}
    errors = {'invalid_request', 'invalid_redirect_uri', 'invalid_code', 'expired_code', 'invalid_registration',
              'invalid_user_credentials', 'invalid_authentication_session', 'invalid_client', 'invalid_scope',
              'client_disabled', 'user_disabled', 'resolve_required_actions', 'cookie_not_found', 'not_allowed',
              'ssl_required', 'user_session_not_found', 'session_expired', 'invalid_token', 'invalid_signature',
              'pkce_verification_failed', 'illegal_origin', 'generic_authentication_error', 'generic'}
    return [{'type': item.get('type') if item.get('type') in types else 'OTHER',
             'error': item.get('error') if item.get('error') is None or item.get('error') in errors else 'OTHER'} for item in rows[:20]]


def authentication_diagnostic():
    directory, owner = state()
    database = 'master_imported' if owner['phase'] == 'imported' else 'master_retained'
    result = {'events': bounded_events(json.loads(psql(directory, owner,
        "SELECT coalesce(json_agg(q),'[]'::json) FROM (SELECT type,error FROM event_entity ORDER BY event_time DESC LIMIT 20) q;", database))),
        'credentialCounts': {}, 'exceptionClasses': []}
    for kind in ('ordinary', 'emergency'):
        result['credentialCounts'][kind] = json.loads(psql(directory, owner,
            "SELECT json_build_object('password',count(*) FILTER (WHERE c.type='password'),'webauthn',count(*) FILTER (WHERE c.type='webauthn'),"
            "'passwordless',count(*) FILTER (WHERE c.type='webauthn-passwordless')) FROM credential c JOIN user_entity u ON c.user_id=u.id "
            "WHERE u.username='synthetic-" + kind + "';", database))
    native, _ = inspect_container(owner, 'imported' if owner['phase'] == 'imported' else 'retained')
    captured = subprocess.run(['docker', 'logs', '--tail', '400', native], capture_output=True, timeout=10)
    content = (captured.stdout + captured.stderr).decode(errors='replace')
    known = {'java.lang.NullPointerException', 'java.lang.IllegalArgumentException', 'java.lang.IllegalStateException',
             'org.keycloak.models.ModelException', 'org.keycloak.models.ModelDuplicateException',
             'com.webauthn4j.verifier.exception.BadChallengeException', 'com.webauthn4j.verifier.exception.BadOriginException',
             'com.webauthn4j.verifier.exception.BadRpIdException', 'com.webauthn4j.verifier.exception.BadSignatureException',
             'com.webauthn4j.verifier.exception.UserNotPresentException', 'com.webauthn4j.verifier.exception.UserNotVerifiedException',
             'jakarta.ws.rs.BadRequestException', 'freemarker.core.InvalidReferenceException', 'org.hibernate.exception.ConstraintViolationException'}
    result['exceptionClasses'] = sorted(value for value in known if value in content)
    print(json.dumps(result))


def action_snapshot(directory, owner):
    result = snapshot(directory, owner)
    for table in ('offline_user_session', 'offline_client_session'):
        result[table] = json.loads(psql(directory, owner,
            "SELECT coalesce(json_agg(h ORDER BY h),'[]'::json) FROM (SELECT md5(row_to_json(t)::text) h FROM " + table + " t) q;", 'master_retained'))
    return result


def action_baseline():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    path = directory / 'action-before.json'; require(not path.exists(), 'Fresh action baseline required')
    private_write(path, json.dumps(action_snapshot(directory, owner)))


def verify_action_state():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    verify_retained(json.loads((directory / 'action-before.json').read_text()), action_snapshot(directory, owner))


def readback():
    global PROFILE_DIAGNOSTIC
    directory, _ = state()
    verify_candidate(directory, json.loads((directory / 'candidate-receipt.json').read_text()))
    receipt = json.load(sys.stdin)
    try:
        verify_effective(profile.parse_document((directory / 'candidate.json').read_bytes()), receipt['effective'], receipt.get('retirementWindow'))
    except (ValueError, TypeError, KeyError) as failure:
        PROFILE_DIAGNOSTIC = profile_diagnostic(receipt['effective'], failure)
        raise


def stop():
    directory, owner = state()
    for name in reversed(owner['containers']):
        kind = name.removeprefix(owner['project'] + '-')
        # A failed creation may leave only a reservation; it is never an invitation to adopt another resource.
        if subprocess.run(['docker', 'inspect', name], capture_output=True).returncode == 0:
            stop_kind(directory, owner, kind)


def check():
    directory, owner = state()
    require(owner['phase'] == 'enrollment', 'Fresh owned runtime phase required')
    inspect_container(owner, 'postgres')
    inspect_container(owner, 'mailpit')
    _, native = inspect_container(owner, 'retained')
    require(native['State']['Running'], 'Owned retained native runtime required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['authentication_diagnostic', 'check', 'action_baseline', 'verify_action_state', 'prepare', 'start', 'export_candidate', 'import_start', 'retained_start', 'restart', 'verify_state', 'readback', 'stop'])
    args = parser.parse_args(); require_hosted(); os.umask(0o077)
    globals()[args.action]()


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        evidence = ROOT / '.work/master-transition'; evidence.mkdir(parents=True, exist_ok=True)
        diagnostic = {'status': 'FAILED', 'stage': PHASE,
                      'sourceLines': [frame.lineno for frame in traceback.extract_tb(failure.__traceback__)
                                      if Path(frame.filename).resolve() == Path(__file__).resolve()][-6:]}
        if PROFILE_DIAGNOSTIC is not None:
            diagnostic['profile'] = PROFILE_DIAGNOSTIC
        (evidence / 'lifecycle-summary.json').write_text(json.dumps(diagnostic, indent=2) + '\n')
        print('Owned master fixture failed; raw logs and credential material remain private.', file=sys.stderr)
        raise SystemExit(1)
