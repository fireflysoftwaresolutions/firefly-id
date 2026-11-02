#!/usr/bin/env python3
"""Hosted-only credential-loss qualification with actual native/Core/KYC owners.

Successful identity proofing belongs exclusively to the Domain test classpath.
No command accepts an existing database, remote Docker, arbitrary process or path.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import uuid

import native_integration_fixture as owned

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.work/reproofing-integration'
CORE_RELATIVE = 'core-common-kycb-mgmt-web/target/core-common-kycb-mgmt.jar'
FIXTURE_MAIN = 'io.fireflysoftware.domain.kyc.kyb.web.reproofing.ReproofingFixtureApplication'


def protected(path, value):
    if path.exists():
        raise RuntimeError('Refusing to replace owned fixture material')
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    path.chmod(0o600)


def state():
    directory, owner = owned.state()
    if owner.get('suite') != 'credential-loss-v1':
        raise RuntimeError('Credential-loss suite ownership mismatch')
    return directory, owner


def output_json(name, value):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / name).write_text(json.dumps(value, indent=2) + '\n')


def prepare():
    owned.resource_floor(ROOT, 12)
    run = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    directory = ROOT / '.state' / ('native-' + run)
    subprocess.run([sys.executable, str(ROOT / 'scripts/generate_native_fixture.py'), '--output', str(directory)], check=True)
    directory, owner = owned.state()
    owner['suite'] = 'credential-loss-v1'
    owned.save_owner(directory, owner)
    credentials = json.loads((directory / 'credentials.json').read_text())
    values = {key: secrets.token_urlsafe(36) for key in ('native-domain', 'domain-core', 'core-verifier',
                                                        'fixture-control', 'core-native', 'domain-native',
                                                        'core-notification', 'notification-monitor')}
    values['native_client'] = 'reproofing-native-caller'
    values['domain_client'] = 'reproofing-domain-caller'
    values['verifier_client'] = 'reproofing-core-verifier'
    values['fixture_client'] = 'reproofing-fixture-controller'
    values['notification_client'] = 'reproofing-notification-worker'
    values['monitor_client'] = 'reproofing-notification-monitor'
    for name, value in values.items():
        if not name.endswith('_client'):
            protected(directory / 'secrets' / (name + '.secret'), value)
    protected(directory / 'secrets/native-domain-kc.secret', values['native-domain'])
    protected(directory / 'secrets/enrollment.key', secrets.token_bytes(32))
    credentials['reproofing'] = values
    profile = credentials['profiles'][0]
    realm_file = directory / 'realms' / (profile['realm'] + '.json')
    realm = json.loads(realm_file.read_text())
    person = realm['users'][0]
    profile['tenant'] = person['attributes']['tenant_id'][0]
    profile['party'] = person['attributes']['party_id'][0]
    person['emailVerified'] = True
    for label in ('locked', 'changed', 'contact', 'held-after-proof', 'never-enrolled'):
        additional = json.loads(json.dumps(person))
        additional.update(id=str(uuid.uuid4()), username=label + '-customer',
                          email=label + '@example.invalid')
        additional['attributes']['party_id'] = [str(uuid.uuid4())]
        if label == 'never-enrolled':
            additional['requiredActions'] = ['CONFIGURE_TOTP', 'UPDATE_PASSWORD']
        realm['users'].append(additional)
        profile[label] = {'id': additional['id'], 'username': additional['username'],
                          'email': additional['email'], 'password': profile['person']['password']}
    attrs = {'enabled': 'true', 'issuer': profile['issuer'], 'tenant': profile['tenant'], 'population': 'HUMAN',
             'tenant-attribute': 'tenant_id', 'link-attribute': 'party_id', 'allowed-origin': 'https://id.firefly.test:8443',
             'ttl-seconds': '600', 'core-workload-client-id': 'reproofing-core-owner',
             'domain-workload-client-id': 'reproofing-domain-owner', 'domain-origin': profile['domain'],
             'notification-workload-client-id': values['notification_client'],
             'domain-client-id': values['native_client'], 'provider-origin': profile['domain']}
    realm['attributes'].update({'firefly.reproofing.' + name: value for name, value in attrs.items()})
    for client_id, secret in [('reproofing-core-owner', values['core-native']),
                              ('reproofing-domain-owner', values['domain-native']),
                              (values['notification_client'], values['core-notification'])]:
        realm['clients'].append({'clientId': client_id, 'enabled': True, 'publicClient': False, 'secret': secret,
                                 'standardFlowEnabled': False, 'directAccessGrantsEnabled': False,
                                 'serviceAccountsEnabled': False, 'implicitFlowEnabled': False,
                                 'protocol': 'openid-connect', 'fullScopeAllowed': False})
    for client in realm['clients']:
        if client['clientId'].startswith('reproofing-'):
            client['attributes'] = {**client.get('attributes', {}),
                                    'oauth2.device.authorization.grant.enabled': 'false',
                                    'oidc.ciba.grant.enabled': 'false',
                                    'standard.token.exchange.enabled': 'false',
                                    'oauth2.jwt.authorization.grant.enabled': 'false'}
    realm['smtpServer'] = {'host': '127.0.0.1', 'port': '1025', 'from': 'identity@example.invalid',
                           'fromDisplayName': 'Firefly Identity', 'ssl': 'false', 'starttls': 'false', 'auth': 'false'}
    realm_file.write_text(json.dumps(realm, indent=2) + '\n')
    (directory / 'credentials.json').write_text(json.dumps(credentials, indent=2) + '\n')
    for port in (5432, 8443, 8444, 8445, 8448, 8449, 1025, 8025):
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', port))
            except OSError as error:
                raise RuntimeError('Refusing an occupied owned fixture port') from error
    owned.tls(directory, credentials)
    # Native image UID reads only these attempt-owned private files; host services
    # use different files, so neither service receives the other's credentials.
    for name in ('native-domain-kc.secret', 'enrollment.key'):
        owned.run(['sudo', 'chown', '1000:0', str(directory / 'secrets' / name)], directory, 'replacement-secret-owner')
    owned.run(['sudo', 'chmod', '755', str(directory / 'secrets')], directory, 'replacement-secret-directory')
    print('Prepared new credential-loss fixture; credentials and synthetic references remain private.')


def container(directory, owner, suffix, arguments):
    name = owner['project'] + '-' + suffix
    owner['containers'].append(name)
    owned.save_owner(directory, owner)
    owned.run(['docker', 'run', '--detach', '--name', name, '--label', owned.LABEL + '=' + owner['run'],
               *arguments], directory, suffix + '-start')
    return name


def start_native(directory, owner, credentials, images):
    for module in ('native-recovery', 'native-domain-gateway'):
        artifact = ROOT / 'extensions' / module / 'target' / ('firefly-id-' + module + '-26.10.1-SNAPSHOT.jar')
        if not artifact.is_file():
            raise RuntimeError('Actual native candidate artifact missing')
        target = directory / 'providers' / artifact.name
        if target.exists():
            raise RuntimeError('Native provider destination already exists')
        target.write_bytes(artifact.read_bytes())
        target.chmod(0o644)
    arguments = ['--network', 'host', '--env-file', str(directory / 'keycloak.env'),
                 '--env', 'KC_DB=postgres', '--env', 'KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/native_kc',
                 '--env', 'KC_DB_USERNAME=native_kc', '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=native-bootstrap',
                 '--env', 'KC_HTTP_ENABLED=false', '--env', 'KC_HTTP_HOST=127.0.0.1', '--env', 'KC_HTTPS_PORT=8443',
                 '--env', 'KC_HOSTNAME=https://id.firefly.test:8443', '--env', 'KC_HOSTNAME_STRICT=true',
                 '--env', 'KC_HTTPS_CERTIFICATE_FILE=/run/native/server.crt', '--env', 'KC_HTTPS_CERTIFICATE_KEY_FILE=/run/native/server.key',
                 '--env', 'KC_LOG_LEVEL=warn', '--env', 'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m',
                 '--env', 'FIREFLY_SUPPORT_PIN_KEYS_DIR=/run/pepper', '--env', 'FIREFLY_SUPPORT_PIN_ACTIVE_KEY=v1',
                 '--env', 'FIREFLY_REPROOFING_DOMAIN_SECRET_FILE=/run/reproofing/native-domain-kc.secret',
                 '--env', 'FIREFLY_REPROOFING_ENROLLMENT_KEY_FILE=/run/reproofing/enrollment.key',
                 '--env', 'JAVA_OPTS_APPEND=-Djavax.net.ssl.trustStore=/run/native/trust.p12 -Djavax.net.ssl.trustStorePassword=' + credentials['store'],
                 '--volume', str(directory / 'providers') + ':/opt/keycloak/providers:ro',
                 '--volume', str(directory / 'realms') + ':/opt/keycloak/data/import:ro',
                 '--volume', str(ROOT / 'dist/themes') + ':/opt/keycloak/themes:ro',
                 '--volume', str(directory / 'tls') + ':/run/native:ro', '--volume', str(directory / 'pepper') + ':/run/pepper:ro',
                 '--volume', str(directory / 'secrets') + ':/run/reproofing:ro',
                 '--volume', str(ROOT / 'config/password-blacklist.txt') + ':/opt/keycloak/data/password-blacklists/firefly-baseline.txt:ro']
    for name in ('id.firefly.test', 'domain-customers.firefly.test', 'core-customers.firefly.test'):
        arguments += ['--add-host', name + ':127.0.0.1']
    arguments += [images['keycloak']['image'], 'start', '--import-realm',
                  '--spi-brute-force-protector--provider=firefly-native-recovery']
    container(directory, owner, 'keycloak', arguments)
    owned.wait_https(credentials['profiles'][0]['issuer'] + '/.well-known/openid-configuration', directory)


def service(directory, owner, credentials, name, settings, command, *, resume=False):
    source = ROOT / '.qualification/reproofing-domain'
    if name == 'core':
        source = source / '.qualification/core'
    configuration = directory / (name + '-reproofing.json')
    if resume:
        if not configuration.is_file() or json.loads(configuration.read_text()) != settings:
            raise RuntimeError('Owned service restart configuration mismatch')
    else:
        protected(configuration, json.dumps(settings))
    environment = dict(os.environ, SPRING_APPLICATION_JSON=json.dumps(settings),
                       DB_HOST='127.0.0.1', DB_PORT='5432', DB_NAME='kycb_reproofing',
                       DB_USERNAME='reproofing_runtime', DB_PASSWORD=credentials['core-db'], DB_SSL_MODE='disable')
    java = ['java', '-Xms64m', '-Xmx512m', '-Djavax.net.ssl.trustStore=' + str(directory / 'tls/trust.p12'),
            '-Djavax.net.ssl.trustStorePassword=' + credentials['store']]
    with (directory / 'logs' / (name + '-reproofing.log')).open('ab') as output:
        process = subprocess.Popen(java + command, cwd=source, env=environment, stdout=output, stderr=subprocess.STDOUT)
    owner['processes'].append({'pid': process.pid, 'jar': command[-1], 'kind': name + '-reproofing'})
    owned.save_owner(directory, owner)
    return process


def start():
    directory, owner = state()
    owned.resource_floor(directory, 12)
    credentials = json.loads((directory / 'credentials.json').read_text())
    values = credentials['reproofing']
    profile = credentials['profiles'][0]
    images = json.loads((ROOT / 'deploy/images.lock.json').read_text())
    postgres = container(directory, owner, 'postgres', ['--publish', '127.0.0.1:5432:5432',
                          '--env-file', str(directory / 'postgres.env'), images['postgres']['image']])
    for _ in range(90):
        if subprocess.run(['docker', 'exec', postgres, 'pg_isready', '-U', 'postgres'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Owned PostgreSQL readiness timed out')
    owned.psql(directory, owner, "CREATE ROLE native_kc LOGIN PASSWORD '" + credentials['keycloak-db']
               + "'; CREATE DATABASE native_kc OWNER native_kc; CREATE ROLE reproofing_owner NOLOGIN; "
               + "CREATE ROLE reproofing_runtime LOGIN PASSWORD '" + credentials['core-db']
               + "'; CREATE DATABASE kycb_reproofing;")
    owned.psql(directory, owner, 'REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE,CREATE ON SCHEMA public TO reproofing_owner;', 'kycb_reproofing')
    core = ROOT / '.qualification/reproofing-domain/.qualification/core'
    installer = (core / 'ops/reproofing-installer/install.sql').read_text()
    installer = installer.replace(":'reproofing_owner'", "'reproofing_owner'").replace(":'reproofing_runtime'", "'reproofing_runtime'")
    installer = installer.replace(':"reproofing_owner"', 'reproofing_owner').replace(':"reproofing_runtime"', 'reproofing_runtime')
    owned.psql(directory, owner, installer, 'kycb_reproofing')
    container(directory, owner, 'mailpit', ['--network', 'host', images['mailpit']['image']])
    start_native(directory, owner, credentials, images)
    common = {'server.address': '127.0.0.1', 'server.ssl.enabled': True,
              'server.ssl.key-store': 'file:' + str(directory / 'tls/server.p12'),
              'server.ssl.key-store-password': credentials['store'], 'server.ssl.key-store-type': 'PKCS12',
              'spring.flyway.enabled': False, 'spring.r2dbc.url': 'r2dbc:postgresql://127.0.0.1:5432/kycb_reproofing',
              'spring.r2dbc.username': 'reproofing_runtime', 'spring.r2dbc.password': credentials['core-db'],
              'firefly.cache.enabled': False, 'firefly.web.idempotency.enabled': False,
              'firefly.security.resource-server.enabled': False,
              'firefly.cqrs.query.caching-enabled': False, 'firefly.eda.enabled': False, 'firefly.stepevents.enabled': False,
              'springdoc.api-docs.enabled': False, 'springdoc.swagger-ui.enabled': False, 'logging.level.root': 'WARN',
              'firefly.reproofing.enabled': True, 'firefly.reproofing.issuer': profile['issuer'],
              'firefly.reproofing.realm': profile['realm'], 'firefly.reproofing.tenant': profile['tenant'],
              'firefly.reproofing.provider-id': 'fixture-proofing-v1', 'firefly.reproofing.policy-id': 'fixture-policy-v1'}
    secret = lambda name: str(directory / 'secrets' / (name + '.secret'))
    core_settings = {**common, 'server.port': profile['core_port'],
                     'firefly.reproofing.receiver.client-id': values['domain_client'],
                     'firefly.reproofing.receiver.secret-file': secret('domain-core'),
                     'firefly.reproofing.native.base-url': profile['issuer'] + '/firefly-recovery/lost-credentials/rpc',
                     'firefly.reproofing.native.client-id': 'reproofing-core-owner',
                     'firefly.reproofing.native.secret-file': secret('core-native'),
                     'firefly.reproofing.notifications.enabled': True,
                     'firefly.reproofing.notifications.client-id': values['notification_client'],
                     'firefly.reproofing.notifications.secret-file': secret('core-notification'),
                     'firefly.reproofing.notifications.monitor.client-id': values['monitor_client'],
                     'firefly.reproofing.notifications.monitor.secret-file': secret('notification-monitor'),
                     'firefly.reproofing.notifications.poll-interval': 'PT2S',
                     'firefly.reproofing.notifications.request-timeout': 'PT10S',
                     'firefly.reproofing.notifications.stale-after': 'PT30S',
                     'firefly.reproofing.notifications.overdue-after': 'PT10S',
                     'firefly.reproofing.evidence.base-url': profile['domain'] + '/internal/identity-recovery/evidence',
                     'firefly.reproofing.evidence.client-id': values['verifier_client'],
                     'firefly.reproofing.evidence.secret-file': secret('core-verifier')}
    core_process = service(directory, owner, credentials, 'core', core_settings, ['-jar', str(core / CORE_RELATIVE)])
    owned.wait_https(profile['core'] + '/api/v1/identity-recovery/cases', directory, core_process)
    start_domain(directory, owner, credentials, common)
    summary = json.loads((ROOT / '.qualification/reproofing-domain/.qualification/reproofing-sdk-summary.json').read_text())
    manifest = {'scope': 'Actual Keycloak and customer KYC owners with test-classpath-only proofing; not real provider or production acceptance',
                'identity_source': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
                'producer': summary, 'native_image': images['keycloak']['image'], 'postgres_image': images['postgres']['image'],
                'mailpit_image': images['mailpit']['image']}
    for artifact in list((directory / 'providers').glob('*.jar')) + [core / CORE_RELATIVE]:
        manifest[artifact.name] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    output_json('manifest.json', manifest)
    print('Actual native, durable Core and independent customer Domain fixture ready.')


def start_domain(directory, owner, credentials, common):
    # Filled with the exact genuine-SDK consumer's declared fixture properties;
    # absence is an integration failure, never an alternate fake Domain.
    source = ROOT / '.qualification/reproofing-domain'
    descriptor = source / '.qualification/reproofing-runtime.json'
    if not descriptor.is_file():
        raise RuntimeError('Actual Domain fixture runtime descriptor missing')
    descriptor_value = json.loads(descriptor.read_text())
    if descriptor_value.get('mainClass') != FIXTURE_MAIN:
        raise RuntimeError('Unexpected Domain fixture application')
    classpath_file = source / '.qualification/reproofing-domain-classpath.txt'
    classpath = classpath_file.read_text().strip()
    if not classpath or '\n' in classpath:
        raise RuntimeError('Invalid actual Domain classpath')
    settings = {**common, **descriptor_value['properties'],
                'server.port': credentials['profiles'][0]['domain_backend_port']}
    # All templated values are private runner-local paths/credentials; the file
    # never becomes evidence and no response content is logged.
    substitutions = {'STATE': str(directory), 'CORE': credentials['profiles'][0]['core'],
                     'DOMAIN': credentials['profiles'][0]['domain'], 'ISSUER': credentials['profiles'][0]['issuer'],
                     'NATIVE_CLIENT': credentials['reproofing']['native_client'],
                     'DOMAIN_CLIENT': credentials['reproofing']['domain_client'],
                     'VERIFIER_CLIENT': credentials['reproofing']['verifier_client'],
                     'FIXTURE_CLIENT': credentials['reproofing']['fixture_client']}
    for name, value in list(settings.items()):
        if isinstance(value, str):
            for token, replacement in substitutions.items():
                value = value.replace('${' + token + '}', replacement)
            if '${' in value:
                raise RuntimeError('Unresolved actual Domain runtime setting')
            settings[name] = value
    process = service(directory, owner, credentials, 'domain', settings, ['-cp', classpath, FIXTURE_MAIN])
    backend = credentials['profiles'][0]['domain'].rsplit(':', 1)[0] + ':' + str(credentials['profiles'][0]['domain_backend_port'])
    owned.wait_https(backend + '/api/v1/identity-recovery/cases', directory, process)
    script = str(Path(__file__).resolve())
    with (directory / 'logs/domain-transport.log').open('ab') as output:
        relay = subprocess.Popen([sys.executable, script, 'serve-proxy'], stdout=output, stderr=subprocess.STDOUT)
    owner['processes'].append({'pid': relay.pid, 'jar': script, 'kind': 'reproofing-domain-transport'})
    owned.save_owner(directory, owner)
    owned.wait_https(credentials['profiles'][0]['domain'] + '/api/v1/identity-recovery/cases', directory, relay)


def serve_proxy():
    directory, _ = state()
    credentials = json.loads((directory / 'credentials.json').read_text())
    profile = credentials['profiles'][0]
    trust = ssl.create_default_context(cafile=str(directory / 'tls/ca.crt'))

    class Relay(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            upstream = None
            try:
                raw_length = self.headers.get('Content-Length', '0')
                if not raw_length.isdigit() or int(raw_length) > 32768 or self.headers.get('Transfer-Encoding'):
                    self.send_error(400)
                    return
                body = self.rfile.read(int(raw_length))
                headers = {key: value for key, value in self.headers.items()
                           if key.lower() not in ('host', 'connection', 'transfer-encoding')}
                upstream = http.client.HTTPSConnection('domain-customers.firefly.test', profile['domain_backend_port'],
                                                        context=trust, timeout=15)
                upstream.request(self.command, self.path, body=body or None, headers=headers)
                response = upstream.getresponse()
                payload = response.read(65537)
                if len(payload) > 65536:
                    raise RuntimeError('Bounded owned transport response exceeded')
                marker = directory / 'record-response-loss.armed'
                if self.command == 'POST' and self.path.endswith('/executions') and 200 <= response.status < 300:
                    try:
                        marker.rename(directory / 'record-response-loss.spent')
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    except FileNotFoundError:
                        pass
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ('content-length', 'connection', 'transfer-encoding'):
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(payload)
            except Exception:
                self.close_connection = True
            finally:
                if upstream is not None:
                    upstream.close()

        do_POST = forward
        do_GET = forward
        do_PUT = forward

    server = http.server.ThreadingHTTPServer(('127.0.0.1', profile['domain_port']), Relay)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory / 'tls/server.crt'), str(directory / 'tls/proxy.key'))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def arm_record_loss():
    directory, _ = state()
    if (directory / 'record-response-loss.spent').exists():
        raise RuntimeError('Owned response-loss fault already consumed')
    protected(directory / 'record-response-loss.armed', 'one committed response\n')
    print(json.dumps({'armed': True}))


def fault_status():
    directory, _ = state()
    print(json.dumps({'recordResponseDropped': (directory / 'record-response-loss.spent').exists()}))


def snapshot():
    directory, owner = state()
    credentials = json.loads((directory / 'credentials.json').read_text())
    changed = str(uuid.UUID(credentials['profiles'][0]['changed']['id']))
    person = str(uuid.UUID(credentials['profiles'][0]['person']['id']))
    native = owned.psql(directory, owner, """SELECT json_build_object(
      'executions',(SELECT count(*) FROM ff_reproofing_execution),
      'recordedExecutions',(SELECT count(*) FROM ff_reproofing_execution WHERE recorded=true),
      'oldestExecutedGrantSeconds',(SELECT coalesce(min(extract(epoch from (cast(authorization_json as jsonb)->>'expiresAt')::timestamptz-clock_timestamp())),0) FROM ff_reproofing_execution),
      'notifications',(SELECT coalesce(json_agg(json_build_object('status',status,'attempts',attempts)),'[]'::json) FROM ff_reproofing_notification),
      'epochs',(SELECT coalesce(json_agg(json_build_object('subject',subject,'epoch',epoch,'failures',failures)),'[]'::json) FROM ff_reproofing_state),
      'liveGrantSeconds',(SELECT coalesce(max(greatest(0,extract(epoch from (cast(authorization_json as jsonb)->>'expiresAt')::timestamptz-clock_timestamp()))),0) FROM ff_reproofing_ceremony WHERE authorization_json IS NOT NULL AND stage='ENROLL'),
      'changedLegacyStates',(SELECT count(*) FROM ff_native_state WHERE subject='""" + changed + """'),
      'changedInvalidationAudits',(SELECT count(*) FROM ff_native_audit WHERE subject='""" + changed + """' AND event_type LIKE 'REPROOFING_%'),
      'pinStored',(SELECT count(*) FROM credential WHERE user_id='""" + person + """' AND type='firefly-support-pin'),
      'pinAuthority',(SELECT json_build_object('credentialPresent',pin_credential_id IS NOT NULL,'generation',pin_generation,'held',pin_held,'failures',pin_failures,'reserved',pin_reserved,'revoked',pin_revoked_at>0) FROM ff_native_state WHERE subject='""" + person + """')
    );""", 'native_kc')
    core = owned.psql(directory, owner, """SELECT json_build_object(
      'cases',(SELECT coalesce(json_agg(json_build_object('status',status,'failures',failures) ORDER BY case_id),'[]'::json) FROM identity_reproofing_case),
      'grants',(SELECT count(*) FROM identity_reproofing_case WHERE authorization_id IS NOT NULL),
      'verifiedGrantTotal',(SELECT coalesce(sum(verified_grants),0) FROM identity_reproofing_budget),
      'consumedAudits',(SELECT count(*) FROM identity_reproofing_audit WHERE event='CONSUMED'),
      'executedAudits',(SELECT count(*) FROM identity_reproofing_audit WHERE event='EXECUTED'),
      'changedLiveGrants',(SELECT count(*) FROM identity_reproofing_case WHERE cast(binding as jsonb)->>'subject'='""" + changed + """' AND grant_expires_at>clock_timestamp()+interval '10 seconds')
    );""", 'kycb_reproofing')
    print(json.dumps({'native': json.loads(native), 'core': json.loads(core)}))


def mail(start):
    directory, owner = state()
    name = owner['project'] + '-mailpit'
    owned.inspect_container(owner, name)
    owned.run(['docker', 'start' if start else 'stop', name], directory, 'owned-notification-transport')
    print(json.dumps({'running': start}))


def restart_native():
    directory, owner = state()
    name = owner['project'] + '-keycloak'
    owned.inspect_container(owner, name)
    owned.run(['docker', 'restart', name], directory, 'owned-reproofing-native-restart')
    credentials = json.loads((directory / 'credentials.json').read_text())
    owned.wait_https(credentials['profiles'][0]['issuer'] + '/.well-known/openid-configuration', directory)
    print(json.dumps({'restarted': True}))


def restart_core():
    directory, owner = state()
    active = [process for process in owner['processes'] if process['kind'] == 'core-reproofing']
    if len(active) != 1:
        raise RuntimeError('Expected exactly one owned Core process')
    process = active[0]
    command = Path('/proc') / str(process['pid']) / 'cmdline'
    if not command.exists() or process['jar'].encode() not in command.read_bytes():
        raise RuntimeError('Owned Core process identity mismatch')
    os.kill(process['pid'], signal.SIGTERM)
    for _ in range(120):
        if not command.exists() or not command.read_bytes():
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('Owned Core shutdown did not finish')
    owner['processes'].remove(process)
    owner.setdefault('retired_processes', []).append({**process, 'state': 'stopped'})
    owned.save_owner(directory, owner)
    credentials = json.loads((directory / 'credentials.json').read_text())
    settings = json.loads((directory / 'core-reproofing.json').read_text())
    core = ROOT / '.qualification/reproofing-domain/.qualification/core'
    restarted = service(directory, owner, credentials, 'core', settings, ['-jar', str(core / CORE_RELATIVE)], resume=True)
    owned.wait_https(credentials['profiles'][0]['core'] + '/api/v1/identity-recovery/cases', directory, restarted)
    print(json.dumps({'restarted': True}))


def notification_probes():
    directory, owner = state()
    marker = directory / 'notification-probes.applied'
    if marker.exists():
        raise RuntimeError('Owned notification probes already applied')
    owned.inspect_container(owner, owner['project'] + '-postgres')
    credentials = json.loads((directory / 'credentials.json').read_text())
    realms = [profile['realm'] for profile in credentials['profiles']]
    if len(realms) != 2 or not all(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', realm) for realm in realms):
        raise RuntimeError('Unexpected owned realm identifiers')
    template = """INSERT INTO ff_reproofing_notification
      (id,realm_id,subject,destination_encrypted,destination_digest,created_at,next_attempt_at,delivered_at,attempts,status,lease_token)
      SELECT '{id}',id,'owned-notification-probe','not-a-deliverable-ciphertext','owned-probe',
      cast(extract(epoch from clock_timestamp())*1000 as bigint)-120000,
      cast(extract(epoch from clock_timestamp())*1000 as bigint)-120000,0,8,{status},'expired-owned-lease'
      FROM realm WHERE name='{realm}';"""
    owned.psql(directory, owner, 'BEGIN;'
               + template.format(id='fixture-foreign-failure', status="'FAILED'", realm=realms[1])
               + template.format(id='fixture-expired-delivery', status="'SENDING'", realm=realms[0]) + 'COMMIT;', 'native_kc')
    count = owned.psql(directory, owner, "SELECT count(*) FROM ff_reproofing_notification WHERE id IN ('fixture-foreign-failure','fixture-expired-delivery');", 'native_kc')
    if count != '2':
        raise RuntimeError('Owned aggregate probes were not actually inserted')
    rejected = []
    for label, value in [('unknown', "'UNKNOWN'"), ('null', 'NULL')]:
        try:
            owned.psql(directory, owner, template.format(id='fixture-invalid-' + label, status=value, realm=realms[0]), 'native_kc')
        except RuntimeError:
            rejected.append(label)
    if rejected != ['unknown', 'null']:
        raise RuntimeError('Native notification constraints did not reject invalid state')
    protected(marker, 'owned aggregate and terminal-lease probes\n')
    print(json.dumps({'foreignRealmFailureRetained': True, 'expiredFinalLeaseCreated': True,
                      'invalidStatusRejected': True, 'nullStatusRejected': True}))


def notification_probe_status():
    directory, owner = state()
    result = owned.psql(directory, owner, """SELECT json_build_object(
      'terminalStatus',(SELECT status FROM ff_reproofing_notification WHERE id='fixture-expired-delivery'),
      'terminalAttempts',(SELECT attempts FROM ff_reproofing_notification WHERE id='fixture-expired-delivery'),
      'leaseCleared',(SELECT lease_token IS NULL FROM ff_reproofing_notification WHERE id='fixture-expired-delivery'),
      'foreignFailureRetained',(SELECT count(*)=1 FROM ff_reproofing_notification WHERE id='fixture-foreign-failure' AND status='FAILED')
    );""", 'native_kc')
    print(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'start', 'stop', 'snapshot', 'mail-stop', 'mail-start', 'restart-native',
                                           'serve-proxy', 'arm-record-loss', 'fault-status', 'restart-core',
                                           'notification-probes', 'notification-probe-status'])
    args = parser.parse_args()
    owned.require_hosted()
    try:
        if args.action == 'prepare':
            prepare()
        elif args.action == 'start':
            start()
        elif args.action == 'stop':
            state()
            owned.stop()
        elif args.action == 'snapshot':
            snapshot()
        elif args.action == 'restart-native':
            restart_native()
        elif args.action == 'restart-core':
            restart_core()
        elif args.action == 'notification-probes':
            notification_probes()
        elif args.action == 'notification-probe-status':
            notification_probe_status()
        elif args.action == 'serve-proxy':
            serve_proxy()
        elif args.action == 'arm-record-loss':
            arm_record_loss()
        elif args.action == 'fault-status':
            fault_status()
        else:
            mail(args.action == 'mail-start')
    except Exception:
        output_json('boot-summary.json', {'phase': owned.PHASE, 'failure': 'Owned credential-loss fixture failed; private logs retained on runner'})
        print('Owned credential-loss fixture failed; no credentials or private logs emitted.', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
