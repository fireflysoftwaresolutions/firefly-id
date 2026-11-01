#!/usr/bin/env python3
"""Owned hosted-only HTTPS/native/Core/Domain fixture. No existing database or remote Docker is admitted."""
import argparse
import hashlib
import json
import http.server
import threading
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'org.firefly-id.native-fixture'
PHASE = 'initialization'


def faults_enabled():
    return os.environ.get('FIREFLY_NATIVE_TRANSPORT_FAULTS') == 'true'


def require_hosted():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise RuntimeError('Native integration is restricted to its hosted Linux runner')
    if any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')):
        raise RuntimeError('Docker selection overrides are not admitted')
    endpoint = subprocess.check_output(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], text=True)
    if not json.loads(endpoint).startswith('unix://'):
        raise RuntimeError('Only the local hosted Docker daemon is admitted')


def state():
    run = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    if not re.fullmatch(r'\d+-\d+', run):
        raise RuntimeError('Unexpected hosted attempt identity')
    directory = ROOT / '.state' / ('native-' + run)
    owner = json.loads((directory / 'ownership.json').read_text())
    if owner['run'] != run or owner['root'] != str(directory) or owner['kind'] != 'native-integration':
        raise RuntimeError('Native state ownership mismatch')
    return directory, owner


def resource_floor(directory, gibibytes):
    if shutil.disk_usage(directory).free < gibibytes * 1024 ** 3:
        raise RuntimeError('Owned hosted resource floor reached')


def save_owner(directory, owner):
    (directory / 'ownership.json').write_text(json.dumps(owner, indent=2) + '\n')


def run(command, directory, label, *, input=None, env=None):
    global PHASE
    PHASE = label
    with (directory / 'logs' / (label + '.log')).open('ab') as output:
        result = subprocess.run(command, input=input, stdout=output, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise RuntimeError('Owned native fixture phase failed: ' + label)


def psql(directory, owner, sql, database='postgres'):
    container = owner['project'] + '-postgres'
    result = subprocess.run(['docker', 'exec', '-i', container, 'psql', '-X', '-U', 'postgres', '-d', database,
                             '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=sqlstate', '-At'], input=sql.encode(), capture_output=True)
    if result.returncode:
        with (directory / 'logs' / 'database-private.log').open('ab') as stream:
            stream.write(result.stderr)
        raise RuntimeError('Owned fixture database phase failed')
    return result.stdout.decode().strip()


def inspect_container(owner, container):
    if container not in owner['containers'] or not container.startswith(owner['project'] + '-'):
        raise RuntimeError('Unowned container operation refused')
    actual = json.loads(subprocess.check_output(['docker', 'inspect', container], text=True))[0]
    if actual['Config'].get('Labels', {}).get(LABEL) != owner['run']:
        raise RuntimeError('Container ownership label mismatch')
    return actual


def tls(directory, credentials):
    tls_dir = directory / 'tls'
    env = dict(os.environ, FIXTURE_KEYSTORE_PASSWORD=credentials['store'])
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls_dir / 'ca.key'),
         '-out', str(tls_dir / 'ca.crt'), '-subj', '/CN=Owned Firefly Native Fixture CA', '-days', '2',
         '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], directory, 'ca')
    run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls_dir / 'server.key'),
         '-out', str(tls_dir / 'server.csr'), '-subj', '/CN=id.firefly.test'], directory, 'certificate-request')
    names = ['id.firefly.test', 'localhost'] + [f'{service}-{kind}.firefly.test' for kind in ('customers', 'workforce') for service in ('core', 'domain')]
    (tls_dir / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + name for name in names) + ',IP:127.0.0.1\n')
    run(['openssl', 'x509', '-req', '-in', str(tls_dir / 'server.csr'), '-CA', str(tls_dir / 'ca.crt'), '-CAkey', str(tls_dir / 'ca.key'),
         '-CAcreateserial', '-out', str(tls_dir / 'server.crt'), '-days', '2', '-extfile', str(tls_dir / 'server.ext')], directory, 'certificate-sign')
    run(['openssl', 'pkcs12', '-export', '-in', str(tls_dir / 'server.crt'), '-inkey', str(tls_dir / 'server.key'), '-certfile', str(tls_dir / 'ca.crt'),
         '-out', str(tls_dir / 'server.p12'), '-passout', 'env:FIXTURE_KEYSTORE_PASSWORD'], directory, 'server-store', env=env)
    run(['keytool', '-importcert', '-noprompt', '-storetype', 'PKCS12', '-keystore', str(tls_dir / 'trust.p12'),
         '-storepass:env', 'FIXTURE_KEYSTORE_PASSWORD', '-alias', 'owned-native-ca', '-file', str(tls_dir / 'ca.crt')], directory, 'trust-store', env=env)
    (tls_dir / 'proxy.key').write_bytes((tls_dir / 'server.key').read_bytes())
    for path in tls_dir.iterdir(): path.chmod(0o600)
    for name in ('ca.crt', 'server.crt', 'trust.p12'): (tls_dir / name).chmod(0o644)
    # Only the hosted attempt's private mounted key is made readable to the native image's fixed UID.
    run(['sudo', 'chown', '1000:0', str(tls_dir / 'server.key'), str(directory / 'pepper/v1')], directory, 'native-secret-owner')
    run(['sudo', 'chmod', '755', str(directory), str(directory / 'tls'), str(directory / 'pepper'), str(directory / 'realms'), str(directory / 'providers')], directory, 'native-mount-access')
    for path in (directory / 'realms').glob('*.json'):
        run(['sudo', 'chown', '1000:0', str(path)], directory, 'realm-owner')
    hosts = '\n127.0.0.1 ' + ' '.join(names) + '\n'
    run(['sudo', 'tee', '-a', '/etc/hosts'], directory, 'owned-hostnames', input=hosts.encode())
    nss = Path.home() / '.pki/nssdb'; nss.mkdir(parents=True, exist_ok=True)
    if not (nss / 'cert9.db').exists(): run(['certutil', '-N', '-d', 'sql:' + str(nss), '--empty-password'], directory, 'browser-trust-init')
    run(['certutil', '-A', '-d', 'sql:' + str(nss), '-n', 'owned-native-' + directory.name, '-t', 'C,,', '-i', str(tls_dir / 'ca.crt')], directory, 'browser-trust')
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write('FIREFLY_NATIVE_STATE=' + str(directory) + '\nNODE_EXTRA_CA_CERTS=' + str(tls_dir / 'ca.crt') + '\n')


def wait_https(url, directory, process=None):
    global PHASE
    PHASE = 'https-readiness-' + str(urllib.parse.urlsplit(url).port)
    context = ssl.create_default_context(cafile=str(directory / 'tls/ca.crt'))
    for _ in range(120):
        if process is not None and process.poll() is not None: raise RuntimeError('Owned service exited before TLS readiness')
        try:
            with urllib.request.urlopen(url, context=context, timeout=2) as response:
                if response.status < 500: return
        except urllib.error.HTTPError as error:
            if error.code < 500: return
        except Exception: pass
        time.sleep(1)
    raise RuntimeError('Owned HTTPS service readiness timed out')


def prepare():
    resource_floor(ROOT, 12)
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    directory = ROOT / '.state' / ('native-' + run_id)
    subprocess.run(['python3', str(ROOT / 'scripts/generate_native_fixture.py'), '--output', str(directory)], check=True)
    directory, owner = state(); credentials = json.loads((directory / 'credentials.json').read_text())
    tls(directory, credentials)
    for port in (5432, 8443, 8444, 8445, 8446, 8447, 8448, 8449, 8451):
        with socket.socket() as probe:
            try: probe.bind(('127.0.0.1', port))
            except OSError: raise RuntimeError('Refusing an occupied fixture port')
    print('Prepared new owned HTTPS fixture with real CA and separate population profiles.')


def start():
    directory, owner = state(); credentials = json.loads((directory / 'credentials.json').read_text())
    resource_floor(directory, 12)
    images = json.loads((ROOT / 'deploy/images.lock.json').read_text())
    core = ROOT / '.qualification/domain/.qualification/core'; domain = ROOT / '.qualification/domain'
    container = owner['project'] + '-postgres'
    owner['containers'].append(container); save_owner(directory, owner)
    run(['docker', 'run', '--detach', '--name', container, '--label', LABEL + '=' + owner['run'],
         '--publish', '127.0.0.1:5432:5432', '--env-file', str(directory / 'postgres.env'), images['postgres']['image']], directory, 'postgres-start')
    for _ in range(90):
        if subprocess.run(['docker', 'exec', container, 'pg_isready', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
        time.sleep(1)
    else: raise RuntimeError('Owned PostgreSQL readiness timed out')
    psql(directory, owner, f"CREATE ROLE native_kc LOGIN PASSWORD '{credentials['keycloak-db']}'; CREATE DATABASE native_kc OWNER native_kc; CREATE ROLE recovery_owner NOLOGIN; CREATE ROLE recovery_runtime LOGIN PASSWORD '{credentials['core-db']}'; CREATE DATABASE sca_native;")
    psql(directory, owner, 'REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE,CREATE ON SCHEMA public TO recovery_owner;', 'sca_native')
    for migration in sorted((core / 'core-common-sca-mgmt-models/src/main/resources/db/migration').glob('V[1-4]__*.sql')):
        psql(directory, owner, migration.read_text(), 'sca_native')
    installer = (core / 'ops/recovery-installer/install.sql').read_text().replace(":'recovery_owner'", "'recovery_owner'").replace(":'recovery_runtime'", "'recovery_runtime'").replace(':"recovery_owner"', 'recovery_owner').replace(':"recovery_runtime"', 'recovery_runtime')
    psql(directory, owner, installer, 'sca_native')
    import shutil
    for module in ('native-recovery', 'native-domain-gateway'):
        jar = ROOT / 'extensions' / module / 'target' / ('firefly-id-' + module + '-26.10.1-SNAPSHOT.jar')
        if not jar.is_file(): raise RuntimeError('Missing actual native candidate artifact')
        shutil.copyfile(jar, directory / 'providers' / jar.name); (directory / 'providers' / jar.name).chmod(0o644)
    kc = owner['project'] + '-keycloak'; owner['containers'].append(kc); save_owner(directory, owner)
    command = ['docker', 'run', '--detach', '--name', kc, '--label', LABEL + '=' + owner['run'], '--network', 'host',
               '--env-file', str(directory / 'keycloak.env'), '--env', 'KC_DB=postgres', '--env', 'KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/native_kc',
               '--env', 'KC_DB_USERNAME=native_kc', '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=native-bootstrap', '--env', 'KC_HTTP_ENABLED=false',
               '--env', 'KC_HTTP_HOST=127.0.0.1', '--env', 'KC_HTTPS_PORT=8443', '--env', 'KC_HOSTNAME=https://id.firefly.test:8443',
               '--env', 'KC_HOSTNAME_STRICT=true', '--env', 'KC_HTTPS_CERTIFICATE_FILE=/run/native/server.crt', '--env', 'KC_HTTPS_CERTIFICATE_KEY_FILE=/run/native/server.key',
               '--env', 'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m', '--env', 'FIREFLY_SUPPORT_PIN_KEYS_DIR=/run/pepper', '--env', 'FIREFLY_SUPPORT_PIN_ACTIVE_KEY=v1',
               '--env', f'JAVA_OPTS_APPEND=-Djavax.net.ssl.trustStore=/run/native/trust.p12 -Djavax.net.ssl.trustStorePassword={credentials["store"]}',
               '--volume', str(directory / 'providers') + ':/opt/keycloak/providers:ro', '--volume', str(directory / 'realms') + ':/opt/keycloak/data/import:ro',
               '--volume', str(ROOT / 'dist/themes') + ':/opt/keycloak/themes:ro', '--volume', str(directory / 'tls') + ':/run/native:ro',
               '--volume', str(directory / 'pepper') + ':/run/pepper:ro', '--volume', str(ROOT / 'config/password-blacklist.txt') + ':/opt/keycloak/data/password-blacklists/firefly-baseline.txt:ro']
    for name in ['id.firefly.test'] + [f'{service}-{profile["kind"]}.firefly.test' for profile in credentials['profiles'] for service in ('core', 'domain')]: command += ['--add-host', name + ':127.0.0.1']
    command += [images['keycloak']['image'], 'start', '--import-realm', '--spi-brute-force-protector--provider=firefly-native-recovery']
    resource_floor(directory, 12)
    run(command, directory, 'keycloak-start')
    wait_https(credentials['profiles'][0]['issuer'] + '/.well-known/openid-configuration', directory)
    # The native JDK needs the mounted CA store but never its key-store password in public logs.
    run(['sudo', 'chmod', '644', str(directory / 'tls/trust.p12')], directory, 'native-trust-access')
    for profile in credentials['profiles']:
        common = {'server.address': '127.0.0.1', 'server.ssl.enabled': True, 'server.ssl.key-store': 'file:' + str(directory / 'tls/server.p12'),
                  'server.ssl.key-store-password': credentials['store'], 'server.ssl.key-store-type': 'PKCS12', 'spring.profiles.active': 'sca-recovery-receiver',
                  'firefly.sca.recovery.enabled': True, 'firefly.cache.enabled': False, 'firefly.web.idempotency.enabled': False, 'firefly.cqrs.query.caching-enabled': False,
                  'firefly.eda.enabled': False, 'firefly.stepevents.enabled': False,
                  'logging.level.root': 'WARN', 'springdoc.api-docs.enabled': False, 'springdoc.swagger-ui.enabled': False}
        issuer = profile['issuer']; kind = profile['kind']
        core_settings = {**common, 'server.port': profile['core_port'], 'spring.flyway.enabled': False,
            'spring.r2dbc.url': 'r2dbc:postgresql://127.0.0.1:5432/sca_native', 'spring.r2dbc.username': 'recovery_runtime', 'spring.r2dbc.password': credentials['core-db'],
            'firefly.security.resource-server.enabled': True, 'firefly.security.resource-server.issuer': issuer,
            'firefly.security.resource-server.jwk-set-uri': issuer + '/protocol/openid-connect/certs', 'firefly.security.resource-server.audiences': ['firefly-recovery-core'],
            'firefly.security.resource-server.tenant-required': True, 'firefly.security.resource-server.tenant-claim-paths': ['tenant_id'],
            'firefly.security.resource-server.strict-policy': True, 'firefly.security.resource-server.signature-algorithms': ['RS256'],
            'firefly.sca.recovery.receiver.issuer': issuer, 'firefly.sca.recovery.receiver.audience': 'firefly-recovery-core',
            'firefly.sca.recovery.receiver.allowed-clients': 'native-ceremony', 'firefly.sca.recovery.receiver.allowed-populations': profile['population'],
            'firefly.sca.recovery.database-audit.enabled': True, 'firefly.sca.recovery.native-owner.enabled': True,
            'firefly.sca.recovery.native-owner.base-url': issuer + '/firefly-recovery/rpc', 'firefly.sca.recovery.native-owner.provider-id': 'firefly-keycloak-native-v1',
            'firefly.sca.recovery.native-owner.workload-client-id': 'native-core-owner', 'firefly.sca.recovery.native-owner.workload-secret-file': profile['core_secret_file'],
            'firefly.sca.recovery.native-self-policy.enabled': True, 'firefly.sca.recovery.native-self-policy.realm': profile['realm'],
            'firefly.sca.recovery.native-self-policy.actor-audiences': 'firefly-recovery-core,firefly-recovery-domain'}
        domain_settings = {**common, 'server.port': profile['domain_backend_port'] if faults_enabled() else profile['domain_port']}
        env = dict(os.environ, SCA_RECOVERY_ENABLED='true', SCA_RECOVERY_TRUSTED_ISSUER=issuer, SCA_RECOVERY_TRUSTED_JWKS_URI=issuer + '/protocol/openid-connect/certs',
                   SCA_RECOVERY_REALM=profile['realm'], SCA_RECOVERY_POPULATION=profile['population'], SCA_RECOVERY_AUDIENCES='firefly-recovery-domain,firefly-recovery-core',
                   SCA_RECOVERY_ALLOWED_CLIENTS='native-ceremony', SCA_RECOVERY_AUDIENCE='firefly-recovery-core', SCA_RECOVERY_ALLOWED_POPULATIONS=profile['population'],
                   DB_HOST='127.0.0.1', DB_PORT='5432', DB_NAME='sca_native', DB_SSL_MODE='disable', DB_USERNAME='recovery_runtime', DB_PASSWORD=credentials['core-db'],
                   ENDPOINT_CORE_SCA_MGMT=profile['core'], SCA_RECOVERY_MAX_LIFETIME_SECONDS='300' if profile['population'] == 'HUMAN' else '180',
                   SCA_RECOVERY_CORE_ORIGIN=profile['core'], SCA_RECOVERY_NATIVE_SELF_SERVICE_POLICY_ENABLED='true', SCA_RECOVERY_NATIVE_HTTP_ENABLED='true',
                   SCA_RECOVERY_NATIVE_RPC_URI=issuer + '/firefly-recovery/rpc', SCA_RECOVERY_NATIVE_WORKLOAD_USERNAME='native-domain-owner',
                   SCA_RECOVERY_NATIVE_WORKLOAD_PASSWORD_FILE=profile['domain_secret_file'], SCA_RECOVERY_NATIVE_TIMEOUT_SECONDS='5', SCA_RECOVERY_NATIVE_PROVIDER_PROFILE='firefly-keycloak-native-v1')
        for service, source, jar, settings in [('core', core, 'core-common-sca-mgmt-web/target/core-common-sca-mgmt.jar', core_settings),
                                               ('domain', domain, 'domain-common-sca-web/target/domain-common-sca.jar', domain_settings)]:
            path = source / jar
            if not path.is_file(): raise RuntimeError('Missing actual executable service artifact')
            configuration = directory / (service + '-' + kind + '.json'); configuration.write_text(json.dumps(settings)); configuration.chmod(0o600)
            service_env = dict(env, SPRING_APPLICATION_JSON=json.dumps(settings))
            with (directory / 'logs' / (service + '-' + kind + '.log')).open('ab') as output:
                process = subprocess.Popen(['java', '-Xms64m', '-Xmx384m', '-Djavax.net.ssl.trustStore=' + str(directory / 'tls/trust.p12'),
                                            '-Djavax.net.ssl.trustStorePassword=' + credentials['store'], '-jar', str(path)], cwd=source, env=service_env, stdout=output, stderr=subprocess.STDOUT)
            owner['processes'].append({'pid': process.pid, 'jar': str(path), 'kind': service + '-' + kind}); save_owner(directory, owner)
            address = backend_origin(profile) if service == 'domain' and faults_enabled() else profile[service]
            wait_https(address + '/api/v1/sca/recovery-operations', directory, process)
        if faults_enabled():
            with (directory / 'logs' / ('proxy-' + kind + '.log')).open('ab') as output:
                proxy = subprocess.Popen(['python3', str(Path(__file__).resolve()), 'serve_proxy', '--population', kind], stdout=output, stderr=subprocess.STDOUT)
            owner['processes'].append({'pid': proxy.pid, 'jar': str(Path(__file__).resolve()), 'kind': 'proxy-' + kind}); save_owner(directory, owner)
            wait_https(profile['domain'] + '/api/v1/sca/recovery-operations', directory, proxy)
    resource_floor(directory, 8)
    sdk = json.loads((domain / '.qualification/sdk-domain-summary.json').read_text())
    manifest = {'scope': 'Real owned native/Core/Domain HTTPS fixture; production and business acceptance excluded',
                'identity_source': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
                'core_source': sdk['core_source'], 'domain_source': sdk['domain_source'], 'source_parent': sdk['source_parent'],
                'candidate_sdk_version': sdk['candidate_sdk_version'], 'candidate_sdk_sha256': sdk['candidate_sdk_sha256'],
                'producer_spec_sha256': sdk['producer_spec_sha256'], 'native_image': images['keycloak']['image'], 'postgres_image': images['postgres']['image'],
                'transport_faults_enabled': faults_enabled()}
    for path in list((directory / 'providers').glob('*.jar')) + [core / 'core-common-sca-mgmt-web/target/core-common-sca-mgmt.jar', domain / 'domain-common-sca-web/target/domain-common-sca.jar']:
        manifest[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (ROOT / '.work/native-integration').mkdir(parents=True, exist_ok=True)
    (ROOT / '.work/native-integration/manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Actual native owner plus isolated customer/workforce Core/Domain HTTPS processes ready.')



def backend_origin(profile):
    endpoint = urllib.parse.urlsplit(profile['domain'])
    return endpoint._replace(netloc=endpoint.hostname + ':' + str(profile['domain_backend_port'])).geturl()


def arm_fault(kind, fault):
    if not faults_enabled(): raise RuntimeError('Owned transport faults require explicit hosted opt-in')
    directory, owner = state()
    if kind not in ('customers', 'workforce') or fault not in ('record-response-loss', 'verify-race'):
        raise RuntimeError('Unsupported owned transport fault')
    path = directory / (fault + '-' + kind)
    if path.exists() or path.with_suffix('.spent').exists():
        raise RuntimeError('Refusing to overwrite a retained fault marker')
    path.write_text('one owned negative transport fault only\n'); path.chmod(0o600)
    print('Armed one bounded owned transport fault; no provider verdict or authorization was fabricated.')


def fault_status(kind):
    if not faults_enabled() or kind not in ('customers', 'workforce'):
        raise RuntimeError('Owned transport fault status requires explicit hosted opt-in')
    directory, owner = state()
    arrivals = directory / ('verify-race-' + kind + '.arrivals')
    print(json.dumps({'recordLossSpent': (directory / ('record-response-loss-' + kind + '.spent')).is_file(),
                      'verifyRaceSpent': (directory / ('verify-race-' + kind + '.spent')).is_file(),
                      'verifyRaceArrivals': int(arrivals.read_text()) if arrivals.is_file() else 0}))


def private_proof(kind):
    if not faults_enabled() or kind not in ('customers', 'workforce'):
        raise RuntimeError('Private proof fixture requires explicit hosted opt-in')
    directory, owner = state()
    profile = next(value for value in json.loads((directory / 'credentials.json').read_text())['profiles'] if value['kind'] == kind)
    subject = profile['person']['id']
    if not re.fullmatch(r'[0-9a-f-]{36}', subject): raise RuntimeError('Noncanonical fixture subject')
    proof = psql(directory, owner, f"SELECT json_build_object('binding',c.binding_json::json,'operationId',p.operation_id,'challengeId',p.challenge_id,'reservationId',p.reservation_id,'providerChallengeId',p.provider_challenge_id,'category',p.category,'attestation',p.id,'action','COMPLETE_VERIFICATION') FROM ff_native_attestation p JOIN ff_native_ceremony c ON c.id=p.ceremony_id JOIN ff_native_state s ON s.subject=p.subject WHERE p.subject='{subject}' AND p.category='KNOWLEDGE' AND p.completed AND p.verified AND s.locked AND NOT s.hold AND p.expires_at > extract(epoch FROM clock_timestamp())*1000 AND NOT EXISTS (SELECT 1 FROM ff_native_execution e WHERE e.subject=p.subject);", 'native_kc')
    value = json.loads(proof)
    value['actorAssertion'] = (directory / 'secrets' / ('actor-' + kind)).read_text()
    print(json.dumps(value))


def serve_proxy(kind):
    if not faults_enabled(): raise RuntimeError('Owned transport faults require explicit hosted opt-in')
    directory, owner = state()
    profile = next(value for value in json.loads((directory / 'credentials.json').read_text())['profiles'] if value['kind'] == kind)
    trusted = ssl.create_default_context(cafile=str(directory / 'tls/ca.crt'))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trusted), NoRedirect())
    gate = threading.Event(); lock = threading.Lock(); arrivals = 0
    class Proxy(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self):
            self.send_response(405); self.send_header('Content-Length', '0'); self.end_headers()
        def do_POST(self):
            nonlocal arrivals
            try:
                path = urllib.parse.urlsplit(self.path)
                if path.query or not re.fullmatch(r'/api/v1/sca/recovery-operations(?:/[A-Za-z0-9/_-]+)?', path.path):
                    raise RuntimeError('Unsupported proxy route')
                length = int(self.headers.get('Content-Length', '0'))
                if length < 0 or length > 65536: raise RuntimeError('Bounded proxy input required')
                actor = self.headers.get('Authorization', '')
                if not actor.startswith('Bearer ') or len(actor) > 16391: raise RuntimeError('Actual bounded actor required')
                request = urllib.request.Request(backend_origin(profile) + path.path, data=self.rfile.read(length), method='POST',
                    headers={key: self.headers[key] for key in ('Authorization', 'Content-Type', 'Accept') if key in self.headers})
                try: response = opener.open(request, timeout=4)
                except urllib.error.HTTPError as refused: response = refused
                with response:
                    payload = response.read(65537)
                    if len(payload) > 65536: raise RuntimeError('Bounded proxy output required')
                    status = response.status; content_type = response.headers.get('Content-Type', 'application/json')
                if status == 201 and path.path == '/api/v1/sca/recovery-operations':
                    with lock:
                        actor_path = directory / 'secrets' / ('actor-' + kind)
                        if not actor_path.exists():
                            with os.fdopen(os.open(actor_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as captured:
                                captured.write(actor[7:])
                # Delay two REAL online verifications, each already accepted by real Domain/Core.
                if path.path.endswith('/authorizations/verify') and status == 200:
                    marker = directory / ('verify-race-' + kind)
                    with lock:
                        participating = marker.exists()
                        if participating:
                            arrivals += 1
                            (directory / ('verify-race-' + kind + '.arrivals')).write_text(str(arrivals))
                            if arrivals == 2:
                                marker.rename(marker.with_suffix('.spent')); gate.set()
                    if participating and not gate.wait(3): raise RuntimeError('Second genuine verification did not arrive')
                if path.path.endswith('/executions') and status == 204:
                    marker = directory / ('record-response-loss-' + kind)
                    with lock:
                        failed_response = marker.exists()
                        if failed_response: marker.rename(marker.with_suffix('.spent'))
                    if failed_response:
                        status = 503; payload = b'{"error":"owned_transport_response_unavailable"}'; content_type = 'application/json'
                self.send_response(status); self.send_header('Content-Type', content_type)
                self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(payload))); self.end_headers()
                if payload: self.wfile.write(payload)
            except Exception:
                try:
                    self.send_response(503); self.send_header('Content-Length', '0'); self.end_headers()
                except Exception: pass
    class OwnedServer(http.server.ThreadingHTTPServer):
        daemon_threads = True
        def handle_error(self, *_): pass
    server = OwnedServer(('127.0.0.1', profile['domain_port']), Proxy)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(directory / 'tls/server.crt', directory / 'tls/proxy.key')
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def snapshot(kind):
    directory, owner = state(); credentials = json.loads((directory / 'credentials.json').read_text())
    profile = next(p for p in credentials['profiles'] if p['kind'] == kind); subject = profile['person']['id']
    if not re.fullmatch(r'[0-9a-f-]{36}', subject): raise RuntimeError('Noncanonical fixture subject')
    native = psql(directory, owner, f"SELECT coalesce((SELECT json_build_object('locked',locked,'hold',hold,'generation',generation,'bootstrap',bootstrap_attempts,'knowledge',knowledge_attempts,'possession',possession_attempts,'pinActive',(pin_credential_id IS NOT NULL AND pin_revoked_at=0)) FROM ff_native_state WHERE subject='{subject}'),'{{}}'::json)::jsonb || jsonb_build_object('executions',(SELECT count(*) FROM ff_native_execution WHERE subject='{subject}'),'executionId',(SELECT id FROM ff_native_execution WHERE subject='{subject}' LIMIT 1),'recorded',(SELECT recorded FROM ff_native_execution WHERE subject='{subject}' LIMIT 1),'recordAttempts',(SELECT record_attempts FROM ff_native_execution WHERE subject='{subject}' LIMIT 1),'unlockAudits',(SELECT count(*) FROM ff_native_audit WHERE subject='{subject}' AND event_type='NATIVE_UNLOCK_COMMITTED'),'recordAudits',(SELECT count(*) FROM ff_native_audit WHERE subject='{subject}' AND event_type='NATIVE_EXECUTION_RECORDED'),'attestations',(SELECT count(*) FROM ff_native_attestation WHERE subject='{subject}'),'maximumChecksPerReservation',(SELECT coalesce(max(total),0) FROM (SELECT count(*) total FROM ff_native_attestation WHERE subject='{subject}' GROUP BY reservation_id) q));", 'native_kc')
    core = psql(directory, owner, f"SELECT coalesce(json_agg(json_build_object('generation',lock_generation,'state',state,'attempts',attempt_count,'challenges',challenge_count,'outcome',execution_outcome,'executionId',execution_id,'successAudits',(SELECT count(*) FROM sca_recovery_audit a WHERE a.operation_id=sca_recovery_operation.id AND a.event_type='EXECUTION_SUCCEEDED')) ORDER BY created_at),'[]'::json) FROM sca_recovery_operation WHERE target_subject='{subject}';", 'sca_native')
    print(json.dumps({'native': json.loads(native), 'core': json.loads(core)}))


def restart():
    directory, owner = state(); container = owner['project'] + '-keycloak'; inspect_container(owner, container)
    run(['docker', 'restart', container], directory, 'native-restart')
    profile = json.loads((directory / 'credentials.json').read_text())['profiles'][0]
    wait_https(profile['issuer'] + '/.well-known/openid-configuration', directory)
    print('Restarted only the owned native process, preserving its PostgreSQL data and mounted keys.')


def stop():
    directory, owner = state()
    for process in owner['processes']:
        command = Path('/proc') / str(process['pid']) / 'cmdline'
        if command.exists():
            if process['jar'].encode() not in command.read_bytes(): raise RuntimeError('Process ownership mismatch')
            os.kill(process['pid'], signal.SIGTERM)
    for container in reversed(owner['containers']):
        if subprocess.run(['docker', 'inspect', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            continue
        inspect_container(owner, container)
        run(['docker', 'stop', '--time', '30', container], directory, 'owned-container-stop')
    print('Stopped only this attempt\'s owned processes/containers; preserved containers, volumes and data.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'start', 'stop', 'restart', 'snapshot', 'serve_proxy', 'arm_record_loss', 'arm_verify_race', 'fault_status', 'private_proof'])
    parser.add_argument('--population', choices=['customers', 'workforce'])
    args = parser.parse_args(); require_hosted()
    if args.action == 'snapshot': snapshot(args.population)
    elif args.action == 'serve_proxy': serve_proxy(args.population)
    elif args.action == 'arm_record_loss': arm_fault(args.population, 'record-response-loss')
    elif args.action == 'arm_verify_race': arm_fault(args.population, 'verify-race')
    elif args.action == 'fault_status': fault_status(args.population)
    elif args.action == 'private_proof': private_proof(args.population)
    else: globals()[args.action]()


if __name__ == '__main__':
    try: main()
    except Exception:
        evidence = ROOT / '.work/native-integration'
        evidence.mkdir(parents=True, exist_ok=True)
        diagnostic = {'status': 'BOOT_OR_LIFECYCLE_FAILED', 'stage': PHASE, 'exceptionClasses': []}
        try:
            directory, owner = state()
            credentials = json.loads((directory / 'credentials.json').read_text())
            secrets_to_redact = [credentials[key] for key in ('postgres', 'keycloak-db', 'core-db', 'admin', 'store')]
            secrets_to_redact += [profile['person']['password'] for profile in credentials['profiles']]
            secrets_to_redact += [path.read_text().strip() for path in (directory / 'secrets').iterdir() if path.is_file()]
            diagnostic['containerStates'] = []
            for container in owner['containers']:
                if subprocess.run(['docker', 'inspect', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                    continue
                actual = inspect_container(owner, container)
                diagnostic['containerStates'].append({'kind': 'keycloak' if container.endswith('-keycloak') else 'postgres',
                                                     'running': actual['State']['Running'], 'exitCode': actual['State']['ExitCode']})
                captured = subprocess.run(['docker', 'logs', '--tail', '2000', container], capture_output=True)
                (directory / 'logs' / ('keycloak-private.log' if container.endswith('-keycloak') else 'postgres-private.log')).write_bytes(captured.stdout + captured.stderr)
            diagnostic['loopbackDns'] = {}
            for host in ['id.firefly.test'] + [f'{service}-{profile["kind"]}.firefly.test' for profile in credentials['profiles'] for service in ('core', 'domain')]:
                try:
                    diagnostic['loopbackDns'][host] = all(value[4][0] in ('127.0.0.1', '::1') for value in socket.getaddrinfo(host, None))
                except OSError:
                    diagnostic['loopbackDns'][host] = False
            for log in (directory / 'logs').glob('*.log'):
                content = log.read_text(errors='replace')
                diagnostic['exceptionClasses'].extend(re.findall(r'Caused by: ([A-Za-z0-9_.$]+)', content)[-6:])
                missing = re.findall(r"required a bean of type '([A-Za-z0-9_.$]+)'", content)
                diagnostic.setdefault('missingBeanTypes', []).extend(missing[-4:])
                # Startup-only bounded diagnostics: no browser has run or actor assertion been minted.
                if PHASE.startswith('https-readiness-'):
                    lines = [line for line in content.splitlines() if 'ERROR:' in line or 'Caused by:' in line or 'Failed to start' in line][-8:]
                    for line in lines:
                        if any(field in line for field in ('actorAssertion', 'Authorization:', 'Bearer ')) or ('{' in line and '}' in line):
                            continue
                        if 'secret' in line.lower() or 'password' in line.lower():
                            diagnostic.setdefault('sanitizedStartupErrors', []).append('Native startup authentication/secret configuration failure [DETAILS REDACTED]')
                            continue
                        for secret in secrets_to_redact:
                            if secret: line = line.replace(secret, '[REDACTED]')
                        line = re.sub(r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}', '[REDACTED JWT]', line)
                        diagnostic.setdefault('sanitizedStartupErrors', []).append(line[:500])
        except Exception:
            pass
        (evidence / 'boot-summary.json').write_text(json.dumps(diagnostic, indent=2) + '\n')
        print('Native integration fixture failed at ' + PHASE + '; raw credentials, bodies and provider logs remain private.', file=__import__('sys').stderr)
        raise SystemExit(1)
