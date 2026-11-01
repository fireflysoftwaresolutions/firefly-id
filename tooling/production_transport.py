#!/usr/bin/env python3
"""Hosted-only, disposable transport checks against the pinned upstream servers."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OWNER_LABEL = 'org.firefly-id.transport'
DATABASE_HOST = 'db.production-transport.test'
WRONG_DATABASE_HOST = 'wrong.production-transport.test'
SERVER_HOST = 'id.production-transport.test'
EXPECTED_REFERENCE = {
    'db': 'postgres',
    'db-url': '${FIREFLY_ID_DATABASE_URL}',
    'db-username': '${FIREFLY_ID_DATABASE_USER}',
    'db-tls-mode': 'verify-server',
    'db-tls-trust-store-file': '/run/secrets/database-ca.pem',
    'http-enabled': 'false',
    'https-certificate-file': '/run/secrets/tls.crt',
    'https-certificate-key-file': '/run/secrets/tls.key',
    'https-protocols': 'TLSv1.3,TLSv1.2',
    'tls-hostname-verifier': 'DEFAULT',
    'http-management-scheme': 'inherited',
    'http-management-port': '9000',
    'legacy-observability-interface': 'false',
    'health-enabled': 'true',
    'metrics-enabled': 'true',
}


def validate_reference(content):
    settings = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key in settings:
            raise ValueError('Invalid reference properties')
        settings[key] = value
    if any(settings.get(key) != value for key, value in EXPECTED_REFERENCE.items()):
        raise ValueError('Transport reference changed')


def database_ready(body):
    try:
        value = json.loads(body)
        checks = value['checks']
        return (value['status'] == 'UP' and isinstance(checks, list) and bool(checks)
                and all(check['status'] == 'UP' for check in checks)
                and any('database' in check['name'].lower() for check in checks))
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def tls_failure_kind(log):
    hostname = bool(re.search(r'hostname .+? could not be verified by hostnameverifier', log, re.I))
    authority = bool(re.search(r'PKIX path building failed|unable to find valid certification path|'
                               r'Path does not chain with any of the trust anchors', log, re.I))
    if hostname and not authority:
        return 'DATABASE_HOSTNAME_REFUSED'
    if authority and not hostname:
        return 'DATABASE_CA_REFUSED'
    return None


def loopback_port(output):
    match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})\s*', output)
    if not match or not 1 <= int(match[1]) <= 65535:
        raise ValueError('Unexpected port binding')
    return int(match[1])


def plaintext_refused(response):
    return response == b'' or bool(re.match(rb'HTTP/1\.[01] 400(?: |\r)', response))


class TransportFailure(Exception):
    """Carries no subprocess, certificate, credential or network diagnostic."""


def command(arguments, timeout=30, required=True):
    try:
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise TransportFailure() from None
    if required and result.returncode != 0:
        raise TransportFailure()
    return result


def https_response(port, ca_file, path, server_name=SERVER_HOST):
    context = ssl.create_default_context(cafile=str(ca_file))
    with socket.create_connection(('127.0.0.1', port), timeout=4) as connection:
        with context.wrap_socket(connection, server_hostname=server_name) as secure:
            secure.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + SERVER_HOST
                            + '\r\nConnection: close\r\n\r\n').encode('ascii'))
            response = http.client.HTTPResponse(secure)
            response.begin()
            body = response.read(65537)
            if len(body) > 65536:
                raise TransportFailure()
            return response.status, body


class HostedTransport:
    def __init__(self, state, summary):
        self.state = state
        self.summary = summary
        self.owner = uuid.uuid4().hex
        self.network = 'firefly-transport-' + self.owner
        self.containers = []
        self.network_created = False
        self.images = json.loads((ROOT / 'deploy/images.lock.json').read_text())
        for component in ('keycloak', 'postgres'):
            if not re.fullmatch(r'[a-z0-9./:-]+@sha256:[0-9a-f]{64}', self.images[component]['image']):
                raise TransportFailure()

    def check(self, condition):
        if not condition:
            raise TransportFailure()

    def record(self, stage):
        self.summary['passed'].append(stage)

    def write(self, name, content, mode=0o600):
        path = self.state / name
        path.write_text(content)
        path.chmod(mode)
        return path

    def mount(self, source, target):
        return ['--mount', 'type=bind,source=' + str(source) + ',target=' + target + ',readonly']

    def create_certificates(self):
        for prefix in ('ca', 'untrusted-ca'):
            command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                     '-keyout', str(self.state / (prefix + '.key')),
                     '-out', str(self.state / (prefix + '.pem')), '-days', '1',
                     '-subj', '/CN=Firefly-Transport-' + prefix,
                     '-addext', 'basicConstraints=critical,CA:TRUE',
                     '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], timeout=30)
        for prefix, names in [('database', [DATABASE_HOST]),
                              ('server', [SERVER_HOST, 'admin.production-transport.test'])]:
            command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                     '-keyout', str(self.state / (prefix + '.key')),
                     '-out', str(self.state / (prefix + '.csr')),
                     '-subj', '/CN=' + names[0]], timeout=30)
            extensions = self.write(prefix + '.extensions',
                                    'subjectAltName=' + ','.join('DNS:' + name for name in names)
                                    + '\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n')
            command(['openssl', 'x509', '-req', '-in', str(self.state / (prefix + '.csr')),
                     '-CA', str(self.state / 'ca.pem'), '-CAkey', str(self.state / 'ca.key'),
                     '-CAcreateserial', '-out', str(self.state / (prefix + '.pem')), '-days', '1',
                     '-extfile', str(extensions)], timeout=30)
        # Only individual files enter containers; the containing host directory stays 0700.
        for name in ('ca.pem', 'untrusted-ca.pem', 'database.pem', 'database.key', 'server.pem', 'server.key'):
            (self.state / name).chmod(0o644)
        self.summary['certificate_sha256'] = {
            name: hashlib.sha256((self.state / name).read_bytes()).hexdigest()
            for name in ('ca.pem', 'untrusted-ca.pem', 'database.pem', 'server.pem')}

    def start_database(self):
        self.database = 'firefly-transport-db-' + self.owner
        self.password = secrets.token_hex(32)
        environment = self.write('postgres.env',
                                 'POSTGRES_USER=transport_admin\nPOSTGRES_DB=postgres\n'
                                 'POSTGRES_PASSWORD=' + secrets.token_hex(32) + '\n')
        initialization = self.write('identity.sql',
                                    "CREATE USER identity_service PASSWORD '" + self.password + "';\n"
                                    'CREATE DATABASE identity OWNER identity_service;\n', 0o644)
        hba = self.write('pg_hba.conf', 'local all all trust\n'
                         'hostssl all all 0.0.0.0/0 scram-sha-256\n'
                         'hostssl all all ::/0 scram-sha-256\n'
                         'hostnossl all all 0.0.0.0/0 reject\n'
                         'hostnossl all all ::/0 reject\n', 0o644)
        boot = ('mkdir -m 700 /tmp/firefly-transport; '
                'cp /fixture/server.key /fixture/server.crt /fixture/pg_hba.conf /tmp/firefly-transport/; '
                'chown -R postgres:postgres /tmp/firefly-transport; '
                'chmod 600 /tmp/firefly-transport/server.key; '
                'exec /usr/local/bin/docker-entrypoint.sh postgres '
                '-c ssl=on -c ssl_min_protocol_version=TLSv1.2 '
                '-c ssl_cert_file=/tmp/firefly-transport/server.crt '
                '-c ssl_key_file=/tmp/firefly-transport/server.key '
                '-c hba_file=/tmp/firefly-transport/pg_hba.conf')
        args = ['docker', 'run', '-d', '--name', self.database, '--label', OWNER_LABEL + '=' + self.owner,
                '--network', self.network, '--network-alias', DATABASE_HOST,
                '--network-alias', WRONG_DATABASE_HOST, '--memory', '512m',
                '--tmpfs', '/var/lib/postgresql/data:rw,size=512m',
                '--log-driver', 'local', '--log-opt', 'max-size=2m', '--log-opt', 'max-file=1',
                '--env-file', str(environment)]
        args += self.mount(self.state / 'database.key', '/fixture/server.key')
        args += self.mount(self.state / 'database.pem', '/fixture/server.crt')
        args += self.mount(hba, '/fixture/pg_hba.conf')
        args += self.mount(initialization, '/docker-entrypoint-initdb.d/10-identity.sql')
        args += ['--entrypoint', '/bin/bash', self.images['postgres']['image'], '-ec', boot]
        self.containers.append(self.database)
        command(args)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ready = command(['docker', 'exec', self.database, 'pg_isready', '-h', '127.0.0.1', '-U', 'transport_admin',
                             '-d', 'identity'], required=False)
            if ready.returncode == 0:
                return
            time.sleep(1)
        raise TransportFailure()

    def start_keycloak(self, scenario, host, authority):
        name = 'firefly-transport-' + scenario + '-' + self.owner
        environment = self.write(scenario + '.env',
                                 'FIREFLY_ID_DATABASE_URL=jdbc:postgresql://' + host + ':5432/identity\n'
                                 'FIREFLY_ID_DATABASE_USER=identity_service\n'
                                 'KCRAW_DB_PASSWORD=' + self.password + '\n'
                                 'FIREFLY_ID_PUBLIC_URL=https://' + SERVER_HOST + '\n'
                                 'FIREFLY_ID_ADMIN_URL=https://admin.production-transport.test\n'
                                 'FIREFLY_ID_PROXY_CIDRS=127.0.0.1/32\n'
                                 'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m\n')
        args = ['docker', 'run', '-d', '--name', name, '--label', OWNER_LABEL + '=' + self.owner,
                '--network', self.network, '--memory', '1536m', '--cpus', '2',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--log-driver', 'local', '--log-opt', 'max-size=2m', '--log-opt', 'max-file=1',
                '--publish', '127.0.0.1::8443', '--publish', '127.0.0.1::9000',
                '--env-file', str(environment)]
        args += self.mount(ROOT / 'deploy/keycloak.production.conf.example', '/opt/keycloak/conf/keycloak.conf')
        args += self.mount(self.state / authority, '/run/secrets/database-ca.pem')
        args += self.mount(self.state / 'server.pem', '/run/secrets/tls.crt')
        args += self.mount(self.state / 'server.key', '/run/secrets/tls.key')
        args += [self.images['keycloak']['image'], '--verbose', 'start', '--cache=local',
                 '--db-connect-timeout=10', '--db-pool-max-size=4']
        self.containers.append(name)
        command(args)
        return name

    def port(self, name, port):
        return loopback_port(command(['docker', 'port', name, str(port) + '/tcp']).stdout.decode())

    def state_of(self, name):
        result = command(['docker', 'inspect', '--format', '{{json .State}}', name])
        return json.loads(result.stdout)

    def wait_ready(self, name):
        port = self.port(name, 9000)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if not self.state_of(name)['Running']:
                raise TransportFailure()
            try:
                status, body = https_response(port, self.state / 'ca.pem', '/health/ready')
                if status == 200 and database_ready(body):
                    return port
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(1)
        raise TransportFailure()

    def require_database_tls(self):
        query = ("SELECT count(*) > 0 AND bool_and(s.ssl AND s.version IN ('TLSv1.2','TLSv1.3') "
                 "AND s.bits >= 128) FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid) "
                 "WHERE a.usename='identity_service' AND a.datname='identity';")
        result = command(['docker', 'exec', self.database, 'psql', '-U', 'transport_admin',
                          '-d', 'postgres', '-tAc', query])
        self.check(result.stdout.strip() == b't')

    def positive(self, scenario, full_checks):
        self.summary['stage'] = scenario.upper() + '_KEYCLOAK_START'
        name = self.start_keycloak(scenario, DATABASE_HOST, 'ca.pem')
        self.summary['stage'] = scenario.upper() + '_MANAGEMENT_READINESS'
        management_port = self.wait_ready(name)
        self.summary['stage'] = scenario.upper() + '_DATABASE_TLS_SESSION'
        self.require_database_tls()
        self.record(scenario.upper() + '_VERIFIED_DATABASE_TLS')
        if full_checks:
            self.summary['stage'] = 'MAIN_HTTPS_DISCOVERY'
            main_port = self.port(name, 8443)
            status, body = https_response(main_port, self.state / 'ca.pem',
                                          '/realms/master/.well-known/openid-configuration')
            self.check(status == 200 and json.loads(body)['issuer'] == 'https://' + SERVER_HOST + '/realms/master')
            self.record('MAIN_HTTPS_DISCOVERY')
            self.summary['stage'] = 'HEALTH_ONLY_ON_MANAGEMENT'
            status, _ = https_response(main_port, self.state / 'ca.pem', '/health/ready')
            self.check(status == 404)
            self.record('HEALTH_ONLY_ON_MANAGEMENT')
            self.record('MANAGEMENT_HTTPS_DATABASE_READY')
            self.summary['stage'] = 'MANAGEMENT_UNTRUSTED_CA_REFUSED'
            try:
                https_response(management_port, self.state / 'untrusted-ca.pem', '/health/ready')
            except ssl.SSLCertVerificationError:
                self.record('MANAGEMENT_UNTRUSTED_CA_REFUSED')
            else:
                raise TransportFailure()
            self.summary['stage'] = 'MANAGEMENT_WRONG_HOSTNAME_REFUSED'
            try:
                https_response(management_port, self.state / 'ca.pem', '/health/ready',
                               server_name='wrong.production-transport.test')
            except ssl.SSLCertVerificationError:
                self.record('MANAGEMENT_WRONG_HOSTNAME_REFUSED')
            else:
                raise TransportFailure()
            self.summary['stage'] = 'MANAGEMENT_PLAINTEXT_REFUSED'
            with socket.create_connection(('127.0.0.1', management_port), timeout=4) as connection:
                connection.sendall(b'GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                try:
                    response = connection.recv(512)
                except ConnectionResetError:
                    response = b''
                self.check(plaintext_refused(response))
            self.record('MANAGEMENT_PLAINTEXT_REFUSED')
            # Probe inside the actual process network namespace, rather than merely omitting a host mapping.
            self.summary['stage'] = 'MAIN_HTTP_LISTENER_ABSENT'
            for port, expected in [(8443, True), (8080, False)]:
                probe = command(['docker', 'exec', name, '/bin/bash', '-ec',
                                 'exec 3<>/dev/tcp/127.0.0.1/' + str(port)], required=False)
                self.check((probe.returncode == 0) == expected)
            self.record('MAIN_HTTP_LISTENER_ABSENT')
        self.remove_container(name)

    def negative(self, scenario, host, authority, expected):
        name = self.start_keycloak(scenario, host, authority)
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            state = self.state_of(name)
            if not state['Running']:
                logs = command(['docker', 'logs', '--tail', '200', name]).stdout.decode(errors='replace')
                observed = tls_failure_kind(logs)
                self.summary.setdefault('negative_outcomes', []).append({
                    'scenario': scenario, 'expected': expected, 'observed': observed or 'UNCLASSIFIED',
                    'exit_code': state['ExitCode'], 'out_of_memory': state['OOMKilled']})
                self.check(state['ExitCode'] != 0 and not state['OOMKilled'] and observed == expected)
                self.record(expected)
                self.remove_container(name)
                return
            time.sleep(1)
        raise TransportFailure()

    def remove_container(self, name):
        owner = command(['docker', 'inspect', '--format',
                         '{{ index .Config.Labels "' + OWNER_LABEL + '" }}', name], required=False)
        if owner.returncode != 0:
            return
        self.check(owner.stdout.decode().strip() == self.owner)
        command(['docker', 'rm', '--force', name], timeout=40)
        self.containers.remove(name)

    def cleanup(self):
        success = True
        for name in list(self.containers):
            try:
                self.remove_container(name)
            except (TransportFailure, ValueError):
                success = False
        if self.network_created:
            try:
                owner = command(['docker', 'network', 'inspect', '--format',
                                 '{{ index .Labels "' + OWNER_LABEL + '" }}', self.network])
                self.check(owner.stdout.decode().strip() == self.owner)
                command(['docker', 'network', 'rm', self.network])
            except (TransportFailure, ValueError):
                success = False
        return success

    def run(self):
        self.summary['images'] = {key: self.images[key]['image'] for key in ('keycloak', 'postgres')}
        for component in ('keycloak', 'postgres'):
            self.summary['stage'] = 'PULL_' + component.upper()
            command(['docker', 'pull', self.images[component]['image']], timeout=240)
        self.summary['stage'] = 'SYNTHETIC_CERTIFICATES'
        self.create_certificates()
        command(['docker', 'network', 'create', '--internal', '--label',
                 OWNER_LABEL + '=' + self.owner, self.network])
        self.network_created = True
        self.summary['stage'] = 'DATABASE_START'
        self.start_database()
        self.summary['stage'] = 'VERIFIED_BASELINE'
        self.positive('baseline', full_checks=True)
        self.summary['stage'] = 'WRONG_DATABASE_HOSTNAME'
        self.negative('wrong-host', WRONG_DATABASE_HOST, 'ca.pem', 'DATABASE_HOSTNAME_REFUSED')
        self.summary['stage'] = 'UNTRUSTED_DATABASE_CA'
        self.negative('wrong-ca', DATABASE_HOST, 'untrusted-ca.pem', 'DATABASE_CA_REFUSED')
        self.summary['stage'] = 'VERIFIED_RECONTROL'
        self.positive('recontrol', full_checks=False)


def main():
    output = ROOT / '.work/production-transport'
    output.mkdir(parents=True, exist_ok=True)
    summary = {
        'schema_version': 1,
        'scope': 'Pinned upstream Keycloak/PostgreSQL with synthetic certificates and disposable state; '
                 'production reference transport only, no institution ingress, identity journeys, migration or HA acceptance',
        'fixture_only_options': ['cache=local', 'db-connect-timeout=10', 'db-pool-max-size=4'],
        'status': 'failed', 'stage': 'HOSTED_RUNNER_GUARD', 'passed': [], 'failures': [],
    }
    qualification = None
    try:
        if not (os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and os.environ.get('RUNNER_OS') == 'Linux'):
            raise TransportFailure()
        revision = os.environ.get('GITHUB_SHA', '')
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise TransportFailure()
        summary['source'] = revision
        summary['stage'] = 'REFERENCE_CONTRACT'
        reference = (ROOT / 'deploy/keycloak.production.conf.example').read_bytes()
        validate_reference(reference.decode())
        summary['reference_sha256'] = hashlib.sha256(reference).hexdigest()
        summary['image_lock_sha256'] = hashlib.sha256((ROOT / 'deploy/images.lock.json').read_bytes()).hexdigest()
        state = Path(tempfile.mkdtemp(prefix='firefly-production-transport-', dir=os.environ['RUNNER_TEMP']))
        state.chmod(0o700)
        qualification = HostedTransport(state, summary)
        qualification.run()
        summary['stage'] = 'COMPLETE'
        summary['status'] = 'passed'
    except Exception:
        # All failure output is a fixed stage; unexpected library exceptions may include private inputs.
        summary['failures'].append(summary['stage'])
    finally:
        if qualification and not qualification.cleanup():
            summary['status'] = 'failed'
            summary['failures'].append('OWNED_RESOURCE_CLEANUP')
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
