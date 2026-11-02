"""Owned hosted-only real native service concurrency and retained synthetic migration.

No CLI targets are accepted. Raw Docker/HTTP/SQL output stays private in this
attempt; the only published artifact is an allowlisted status/count receipt.
"""
from enum import Enum
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
import traceback
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'io.firefly.identity.support-retained'
MIGRATION = 'META-INF/firefly-native-recovery.xml'
CHANGESET = 'firefly-native-support-evidence-2'
HISTORY_TABLE = 'databasechangelog_firefly_na'
HISTORICAL_IDS = ('firefly-native-recovery-1', 'firefly-native-issued-challenge-1', 'firefly-native-support-proof-1',
                  'firefly-native-totp-replay-1', 'firefly-native-audit-append-only-1',
                  'firefly-native-execution-reconciliation-1', 'firefly-native-form-feedback-1',
                  'firefly-native-admin-pin-audit-1', 'firefly-native-admin-pin-audit-check-1')
TABLES = ('ff_native_state', 'ff_native_ceremony', 'ff_native_attestation', 'ff_native_execution',
          'ff_native_audit', 'ff_native_issued_challenge', 'ff_native_support_proof', 'ff_native_totp_replay',
          'user_entity', 'credential', 'user_attribute')


class FailureCategory(str, Enum):
    COMMAND_FAILED = 'COMMAND_FAILED'
    COMMAND_TIMEOUT = 'COMMAND_TIMEOUT'
    IMAGE_BUILD_FAILED = 'IMAGE_BUILD_FAILED'
    METADATA_INVALID = 'METADATA_INVALID'
    OWNERSHIP_INVALID = 'OWNERSHIP_INVALID'
    TOPOLOGY_INVALID = 'TOPOLOGY_INVALID'
    READINESS_TIMEOUT = 'READINESS_TIMEOUT'
    HTTP_TRANSPORT = 'HTTP_TRANSPORT'
    HTTP_STATUS_UNEXPECTED = 'HTTP_STATUS_UNEXPECTED'
    DATABASE_IDENTITY_CHANGED = 'DATABASE_IDENTITY_CHANGED'
    RETAINED_VALUES_CHANGED = 'RETAINED_VALUES_CHANGED'
    LIQUIBASE_HISTORY_CHANGED = 'LIQUIBASE_HISTORY_CHANGED'
    MIGRATION_NOT_APPLIED = 'MIGRATION_NOT_APPLIED'
    NONCE_FENCE_NOT_INSTALLED = 'NONCE_FENCE_NOT_INSTALLED'
    UNEXPECTED_EXCEPTION = 'UNEXPECTED_EXCEPTION'


class QualificationFailure(RuntimeError):
    def __init__(self, category):
        self.category = category
        super().__init__(category.value)


def admit():
    if any(os.environ.get(key) != value for key, value in {
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}.items()):
        raise RuntimeError('Owned GitHub hosted runner required')
    run = os.environ.get('GITHUB_RUN_ID', '') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not re.fullmatch(r'[0-9]+-[0-9]+', run):
        raise RuntimeError('Numeric owned run required')
    if any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_TLS', 'DOCKER_CERT_PATH')):
        raise RuntimeError('Docker selection overrides refused')
    result = subprocess.run(['docker', 'context', 'inspect', 'default', '--format', '{{json .Endpoints.docker.Host}}'],
                            capture_output=True, timeout=10)
    try:
        if result.returncode or json.loads(result.stdout) != 'unix:///var/run/docker.sock':
            raise RuntimeError('Default local Unix Docker daemon required')
    except (ValueError, TypeError):
        raise RuntimeError('Default local Unix Docker daemon required') from None
    return run


def bounded_diagnostics(raw):
    locations = []
    filenames = {'SupportQualificationResource.java', 'SupportQualificationOwner.java', 'SupportQualificationFactory.java'}
    categories = {'cannot find symbol': 'CANNOT_FIND_SYMBOL', 'incompatible types': 'INCOMPATIBLE_TYPES',
                  'does not exist': 'MISSING_PACKAGE', 'expected': 'JAVA_SYNTAX', 'illegal': 'JAVA_SYNTAX'}
    for filename, line, column, message in re.findall(r'(?m)^\[ERROR\]\s+[^\n]*[/\\]([A-Za-z0-9_]+\.java):\[(\d+),(\d+)\]([^\n]*)', raw):
        category = next((value for key, value in categories.items() if key in message), 'COMPILER_ERROR')
        if filename in filenames:
            locations.append({'file': filename, 'line': int(line), 'column': int(column), 'category': category})
    states = sorted(set(re.findall(r'(?:ERROR:\s+|SQLState:\s*|SQLSTATE[=: ]+)([A-Z0-9]{5})(?=[:\s]|$)', raw))
                    & {'23505', '23502', '23514', '42501', '42P01', '42703', '42601', '55P03', '57014', 'FQ001'})
    frames = re.findall(r'(?m)^\s+at (io\.firefly\.id\.nativeauth\.(?:Native|SupportQualification)[A-Za-z0-9_$]+\.[A-Za-z0-9_$<>]+\((?:Native|SupportQualification)[A-Za-z0-9_$]+\.java:\d+\))', raw)
    signatures = [
        ('LIQUIBASE_VALIDATION_FAILED', 'liquibase.exception.ValidationFailedException'),
        ('LIQUIBASE_CHECKSUM_MISMATCH', 'checksum'),
        ('LIQUIBASE_MIGRATION_FAILED', 'liquibase.exception.MigrationFailedException'),
        ('LIQUIBASE_DATABASE_ERROR', 'liquibase.exception.DatabaseException'),
        ('KEYCLOAK_STARTUP_FAILED', 'Failed to start server'),
        ('KEYCLOAK_DATABASE_UPDATE_FAILED', 'Failed to update database'),
        ('HIBERNATE_SCHEMA_FAILED', 'SchemaManagementException'),
        ('DATABASE_CONNECTION_FAILED', 'Unable to acquire JDBC connection'),
        ('JAVA_OUT_OF_MEMORY', 'java.lang.OutOfMemoryError'),
    ]
    runtime = [category for category, pattern in signatures if pattern in raw and
               (category != 'LIQUIBASE_CHECKSUM_MISMATCH' or 'liquibase' in raw.lower())]
    return {'compiler_locations': locations[:12], 'sqlstates': states[:8], 'source_frames': frames[:8],
            'runtime_categories': runtime,
            'exception_classes': list(dict.fromkeys(re.findall(
                r'(?m)^(?:Caused by: |ERROR:\s*)?((?:java\.lang|jakarta\.persistence|org\.keycloak(?:\.[A-Za-z0-9_]+)*|liquibase\.exception|org\.hibernate(?:\.[A-Za-z0-9_]+)*|org\.postgresql\.util)\.[A-Za-z0-9_$]*(?:Exception|Error))(?=:|$)', raw)))[:8],
            'framework_frames': re.findall(
                r'(?m)^\s+at ((?:org\.keycloak|liquibase|org\.hibernate|org\.postgresql)(?:\.[A-Za-z0-9_$]+)+\.[A-Za-z0-9_$<>]+\([A-Za-z0-9_$]+\.java:[0-9]+\))', raw)[:8]}



def historical_jar(original, target):
    # Exclusive creation protects a retained historical candidate, even if input equals output.
    with Path(target).open('xb') as output:
        with zipfile.ZipFile(original) as source, zipfile.ZipFile(output, 'w') as destination:
            current = source.read(MIGRATION)
            pattern = rb'<changeSet id="firefly-native-support-evidence-2" author="firefly-id">.*?</changeSet>\n'
            historical, removed = re.subn(pattern, b'', current, flags=re.DOTALL)
            if removed != 1:
                raise RuntimeError('Historical migration boundary unavailable')
            namespace = '{http://www.liquibase.org/xml/ns/dbchangelog}'
            old = ET.fromstring(historical).findall(namespace + 'changeSet')
            new = ET.fromstring(current).findall(namespace + 'changeSet')
            if [ET.tostring(node) for node in old] != [ET.tostring(node) for node in new[:-1]]:
                raise RuntimeError('Earlier Liquibase history changed')
            for info in source.infolist():
                destination.writestr(info, historical if info.filename == MIGRATION else source.read(info.filename))
    return {'excluded_changeset': CHANGESET, 'historical_changesets': len(old),
            'historical_xml_sha256': hashlib.sha256(historical).hexdigest(),
            'current_xml_sha256': hashlib.sha256(current).hexdigest(),
            'scope': 'Synthetic schema baseline from unchanged prior changesets; not a published historical binary'}


class Fixture:
    def __init__(self, run):
        self.run = run
        self.prefix = 'firefly-support-retained-' + run
        self.db = self.prefix + '-db'
        self.server = self.prefix + '-identity'
        self.network = self.prefix + '-network'
        self.directory = ROOT / '.qualification/support-retained'
        self.secret = secrets.token_urlsafe(48)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.columns = {}
        self.retained = {}
        self.database_identity = None
        self.server_running = False
        self.failure_index = 0
        self.receipt = {'result': 'failed', 'scope': 'Owned synthetic native service transactions and retained schema only; no genuine BPO owner or institution acceptance',
                        'scenarios': {}, 'phase': 'INITIALIZE'}

    def command(self, args, *, input=None, timeout=30, include_stderr=False):
        try:
            result = subprocess.run(args, input=input, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.failure((error.stdout or b'') + b'\n' + (error.stderr or b''))
            raise QualificationFailure(FailureCategory.COMMAND_TIMEOUT) from None
        if result.returncode:
            self.failure(result.stdout + b'\n' + result.stderr)
            self.receipt['command_failure'] = {'exit_code': int(result.returncode)}
            raise QualificationFailure(FailureCategory.COMMAND_FAILED)
        return result.stdout + b'\n' + result.stderr if include_stderr else result.stdout

    def docker(self, *args, **kwargs):
        return self.command(['docker', '--context', 'default', *args], **kwargs)

    def failure(self, raw):
        if isinstance(raw, str):
            raw = raw.encode()
        self.failure_index += 1
        if self.directory.is_dir():
            self.private('private-failure-' + str(self.failure_index) + '.log', raw)
        incoming = bounded_diagnostics(raw.decode(errors='replace'))
        existing = self.receipt.setdefault('diagnostics', {'compiler_locations': [], 'sqlstates': [], 'source_frames': []})
        for key, values in incoming.items():
            existing[key] = (existing.get(key, []) + [value for value in values if value not in existing.get(key, [])])[:12]


    def exception_diagnostic(self, error):
        if isinstance(error, QualificationFailure):
            category = error.category.value
        elif isinstance(error, urllib.error.HTTPError):
            category = FailureCategory.HTTP_STATUS_UNEXPECTED.value
        elif isinstance(error, (urllib.error.URLError, TimeoutError, ConnectionError)):
            category = FailureCategory.HTTP_TRANSPORT.value
        elif isinstance(error, (KeyError, IndexError, ValueError, TypeError)):
            category = FailureCategory.METADATA_INVALID.value
        else:
            category = FailureCategory.UNEXPECTED_EXCEPTION.value
        frames = [{'file': 'tooling/support_retained_qualification.py', 'function': frame.name, 'line': frame.lineno}
                  for frame in traceback.extract_tb(error.__traceback__)
                  if Path(frame.filename).resolve() == Path(__file__).resolve() and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', frame.name)]
        result = {'category': category, 'python_frames': frames[-8:]}
        if isinstance(error, urllib.error.HTTPError):
            result['http_status'] = int(error.code) if 100 <= error.code <= 599 else 0
        return result

    def process_diagnostic(self, container):
        state = self.owned('container', container).get('State', {})
        status = state.get('Status')
        code = state.get('ExitCode')
        return {'status': status if status in {'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'} else 'UNKNOWN',
                'running': state.get('Running') is True, 'oom_killed': state.get('OOMKilled') is True,
                'exit_code': code if isinstance(code, int) and not isinstance(code, bool) else None}

    def topology(self, require_server=False):
        network = self.owned('network', self.network)
        expected = {self.db, self.server} if require_server else {self.db}
        peers = {value.get('Name') for value in network.get('Containers', {}).values()}
        if network.get('Internal') is not True or peers != expected:
            raise QualificationFailure(FailureCategory.TOPOLOGY_INVALID)
        for name in expected:
            metadata = self.owned('container', name)
            if set(metadata.get('NetworkSettings', {}).get('Networks', {})) != {self.network}:
                raise QualificationFailure(FailureCategory.TOPOLOGY_INVALID)
            if metadata.get('HostConfig', {}).get('PortBindings') or any(metadata.get('NetworkSettings', {}).get('Ports', {}).values()):
                raise QualificationFailure(FailureCategory.TOPOLOGY_INVALID)
        return network

    def metadata(self, kind, name):
        try:
            value = json.loads(self.docker(kind, 'inspect', name))[0]
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, TypeError, IndexError):
            raise QualificationFailure(FailureCategory.METADATA_INVALID) from None

    def owned(self, kind, name):
        allowed = {'container': {self.db, self.server, self.prefix + '-production-inspect'}, 'network': {self.network}}
        if name not in allowed.get(kind, set()):
            raise QualificationFailure(FailureCategory.OWNERSHIP_INVALID)
        value = self.metadata(kind, name)
        labels = value.get('Config', {}).get('Labels', {}) if kind == 'container' else value.get('Labels', {})
        if labels.get(LABEL) != self.run:
            raise QualificationFailure(FailureCategory.OWNERSHIP_INVALID)
        return value

    def private(self, name, data):
        target = self.directory / name
        with target.open('xb') as stream:
            os.chmod(target, 0o600)
            stream.write(data)
        return target

    def sql(self, statement):
        self.topology(require_server=self.server_running)
        return self.docker('exec', '-i', self.db, 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose',
                           '-U', 'support_fixture', '-d', 'support_fixture', input=statement.encode(), timeout=30).decode().strip()

    def wait(self, probe, seconds=100):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if probe():
                    return
            except Exception as error:
                self.receipt['last_probe'] = self.exception_diagnostic(error)
            time.sleep(1)
        raise QualificationFailure(FailureCategory.READINESS_TIMEOUT)

    def call(self, operation):
        metadata = self.owned('container', self.server)
        self.topology(require_server=True)
        if metadata['HostConfig'].get('PortBindings'):
            raise QualificationFailure(FailureCategory.TOPOLOGY_INVALID)
        address = ipaddress.ip_address(metadata['NetworkSettings']['Networks'][self.network]['IPAddress'])
        if address.version != 4 or not address.is_private or address.is_loopback:
            raise RuntimeError('Private owned bridge required')
        request = urllib.request.Request('http://' + str(address) + ':8080/realms/master/support-qualification/' + operation,
                                         data=b'', headers={'X-Fixture-Secret': self.secret}, method='POST')
        try:
            with self.http.open(request, timeout=80) as response:
                data = json.loads(response.read(8192))
        except urllib.error.HTTPError as error:
            raw = error.read(16384)
            self.failure(raw)
            try:
                failed = json.loads(raw)
                # Java supplies fixed stage identifiers and actual source frames only.
                if isinstance(failed.get('stage'), str) and re.fullmatch('[A-Z_]{1,80}', failed['stage']):
                    self.receipt['native_invariant'] = failed['stage']
                states = failed.get('sqlstates', [])
                self.receipt['diagnostics']['sqlstates'] = [value for value in states if value in {'FQ001', '23505', '23502', '23514', '42501', '42P01', '42703', '42601', '55P03', '57014'}][:8]
                frames = failed.get('source_frames', [])
                self.receipt['diagnostics']['source_frames'] = [value for value in frames if isinstance(value, str) and re.fullmatch(r'io\.firefly\.id\.nativeauth\.(?:Native|SupportQualification)[A-Za-z0-9_$]+\.[A-Za-z0-9_$<>]+\((?:Native|SupportQualification)[A-Za-z0-9_$]+\.java:[0-9]+\)', value)][:8]
            except (ValueError, TypeError, AttributeError):
                pass
            raise RuntimeError('Native scenario invariant failed') from None
        if data.get('result') != 'passed':
            raise RuntimeError('Native scenario invariant failed')
        # Only fixed keys and bounded primitive values can reach the public receipt.
        safe = {key: value for key, value in data.items() if key in {
            'result', 'scenario', 'observed_lock_waiters', 'committed_consumptions', 'simultaneous_committed_reservations', 'fourth_refused', 'audit_trigger_sqlstate', 'original_proof_and_counters_preserved'}}
        self.receipt['scenarios'][operation] = safe

    def build(self, image, context, containerfile):
        path = self.directory / (image.split(':')[-1] + '.build.log')
        with path.open('xb') as log:
            os.chmod(path, 0o600)
            result = subprocess.run(['docker', '--context', 'default', 'build', '--file', str(containerfile), '--tag', image, str(context)],
                                    stdout=log, stderr=subprocess.STDOUT, timeout=360)
        if result.returncode:
            self.failure(path.read_bytes())
            raise QualificationFailure(FailureCategory.IMAGE_BUILD_FAILED)

    def fixture_image(self, phase, native):
        context = self.directory / phase
        context.mkdir()
        shutil.copyfile(native, context / 'native.jar')
        shutil.copyfile(ROOT / 'qualification/support-retained/target/support-retained-fixture-26.10.1-SNAPSHOT.jar', context / 'fixture.jar')
        image = json.loads((ROOT / 'deploy/images.lock.json').read_text())['keycloak']['image']
        containerfile = context / 'Containerfile'
        containerfile.write_text('FROM ' + image + '\nENV KC_DB=postgres KC_HEALTH_ENABLED=true\n'
                                 'COPY --chown=keycloak:keycloak native.jar /opt/keycloak/providers/native.jar\n'
                                 'COPY --chown=keycloak:keycloak fixture.jar /opt/keycloak/providers/fixture.jar\n'
                                 'RUN /opt/keycloak/bin/kc.sh build\nENTRYPOINT ["/opt/keycloak/bin/kc.sh"]\n'
                                 'CMD ["start", "--optimized", "--verbose"]\n')
        tag = self.prefix + ':' + phase
        self.build(tag, context, containerfile)
        return tag

    def boot(self, image, phase):
        self.receipt['boot_phase'] = phase
        self.receipt['readiness'] = {'http_status': None, 'healthy': False}
        self.receipt.pop('last_probe', None)
        self.receipt['boundary'] = 'BOOT_TOPOLOGY_BEFORE_START'
        self.topology(require_server=False)
        self.receipt['boundary'] = 'BOOT_ENVIRONMENT_WRITE'
        environment = self.private(phase + '.env', ('KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://' + self.db + ':5432/support_fixture\n'
            'KC_DB_USERNAME=support_fixture\nKC_DB_PASSWORD=' + self.password + '\nKC_HTTP_ENABLED=true\nKC_HOSTNAME=http://localhost\n'
            'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m\nFIREFLY_SUPPORT_QUALIFICATION=owned-github-hosted-only\n'
            'FIREFLY_SUPPORT_QUALIFICATION_RUN=' + self.run + '\nFIREFLY_SUPPORT_QUALIFICATION_SECRET=' + self.secret + '\n'
            'FIREFLY_SUPPORT_QUALIFICATION_PHASE=' + phase + '\nFIREFLY_SUPPORT_PIN_ACTIVE_KEY=fixture\nFIREFLY_SUPPORT_PIN_KEYS_DIR=/fixture-keys\n').encode())
        self.receipt['boundary'] = 'BOOT_CONTAINER_START'
        self.docker('run', '--detach', '--name', self.server, '--hostname', self.server, '--label', LABEL + '=' + self.run,
                    '--network', self.network, '--env-file', str(environment), '--volume', str(self.directory / 'keys') + ':/fixture-keys:ro', image, timeout=60)
        self.server_running = True
        self.receipt['boundary'] = 'BOOT_TOPOLOGY_AFTER_START'
        self.topology(require_server=True)
        def ready():
            metadata = self.owned('container', self.server)
            address = metadata['NetworkSettings']['Networks'][self.network]['IPAddress']
            try:
                with self.http.open('http://' + address + ':9000/health/ready', timeout=2) as response:
                    status = int(response.status)
                    healthy = json.loads(response.read(16384)).get('status') == 'UP'
                    self.receipt['readiness'] = {'http_status': status, 'healthy': healthy}
                    return healthy
            except urllib.error.HTTPError as error:
                self.receipt['readiness'] = {'http_status': int(error.code), 'healthy': False}
                raise
        self.receipt['boundary'] = 'BOOT_READINESS'
        self.wait(ready, 120)
        self.receipt['boundary'] = 'BOOT_DATABASE_IDENTITY'
        self.check_database_identity()

    def check_database_identity(self):
        metadata = self.owned('container', self.db)
        identity = (metadata['Id'], [(mount['Destination'], mount.get('Name'), mount.get('Source'))
                                     for mount in metadata.get('Mounts', [])])
        if self.database_identity is None:
            self.database_identity = identity
        elif self.database_identity != identity:
            raise QualificationFailure(FailureCategory.DATABASE_IDENTITY_CHANGED)

    def reject_unauthorized_routes(self):
        metadata = self.owned('container', self.server)
        address = metadata['NetworkSettings']['Networks'][self.network]['IPAddress']
        for probe, realm, secret in [('MISSING_SECRET', 'master', None), ('WRONG_SECRET', 'master', 'incorrect-fixture-secret'),
                                     ('WRONG_REALM', 'support-retained-fixture', self.secret)]:
            self.receipt['boundary'] = 'ROUTE_PROBE_' + probe
            headers = {} if secret is None else {'X-Fixture-Secret': secret}
            request = urllib.request.Request('http://' + address + ':8080/realms/' + realm + '/support-qualification/admission',
                                             data=b'', headers=headers, method='POST')
            try:
                response = self.http.open(request, timeout=5)
                status = int(getattr(response, 'status', 200))
                response.close()
                self.receipt['route_probe'] = {'probe': probe, 'status': status}
            except urllib.error.HTTPError as failure:
                self.receipt['route_probe'] = {'probe': probe, 'status': int(failure.code)}
                if failure.code == 404:
                    continue
            raise QualificationFailure(FailureCategory.HTTP_STATUS_UNEXPECTED)
        self.receipt['route_admission'] = {'missing_secret_refused': True, 'wrong_secret_refused': True, 'other_realm_refused': True}

    def stop_server(self):
        self.topology(require_server=True)
        self.owned('container', self.server)
        self.docker('stop', '--time', '20', self.server, timeout=30)
        self.docker('container', 'rm', self.server)
        self.server_running = False

    def snapshot(self, initial=False, read=None):
        read = read or self.sql
        result = {}
        for table in TABLES:
            if initial:
                self.columns[table] = read("SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) FROM pg_attribute "
                                              "WHERE attrelid='" + table + "'::regclass AND attnum>0 AND NOT attisdropped;")
            columns = self.columns[table]
            where = " WHERE realm_id='support-retained-fixture'" if table in {'user_entity', 'credential'} else ''
            if table == 'credential':
                where = " WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id='support-retained-fixture')"
            if table == 'user_attribute':
                where = " WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id='support-retained-fixture')"
            # Before scenario execution every native row is a retained original row.
            result[table] = read('SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),\'[]\'::jsonb)::text FROM (SELECT ' + columns + ' FROM ' + table + where + ') t;')
            if result[table] == '[]':
                raise RuntimeError('Retained fixture table unexpectedly empty')
        return result

    def history(self, read=None):
        raw = (read or self.sql)("SELECT COALESCE(jsonb_agg(jsonb_build_array(id,author,filename,md5sum) ORDER BY orderexecuted),'[]'::jsonb)::text FROM " + HISTORY_TABLE + " WHERE id<>'firefly-native-support-evidence-2';")
        rows = json.loads(raw)
        if (not isinstance(rows, list) or len(rows) != 9 or [row[0] for row in rows] != list(HISTORICAL_IDS)
                or any(len(row) != 4 or row[1] != 'firefly-id' or row[2] != MIGRATION
                       or not isinstance(row[3], str) or not re.fullmatch(r'[0-9]+:[0-9a-f]{32}', row[3]) for row in rows)):
            raise QualificationFailure(FailureCategory.LIQUIBASE_HISTORY_CHANGED)
        return raw

    def schema_failure_diagnostic(self):
        if not self.retained or not getattr(self, 'old_history', None):
            return {'available': False, 'reason': 'NO_RETAINED_BASELINE'}
        # Diagnostic SELECTs remain safe when the failed identity process is no longer a network peer.
        network = self.owned('network', self.network)
        peers = {peer.get('Name') for peer in network.get('Containers', {}).values()}
        database = self.owned('container', self.db)
        if (network.get('Internal') is not True or self.db not in peers or not peers <= {self.db, self.server}
                or set(database.get('NetworkSettings', {}).get('Networks', {})) != {self.network}
                or database.get('HostConfig', {}).get('PortBindings')
                or any(database.get('NetworkSettings', {}).get('Ports', {}).values())):
            raise QualificationFailure(FailureCategory.TOPOLOGY_INVALID)
        for peer in peers:
            self.owned('container', peer)
        def read(statement):
            if not statement.startswith('SELECT '):
                raise QualificationFailure(FailureCategory.METADATA_INVALID)
            return self.docker('exec', '-i', self.db, 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                               '-v', 'VERBOSITY=verbose', '-U', 'support_fixture', '-d', 'support_fixture',
                               input=statement.encode(), timeout=20).decode().strip()
        result = {'available': True,
                  'additive_changeset_rows': int(read("SELECT count(*) FROM " + HISTORY_TABLE + " WHERE id='firefly-native-support-evidence-2';")),
                  'nonce_constraint_rows': int(read("SELECT count(*) FROM pg_constraint WHERE conname='ff_native_support_nonce_once';")),
                  'binding_column_rows': int(read("SELECT count(*) FROM information_schema.columns WHERE table_name='ff_native_support_proof' AND column_name IN ('nonce_digest','target_issuer','pin_credential_id','pin_key_version','staff_issuer','staff_subject','case_id','call_id','tenant','customer_link','permitted_action','purpose','reserved_at','status','consumed_at');"))}
        try:
            result['prior_history_unchanged'] = self.history(read=read) == self.old_history
        except QualificationFailure as error:
            if error.category != FailureCategory.LIQUIBASE_HISTORY_CHANGED:
                raise
            result['prior_history_unchanged'] = False
        original = self.snapshot(read=read)
        result['original_tables_unchanged'] = {table: original[table] == self.retained[table] for table in TABLES}
        return result

    def prepare_retained(self):
        self.call('setup')
        # Only historical column contracts. No table replacement, checksum edits, reset, truncate or deletion.
        self.sql("""INSERT INTO ff_native_audit (id,realm_id,subject,event_type,reference_id,occurred_at) VALUES ('retained-audit','support-retained-fixture','historical-user','RETAINED_SYNTHETIC','retained-reference',123);
INSERT INTO ff_native_ceremony (id,realm_id,subject,csrf_digest,expires_at,stage,generation,binding_json,owner_link,operation_id,failed) VALUES ('retained-ceremony','support-retained-fixture','historical-user','retained-digest',123,'FAILED','retained-generation','{}','retained-owner','retained-operation',true);
INSERT INTO ff_native_attestation (id,realm_id,subject,generation,ceremony_id,operation_id,reservation_id,category,expires_at,verified,completed) VALUES ('retained-attestation','support-retained-fixture','historical-user','retained-generation','retained-ceremony','retained-operation','retained-reservation','POSSESSION',123,false,false);
INSERT INTO ff_native_execution (id,realm_id,subject,generation,operation_id,binding_digest,outcome,completed_at,ceremony_id,binding_json,authorization_expires_at,record_attempts,recorded) VALUES ('retained-execution','support-retained-fixture','historical-user','retained-generation','retained-operation','retained-digest','UNKNOWN',0,'retained-ceremony','{}','1970-01-01T00:00:00Z',1,false);
INSERT INTO ff_native_issued_challenge (id,ceremony_id,operation_id,reservation_id,category,credential_id,expires_at) VALUES ('retained-challenge','retained-ceremony','retained-operation','retained-challenge-reservation','POSSESSION','retained-credential',123);
INSERT INTO ff_native_totp_replay (id,expires_at) VALUES ('retained-replay',123);""")
        if self.sql("SELECT count(*) FROM information_schema.columns WHERE table_name='ff_native_support_proof' AND column_name='nonce_digest';") != '0':
            raise RuntimeError('Historical baseline already contains additive binding')
        if self.sql("SELECT count(*) FROM databasechangelog_firefly_na WHERE id='firefly-native-support-evidence-2';") != '0':
            raise RuntimeError('Historical baseline already contains additive migration')
        if self.sql("SELECT count(*) FROM pg_constraint WHERE conname='ff_native_support_nonce_once';") != '0':
            raise RuntimeError('Historical baseline already contains nonce fence')
        self.retained = self.snapshot(initial=True)
        self.receipt['historical_tables'] = {table: {'rows': len(json.loads(value)),
            'original_columns': len(self.columns[table].split(','))} for table, value in self.retained.items()}
        self.old_history = self.history()

    def production_inventory(self):
        # Inspect every installed provider in the ordinary distributable image, not just expected input JARs.
        image = self.prefix + ':production'
        self.build(image, ROOT, ROOT / 'deploy/Containerfile.native')
        container = self.prefix + '-production-inspect'
        self.docker('create', '--name', container, '--label', LABEL + '=' + self.run, image)
        self.owned('container', container)
        target = self.directory / 'production-providers'
        self.docker('cp', container + ':/opt/keycloak/providers', str(target))
        count = 0
        for path in target.rglob('*'):
            if path.is_file() and path.suffix == '.jar':
                count += 1
                with zipfile.ZipFile(path) as jar:
                    if any('SupportQualification' in name or 'support-retained-fixture' in name
                           or name == 'META-INF/services/io.firefly.id.nativeauth.NativeSupportAuthorization$Factory' for name in jar.namelist()):
                        raise RuntimeError('Qualification adapter present in production image')
        if count != 3:
            raise RuntimeError('Unexpected production provider inventory')
        self.receipt['production_provider_inventory'] = {'provider_jars': count, 'qualification_adapter_absent': True}
        self.docker('container', 'rm', container)

    def run_all(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        os.chmod(self.directory, 0o700)
        self.receipt['source_revision'] = self.command(['git', 'rev-parse', 'HEAD']).decode().strip()
        current = ROOT / 'extensions/native-recovery/target/firefly-id-native-recovery-26.10.1-SNAPSHOT.jar'
        historical = self.directory / 'historical.jar'
        self.receipt['migration_provenance'] = historical_jar(current, historical)
        self.receipt['phase'] = 'PRODUCTION_INVENTORY'
        self.production_inventory()
        historical_image = self.fixture_image('historical', historical)
        current_image = self.fixture_image('current', current)
        self.receipt['phase'] = 'OWNED_DATABASE'
        self.docker('network', 'create', '--internal', '--label', LABEL + '=' + self.run, self.network)
        if self.owned('network', self.network).get('Internal') is not True:
            raise RuntimeError('Owned internal network required')
        self.password = secrets.token_urlsafe(36)
        environment = self.private('postgres.env', ('POSTGRES_DB=support_fixture\nPOSTGRES_USER=support_fixture\nPOSTGRES_PASSWORD=' + self.password + '\n').encode())
        postgres = json.loads((ROOT / 'deploy/images.lock.json').read_text())['postgres']['image']
        # No tmpfs, teardown, volume replacement or deletion: failed retained state survives until runner disposal.
        self.docker('run', '--detach', '--name', self.db, '--label', LABEL + '=' + self.run, '--network', self.network,
                    '--env-file', str(environment), postgres, timeout=90)
        self.wait(lambda: self.sql('SELECT 1;') == '1')
        keys = self.directory / 'keys'; keys.mkdir(mode=0o700)
        os.chmod(keys, 0o755)
        key = keys / 'fixture'; key.write_bytes(secrets.token_bytes(48)); os.chmod(key, 0o600)
        # Keycloak image runs as UID 1000; the protected pepper is readable only by that owner.
        self.command(['sudo', 'chown', '1000:0', str(key)])
        self.receipt['phase'] = 'HISTORICAL_STARTUP'
        self.boot(historical_image, 'historical')
        self.prepare_retained()
        self.stop_server()
        self.receipt['phase'] = 'ADDITIVE_MIGRATION'
        self.boot(current_image, 'current')
        self.reject_unauthorized_routes()
        self.receipt['boundary'] = 'MIGRATION_COMPARE_ORIGINAL_VALUES'
        migrated = self.snapshot()
        if migrated != self.retained:
            self.receipt['changed_tables'] = [table for table in TABLES if migrated[table] != self.retained[table]]
            raise QualificationFailure(FailureCategory.RETAINED_VALUES_CHANGED)
        self.receipt['boundary'] = 'MIGRATION_COMPARE_LIQUIBASE_HISTORY'
        if self.history() != self.old_history:
            raise QualificationFailure(FailureCategory.LIQUIBASE_HISTORY_CHANGED)
        self.receipt['boundary'] = 'MIGRATION_CHECK_ADDITIVE_CHANGESET'
        if self.sql("SELECT count(*) FROM databasechangelog_firefly_na WHERE id='firefly-native-support-evidence-2';") != '1':
            raise QualificationFailure(FailureCategory.MIGRATION_NOT_APPLIED)
        self.receipt['boundary'] = 'MIGRATION_CHECK_NONCE_CONSTRAINT'
        if self.sql("SELECT count(*) FROM pg_constraint WHERE conname='ff_native_support_nonce_once';") != '1':
            raise QualificationFailure(FailureCategory.NONCE_FENCE_NOT_INSTALLED)
        self.receipt['boundary'] = 'MIGRATION_RETAINED_AUDIT_APPEND_ONLY'
        self.sql("DO $$ BEGIN BEGIN UPDATE ff_native_audit SET event_type='REWRITE' WHERE id='retained-audit'; RAISE EXCEPTION 'Audit update unexpectedly admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; BEGIN DELETE FROM ff_native_audit WHERE id='retained-audit'; RAISE EXCEPTION 'Audit deletion unexpectedly admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;")
        self.receipt['migration'] = {'original_tables_preserved': len(TABLES), 'historical_checksums_preserved': True,
                                     'additive_changeset_applied_once': True, 'original_columns_preserved': True,
                                     'nonce_constraint_added_once': True, 'retained_audit_append_only': True}
        self.receipt['phase'] = 'NATIVE_SCENARIOS'
        for operation in ('admission', 'legacy', 'nonce', 'budget', 'interrupted', 'consume', 'audit', 'generation', 'hold', 'lost'):
            self.receipt['phase'] = operation.upper()
            self.call(operation)
        # Preserve exact all-row state through real process restart, including uncertain/reserved/failed records.
        restart_columns = dict(self.columns)
        before_restart = self.snapshot(initial=True)
        self.stop_server()
        self.receipt['phase'] = 'RESTART'
        self.boot(current_image, 'restart')
        if self.snapshot() != before_restart:
            raise RuntimeError('Same retained records changed across restart')
        self.columns = restart_columns
        self.call('reconcile')
        self.receipt.update(result='passed', phase='COMPLETE', retained_database_preserved=True,
                            restart_all_columns_preserved=True, same_database_storage_identity=True, no_counters_reset=True, no_replacement_grants=True)


def main():
    run = admit()
    fixture = Fixture(run)
    try:
        fixture.run_all()
    except Exception as error:
        fixture.receipt['python_failure'] = fixture.exception_diagnostic(error)
        fixture.receipt['failure_category'] = fixture.receipt['python_failure']['category']
        fixture.failure(traceback.format_exc())
        for container in (fixture.server, fixture.db):
            try:
                role = 'identity' if container == fixture.server else 'database'
                fixture.receipt.setdefault('process_states', {})[role] = fixture.process_diagnostic(container)
                fixture.failure(fixture.docker('logs', '--tail', '240', container, include_stderr=True))
            except Exception as diagnostic_error:
                fixture.receipt.setdefault('process_states', {})[role] = {
                    'metadata_available': False, 'diagnostic': fixture.exception_diagnostic(diagnostic_error)}
        try:
            fixture.receipt['schema_after_failure'] = fixture.schema_failure_diagnostic()
        except Exception as diagnostic_error:
            fixture.receipt['schema_after_failure'] = {'available': False, 'diagnostic': fixture.exception_diagnostic(diagnostic_error)}
        fixture.receipt['failed_state_retained_on_runner'] = True
    finally:
        # Never upload env files, SQL snapshots, raw logs, credentials, keys or Docker metadata.
        if fixture.directory.is_dir():
            (fixture.directory / 'summary.json').write_text(json.dumps(fixture.receipt, indent=2) + '\n')
    print(json.dumps(fixture.receipt))
    if fixture.receipt['result'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
