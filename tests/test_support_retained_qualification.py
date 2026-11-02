"""Offline admission/provenance tests; native scenario acceptance requires hosted execution."""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tooling/support_retained_qualification.py'


class SupportRetainedQualificationTest(unittest.TestCase):
    def fixture(self):
        self.assertTrue(SCRIPT.exists(), 'Owned retained fixture orchestration is not implemented')
        spec = importlib.util.spec_from_file_location('support_retained', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_nonhosted_admission_has_no_process_side_effects(self):
        fixture = self.fixture()
        for env in ({}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted', 'RUNNER_OS': 'Linux'}):
            with patch.dict(os.environ, env, clear=True), patch.object(fixture.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    fixture.admit()
                run.assert_not_called()

    def test_admission_uses_only_numeric_owned_run_and_no_external_target(self):
        fixture = self.fixture()
        env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
               'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2'}
        with patch.dict(os.environ, env, clear=True), patch.object(fixture.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'"unix:///var/run/docker.sock"', stderr=b'')):
            self.assertEqual('17-2', fixture.admit())
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '../production'}):
                with self.assertRaises(RuntimeError):
                    fixture.admit()

    def test_historical_jar_preserves_earlier_changesets_and_all_other_entries(self):
        fixture = self.fixture()
        migration = (ROOT / 'extensions/native-recovery/src/main/resources/META-INF/firefly-native-recovery.xml').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            original, historical = (Path(directory) / name for name in ('current.jar', 'historical.jar'))
            with zipfile.ZipFile(original, 'w') as archive:
                archive.writestr('META-INF/firefly-native-recovery.xml', migration)
                archive.writestr('unchanged.bin', b'unchanged native class bytes')
            receipt = fixture.historical_jar(original, historical)
            with zipfile.ZipFile(historical) as archive:
                historical_xml = archive.read('META-INF/firefly-native-recovery.xml')
                self.assertEqual(b'unchanged native class bytes', archive.read('unchanged.bin'))
            ns = '{http://www.liquibase.org/xml/ns/dbchangelog}'
            old = list(ET.fromstring(historical_xml).findall(ns + 'changeSet'))
            current = list(ET.fromstring(migration).findall(ns + 'changeSet'))
            self.assertEqual(9, len(old))
            self.assertEqual([ET.tostring(node) for node in current[:-1]], [ET.tostring(node) for node in old])
            self.assertEqual('firefly-native-support-evidence-2', receipt['excluded_changeset'])
            self.assertEqual(9, receipt['historical_changesets'])

    def test_historical_builder_refuses_overwriting_retained_candidate(self):
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'retained.jar'
            path.write_bytes(b'preserved')
            with self.assertRaises(FileExistsError):
                fixture.historical_jar(path, path)
            self.assertEqual(b'preserved', path.read_bytes())

    def hosted_environment(self):
        return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2'}

    def test_docker_selection_overrides_refuse_before_any_process(self):
        fixture = self.fixture()
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_TLS', 'DOCKER_CERT_PATH'):
            with self.subTest(key=key), patch.dict(os.environ, {**self.hosted_environment(), key: 'external'}, clear=True), \
                    patch.object(fixture.subprocess, 'run') as command:
                with self.assertRaises(RuntimeError):
                    fixture.admit()
                command.assert_not_called()

    def test_nondefault_unix_or_remote_context_refuses_after_read_only_probe(self):
        fixture = self.fixture()
        for endpoint in (b'"tcp://external.invalid:2375"', b'"unix:///tmp/other.sock"', b'bad-json'):
            with self.subTest(endpoint=endpoint), patch.dict(os.environ, self.hosted_environment(), clear=True), \
                    patch.object(fixture.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=endpoint, stderr=b'')) as command:
                with self.assertRaises(RuntimeError):
                    fixture.admit()
                self.assertEqual(['docker', 'context', 'inspect', 'default', '--format', '{{json .Endpoints.docker.Host}}'], command.call_args.args[0])

    def test_topology_refuses_extra_peer_network_or_published_database_port(self):
        fixture = self.fixture()
        self.assertTrue(hasattr(fixture.Fixture, 'topology'), 'Exact owned topology validation is not implemented')
        owned = fixture.Fixture('17-2')
        network = {'Internal': True, 'Containers': {'db': {'Name': owned.db}, 'server': {'Name': owned.server}}}
        def container(name):
            return {'Name': '/' + name, 'NetworkSettings': {'Networks': {owned.network: {}}, 'Ports': {}},
                    'HostConfig': {'PortBindings': {}}}
        for mutation in ('peer', 'network', 'port'):
            import copy
            values = {('network', owned.network): copy.deepcopy(network),
                      ('container', owned.db): container(owned.db), ('container', owned.server): container(owned.server)}
            if mutation == 'peer':
                values['network', owned.network]['Containers']['other'] = {'Name': 'external-peer'}
            elif mutation == 'network':
                values['container', owned.db]['NetworkSettings']['Networks']['external'] = {}
            else:
                values['container', owned.db]['HostConfig']['PortBindings']['5432/tcp'] = [{'HostPort': '5432'}]
            with self.subTest(mutation=mutation), patch.object(owned, 'owned', side_effect=lambda kind, name: values[kind, name]):
                with self.assertRaises(RuntimeError):
                    owned.topology(require_server=True)

    def test_diagnostics_emit_locations_and_known_categories_without_raw_values(self):
        fixture = self.fixture()
        raw = ('[ERROR] /private/SupportQualificationResource.java:[12,3] cannot find symbol secret-never-export\n'
               '[ERROR] /private/Unknown.java:[99,1] token-never-export\n'
               'ERROR:  23505: credential-never-export\n')
        self.assertTrue(hasattr(fixture, 'bounded_diagnostics'), 'Bounded failure diagnostics are not implemented')
        result = fixture.bounded_diagnostics(raw)
        self.assertEqual([{'file': 'SupportQualificationResource.java', 'line': 12, 'column': 3,
                           'category': 'CANNOT_FIND_SYMBOL'}], result['compiler_locations'])
        self.assertEqual(['23505'], result['sqlstates'])
        self.assertNotIn('never-export', str(result))

    def test_known_startup_failures_are_classified_without_messages(self):
        fixture = self.fixture()
        raw = ('liquibase.exception.ValidationFailedException: secret-never-export\n'
               'liquibase checksum was changed password-never-export\n'
               'Failed to start server in production mode token-never-export\n'
               'java.lang.OutOfMemoryError: private-never-export\n')
        diagnostics = fixture.bounded_diagnostics(raw)
        self.assertEqual(['LIQUIBASE_VALIDATION_FAILED', 'LIQUIBASE_CHECKSUM_MISMATCH',
                          'KEYCLOAK_STARTUP_FAILED', 'JAVA_OUT_OF_MEMORY'], diagnostics.get('runtime_categories'))
        self.assertNotIn('never-export', str(diagnostics))

    def test_python_failure_reports_only_own_source_and_fixed_category(self):
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        self.assertTrue(hasattr(owned, 'exception_diagnostic'), 'Bounded Python failure classification is missing')
        with patch.object(owned, 'metadata', return_value={'Config': {'Labels': {}}}):
            try:
                owned.owned('container', owned.db)
            except RuntimeError as error:
                diagnostic = owned.exception_diagnostic(error)
        self.assertEqual('OWNERSHIP_INVALID', diagnostic['category'])
        self.assertTrue(any(row['function'] == 'owned' and row['line'] > 0 for row in diagnostic['python_frames']))
        self.assertEqual({'tooling/support_retained_qualification.py'}, {row['file'] for row in diagnostic['python_frames']})
        self.assertNotIn('/Users/', str(diagnostic))

    def test_route_probe_records_exact_failed_probe_and_http_status(self):
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        response = SimpleNamespace(close=lambda: None)
        with patch.object(owned, 'owned', return_value={'NetworkSettings': {'Networks': {owned.network: {'IPAddress': '172.19.0.2'}}}}), \
                patch.object(owned.http, 'open', return_value=response):
            with self.assertRaises(RuntimeError):
                owned.reject_unauthorized_routes()
        self.assertEqual('ROUTE_PROBE_MISSING_SECRET', owned.receipt.get('boundary'))
        self.assertEqual({'probe': 'MISSING_SECRET', 'status': 200}, owned.receipt.get('route_probe'))

    def test_process_state_never_exports_raw_docker_metadata(self):
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        self.assertTrue(hasattr(owned, 'process_diagnostic'), 'Bounded process state classification is missing')
        metadata = {'State': {'Status': 'exited', 'Running': False, 'OOMKilled': True, 'ExitCode': 137,
                              'Error': 'credential-never-export'}, 'Config': {'Env': ['secret-never-export']}}
        with patch.object(owned, 'owned', return_value=metadata):
            self.assertEqual({'status': 'exited', 'running': False, 'oom_killed': True, 'exit_code': 137},
                             owned.process_diagnostic(owned.server))

    def test_readiness_timeout_preserves_last_probe_error_and_boundary(self):
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        owned.receipt['boundary'] = 'BOOT_READINESS'
        def unavailable():
            raise fixture.urllib.error.URLError('secret-never-export')
        with patch.object(fixture.time, 'monotonic', side_effect=[0, 0, 2]), patch.object(fixture.time, 'sleep'):
            with self.assertRaises(RuntimeError):
                owned.wait(unavailable, seconds=1)
        self.assertEqual('BOOT_READINESS', owned.receipt['boundary'])
        self.assertEqual('HTTP_TRANSPORT', owned.receipt.get('last_probe', {}).get('category'))
        self.assertNotIn('never-export', str(owned.receipt))

    def test_diagnostic_capture_includes_successful_command_stderr(self):
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        result = SimpleNamespace(returncode=0, stdout=b'normal-output', stderr=b'java.lang.NullPointerException: private')
        with patch.object(fixture.subprocess, 'run', return_value=result):
            self.assertTrue('include_stderr' in __import__('inspect').signature(owned.command).parameters,
                            'Successful diagnostic commands discard stderr')
            raw = owned.command(['docker', 'logs', 'fixed-owned-container'], include_stderr=True)
        self.assertIn(b'java.lang.NullPointerException', raw)

    def test_framework_diagnostics_keep_class_and_source_without_exception_message(self):
        fixture = self.fixture()
        raw = ('Caused by: java.lang.NullPointerException: customer-secret-never-export\n'
               '\tat org.keycloak.services.managers.RealmManager.checkRealm(RealmManager.java:123)\n'
               '\tat attacker.Secret.token(Secret.java:123)\n')
        result = fixture.bounded_diagnostics(raw)
        self.assertEqual(['java.lang.NullPointerException'], result.get('exception_classes'))
        self.assertEqual(['org.keycloak.services.managers.RealmManager.checkRealm(RealmManager.java:123)'],
                         result.get('framework_frames'))
        self.assertNotIn('never-export', str(result))
        self.assertNotIn('attacker', str(result))

    def test_failure_schema_probe_requires_original_retained_baseline(self):
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        self.assertTrue(hasattr(owned, 'schema_failure_diagnostic'), 'Read-only structural failure diagnostic is missing')
        with patch.object(owned, 'docker') as command:
            self.assertEqual({'available': False, 'reason': 'NO_RETAINED_BASELINE'}, owned.schema_failure_diagnostic())
            command.assert_not_called()

    def test_native_history_reads_provider_table_and_requires_nine_real_checksums(self):
        import json
        fixture = self.fixture()
        owned = fixture.Fixture('17-2')
        identifiers = ['firefly-native-recovery-1', 'firefly-native-issued-challenge-1', 'firefly-native-support-proof-1',
                       'firefly-native-totp-replay-1', 'firefly-native-audit-append-only-1',
                       'firefly-native-execution-reconciliation-1', 'firefly-native-form-feedback-1',
                       'firefly-native-admin-pin-audit-1', 'firefly-native-admin-pin-audit-check-1']
        rows = [[value, 'firefly-id', 'META-INF/firefly-native-recovery.xml', '9:' + 'a' * 32] for value in identifiers]
        def query(statement):
            return json.dumps(rows) if ' FROM databasechangelog_firefly_na ' in statement else '[]'
        with patch.object(owned, 'sql', side_effect=query):
            self.assertEqual(9, len(json.loads(owned.history())))
        for invalid in ('[]', json.dumps([rows[0]]), json.dumps([row[:3] + [None] for row in rows])):
            with self.subTest(invalid=invalid), patch.object(owned, 'sql', return_value=invalid):
                with self.assertRaises(RuntimeError):
                    owned.history()
