"""Pure transport-evidence classification; never starts a process or service."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProductionTransportTest(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'tooling/production_transport.py'
        if not path.is_file():
            self.fail('Hosted production transport lane is not implemented')
        spec = importlib.util.spec_from_file_location('production_transport', path)
        self.transport = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.transport)

    def test_reference_drift_cannot_silently_weaken_live_scenarios(self):
        content = (ROOT / 'deploy/keycloak.production.conf.example').read_text()
        self.transport.validate_reference(content)
        for old, new in [('db-tls-mode=verify-server', 'db-tls-mode=required'),
                         ('http-enabled=false', 'http-enabled=true'),
                         ('http-management-scheme=inherited', 'http-management-scheme=http'),
                         ('legacy-observability-interface=false', 'legacy-observability-interface=true')]:
            with self.subTest(option=old), self.assertRaises(ValueError):
                self.transport.validate_reference(content.replace(old, new))
        with self.assertRaises(ValueError):
            self.transport.validate_reference(content + '\nhttp-enabled=true\n')

    def test_ready_requires_actual_database_check_and_all_checks_up(self):
        good = {'status': 'UP', 'checks': [
            {'name': 'Keycloak Initialized', 'status': 'UP'},
            {'name': 'Keycloak database connections async health check', 'status': 'UP'}]}
        self.assertTrue(self.transport.database_ready(json.dumps(good).encode()))
        for payload in ({'status': 'UP', 'checks': []},
                        {'status': 'UP', 'checks': [{'name': 'database', 'status': 'DOWN'}]},
                        {'status': 'UP', 'checks': [{'name': 'database', 'status': 'UP'},
                                                  {'name': 'initialized', 'status': 'DOWN'}]},
                        {'status': 'DOWN', 'checks': good['checks']}, [], None):
            with self.subTest(payload=payload):
                self.assertFalse(self.transport.database_ready(json.dumps(payload).encode()))
        self.assertFalse(self.transport.database_ready(b'not-json'))

    def test_wrong_host_and_untrusted_ca_need_distinct_tls_causes(self):
        host = 'The hostname wrong.production-transport.test could not be verified by hostnameverifier org.postgresql.ssl.PGjdbcHostnameVerifier.'
        ca = 'SSL error: PKIX path building failed: unable to find valid certification path to requested target'
        self.assertEqual('DATABASE_HOSTNAME_REFUSED', self.transport.tls_failure_kind(host))
        self.assertEqual('DATABASE_CA_REFUSED', self.transport.tls_failure_kind(ca))
        for message in ('Connection refused', 'Connection acquisition timed out', 'Unknown database',
                        'Failed to start server', host + '\n' + ca):
            with self.subTest(message=message):
                self.assertIsNone(self.transport.tls_failure_kind(message))

    def test_host_probes_require_the_actual_owned_internal_network_endpoint(self):
        import copy
        owner = 'a' * 32
        name = 'firefly-transport-' + owner
        network = {'Name': name, 'Id': 'b' * 64, 'Internal': True,
                   'Labels': {self.transport.OWNER_LABEL: owner},
                   'IPAM': {'Config': [{'Subnet': '172.24.0.0/16'}]}}
        attached = {name: {'NetworkID': network['Id'], 'IPAddress': '172.24.0.2', 'IPPrefixLen': 16}}
        self.assertEqual(('172.24.0.2', 9000),
                         self.transport.owned_endpoint(network, attached, name, owner, 9000))
        invalid = []
        for key, value in [('Internal', False), ('Name', 'unowned'), ('Labels', {}),
                           ('IPAM', {'Config': [{'Subnet': '8.8.8.0/24'}]})]:
            candidate = copy.deepcopy(network); candidate[key] = value
            invalid.append((candidate, attached, 9000))
        for key, value in [('IPAddress', '8.8.8.8'), ('IPAddress', '172.25.0.2'),
                           ('IPAddress', 'localhost'), ('IPAddress', '172.24.0.0'),
                           ('IPAddress', '172.24.255.255'), ('NetworkID', 'c' * 64), ('IPPrefixLen', 24)]:
            candidate = copy.deepcopy(attached); candidate[name][key] = value
            invalid.append((network, candidate, 9000))
        invalid.append((network, attached, 80))
        for candidate_network, candidate_attached, port in invalid:
            with self.subTest(network=candidate_network, attached=candidate_attached, port=port), self.assertRaises(ValueError):
                self.transport.owned_endpoint(candidate_network, candidate_attached, name, owner, port)

    def test_plaintext_health_cannot_pass_as_tls_only(self):
        self.assertTrue(self.transport.plaintext_refused(b''))
        self.assertTrue(self.transport.plaintext_refused(b'HTTP/1.1 400 Bad Request\r\n\r\nTLS required'))
        for body in (b'HTTP/1.1 200 OK\r\n\r\n{"status":"UP"}',
                     b'HTTP/1.1 503 Service Unavailable\r\n\r\n{"status":"DOWN"}',
                     b'HTTP/1.1 301 Moved Permanently\r\n', b'unknown bytes'):
            with self.subTest(body=body):
                self.assertFalse(self.transport.plaintext_refused(body))

    def test_startup_diagnostics_use_fixed_categories_without_raw_inputs(self):
        sentinel = 'PRIVATE-PASSWORD-AND-PATH'
        cases = {
            'failed to create task for container: OCI runtime create failed ' + sentinel: 'DOCKER_TASK_CREATE',
            'failed to set up container networking: iptables ' + sentinel: 'DOCKER_NETWORK',
            'invalid mount config for type bind: ' + sentinel: 'DOCKER_MOUNT',
            'failed to initialize logging driver: ' + sentinel: 'DOCKER_LOGGING',
            'FATAL: private key file "' + sentinel + '" has group or world access': 'POSTGRES_KEY_PERMISSIONS',
            'FATAL: could not load private key file "' + sentinel + '": Permission denied': 'POSTGRES_KEY_LOAD',
            'FATAL: could not load server certificate file "' + sentinel + '"': 'POSTGRES_CERTIFICATE_LOAD',
            'FATAL: could not load pg_hba.conf ' + sentinel: 'POSTGRES_HBA',
            'initdb: error: directory ' + sentinel: 'POSTGRES_INITIALIZATION',
            'FATAL: password authentication failed for user ' + sentinel: 'POSTGRES_AUTHENTICATION',
            'database system is ready to accept connections ' + sentinel: 'POSTGRES_READY',
            'no space left on device ' + sentinel: 'RUNNER_STORAGE',
        }
        for message, expected in cases.items():
            with self.subTest(category=expected):
                categories = self.transport.startup_categories(message)
                self.assertIn(expected, categories)
                self.assertNotIn(sentinel, json.dumps(categories))
        self.assertEqual(['UNCLASSIFIED'], self.transport.startup_categories(sentinel))

    def test_container_diagnostic_preserves_exit_and_oom_without_raw_state_error(self):
        state = {'Status': 'exited', 'Running': False, 'ExitCode': 137, 'OOMKilled': True,
                 'Error': 'PRIVATE-INPUT failed to create task for container',
                 'StartedAt': 'PRIVATE-TIMESTAMP'}
        result = self.transport.container_diagnostic(state, b'PRIVATE-LOG could not load pg_hba.conf')
        self.assertEqual('exited', result['status'])
        self.assertEqual(137, result['exit_code'])
        self.assertTrue(result['out_of_memory'])
        self.assertFalse(result['running'])
        self.assertIn('DOCKER_TASK_CREATE', result['categories'])
        self.assertIn('POSTGRES_HBA', result['categories'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        unknown = self.transport.container_diagnostic({'Status': 'PRIVATE', 'ExitCode': 'PRIVATE'}, b'')
        self.assertEqual('UNKNOWN', unknown['status'])
        self.assertIsNone(unknown['exit_code'])


if __name__ == '__main__':
    unittest.main()
