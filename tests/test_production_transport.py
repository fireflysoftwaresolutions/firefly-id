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

    def test_published_ports_must_be_one_loopback_binding(self):
        self.assertEqual(32123, self.transport.loopback_port('127.0.0.1:32123\n'))
        for value in ('0.0.0.0:32123', '[::]:32123', '127.0.0.1:0',
                      '127.0.0.1:99999', '127.0.0.1:32123\n127.0.0.1:32124'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.transport.loopback_port(value)

    def test_plaintext_health_cannot_pass_as_tls_only(self):
        self.assertTrue(self.transport.plaintext_refused(b''))
        self.assertTrue(self.transport.plaintext_refused(b'HTTP/1.1 400 Bad Request\r\n\r\nTLS required'))
        for body in (b'HTTP/1.1 200 OK\r\n\r\n{"status":"UP"}',
                     b'HTTP/1.1 503 Service Unavailable\r\n\r\n{"status":"DOWN"}',
                     b'HTTP/1.1 301 Moved Permanently\r\n', b'unknown bytes'):
            with self.subTest(body=body):
                self.assertFalse(self.transport.plaintext_refused(body))


if __name__ == '__main__':
    unittest.main()
