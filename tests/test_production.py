"""Candidate audit refusals; no identity service, database or provider runs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProductionAuditTest(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'scripts/check_production.py'
        if not path.exists():
            self.fail('Read-only production candidate audit is not implemented')
        spec = importlib.util.spec_from_file_location('production_audit', path)
        self.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.audit)
        self.catalogue = json.loads((ROOT / 'config/authentication-policies.json').read_text())
        self.server = {
            'db': 'postgres', 'db-url': 'jdbc:postgresql://db.example.net:5432/identity',
            'db-username': 'identity_service', 'db-tls-mode': 'verify-server',
            'db-tls-trust-store-file': '/run/secrets/database-ca.pem',
            'hostname': 'https://id.example.net', 'hostname-admin': 'https://admin.example.net',
            'hostname-strict': 'true', 'hostname-backchannel-dynamic': 'false',
            'http-enabled': 'false', 'http-management-scheme': 'inherited',
            'https-certificate-file': '/run/secrets/tls.crt',
            'https-certificate-key-file': '/run/secrets/tls.key',
            'https-protocols': 'TLSv1.3,TLSv1.2', 'tls-hostname-verifier': 'DEFAULT',
            'proxy-headers': 'xforwarded', 'proxy-trusted-addresses': '10.24.0.0/24',
            'legacy-observability-interface': 'false',
        }
        self.realms = {}
        for profile in ('customers', 'workforce', 'administrators'):
            settings = self.catalogue['profiles'][profile]['realmSettings']
            self.realms[profile] = dict(self.catalogue['defaults'], **settings,
                realm='master' if profile == 'administrators' else profile,
                enabled=True, sslRequired='all', registrationAllowed=False,
                editUsernameAllowed=False, duplicateEmailsAllowed=False, verifyEmail=True,
                revokeRefreshToken=True, refreshTokenMaxReuse=0, adminEventsDetailsEnabled=False,
                clients=[{'clientId': 'application', 'protocol': 'openid-connect', 'enabled': True, 'publicClient': True,
                          'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
                          'implicitFlowEnabled': False, 'serviceAccountsEnabled': False,
                          'redirectUris': ['https://app.example.net/callback'],
                          'webOrigins': ['https://app.example.net'],
                          'attributes': {'pkce.code.challenge.method': 'S256'}}])

    def findings(self, server=None, realms=None):
        return self.audit.audit(server or self.server, realms or self.realms, self.catalogue)['findings']

    def test_secure_candidate_passes_technical_checks_without_production_approval(self):
        result = self.audit.audit(self.server, self.realms, self.catalogue)
        self.assertEqual([], result['findings'])
        self.assertTrue(result['candidate_checks_passed'])
        self.assertFalse(result['production_approved'])
        self.assertIn('PRIVILEGED_FACTOR_FLOW', result['decisions_required'])

    def test_server_transport_and_bootstrap_regressions_are_refused(self):
        cases = [('http-enabled', 'true'), ('http-management-scheme', 'http'),
                 ('hostname-admin', 'https://id.example.net'), ('hostname', 'http://id.example.net'),
                 ('hostname-strict', 'false'), ('hostname-backchannel-dynamic', 'true'),
                 ('proxy-trusted-addresses', '0.0.0.0/0'), ('proxy-trusted-addresses', '::/0'),
                 ('tls-hostname-verifier', 'ANY'), ('https-protocols', 'TLSv1'),
                 ('db-username', 'postgres'), ('db-tls-mode', 'disabled'),
                 ('bootstrap-admin-username', 'temporary'), ('db-password', 'DO-NOT-PRINT')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                server = dict(self.server, **{key: value})
                self.assertTrue(self.findings(server=server))

    def test_jdbc_driver_parameters_cannot_override_verified_tls(self):
        for query in ('sslmode=disable', 'sslmode=require', 'sslmode=verify-full&sslmode=disable',
                      'SSLMode=disable', '%73slmode=disable', 'sslfactory=unsafe',
                      'sslhostnameverifier=unsafe', 'user=secret', 'password=DO-NOT-PRINT'):
            with self.subTest(query=query):
                server = dict(self.server, **{'db-url': self.server['db-url'] + '?' + query})
                self.assertIn('SERVER_DATABASE', self.findings(server=server))

    def test_missing_or_colliding_populations_and_weak_policy_are_refused(self):
        realms = copy.deepcopy(self.realms)
        del realms['administrators']
        self.assertIn('REALM_POPULATIONS', self.findings(realms=realms))
        for key, value in [('realm', 'customers'), ('failureFactor', 5), ('permanentLockout', False),
                           ('sslRequired', 'external'), ('registrationAllowed', True),
                           ('passwordPolicy', 'length(8)'), ('refreshTokenMaxReuse', 1)]:
            with self.subTest(key=key):
                realms = copy.deepcopy(self.realms)
                realms['workforce'][key] = value
                self.assertTrue(self.findings(realms=realms))

    def test_unsafe_interactive_client_grants_and_returns_are_refused(self):
        for key, value in [('directAccessGrantsEnabled', True), ('implicitFlowEnabled', True),
                           ('serviceAccountsEnabled', True), ('redirectUris', ['https://app.example.net/*']),
                           ('redirectUris', ['http://app.example.net/callback']),
                           ('webOrigins', ['*']), ('attributes', {})]:
            with self.subTest(key=key):
                realms = copy.deepcopy(self.realms)
                realms['customers']['clients'][0][key] = value
                self.assertIn('REALM_CLIENT', self.findings(realms=realms))

    def test_parser_refuses_duplicates_expressions_and_ambiguous_property_syntax(self):
        for content in ('hostname=a\nhostname=b', 'db-url=${SECRET}', 'db\\-url=value',
                        'hostname: value', 'hostname=value\\\nother=value'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.audit.parse_config(content)
        self.assertEqual({'http-enabled': 'false'}, self.audit.parse_config('# comment\nhttp-enabled=false\n'))

    def test_cli_malformed_and_secret_inputs_emit_only_fixed_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sensitive-name.conf'
            path.write_text('db-password=DO-NOT-PRINT\nhostname=${DO-NOT-PRINT}')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/check_production.py'),
                                     '--server-config', str(path)], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            for secret in ('DO-NOT-PRINT', 'sensitive-name', directory, 'Traceback'):
                self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertEqual(['INPUT_INVALID'], json.loads(result.stdout)['findings'])

    def test_duplicate_json_keys_cannot_hide_a_weaker_realm_value(self):
        with self.assertRaises(ValueError):
            self.audit.load_json('{"failureFactor":3,"failureFactor":99}')

    def test_client_type_confusion_is_refused(self):
        realms = copy.deepcopy(self.realms)
        realms['customers']['clients'][0]['standardFlowEnabled'] = 'true'
        realms['customers']['clients'][0]['redirectUris'] = []
        self.assertIn('REALM_CLIENT', self.findings(realms=realms))

    def test_duplicate_password_policy_terms_are_refused(self):
        realms = copy.deepcopy(self.realms)
        realms['customers']['passwordPolicy'] += ' and length(1)'
        self.assertIn('REALM_PASSWORD_POLICY', self.findings(realms=realms))

    def test_whitespace_cannot_hide_last_wins_password_policy_overrides(self):
        for override in ('length (1)', ' length(1)', '\tlength\t(1)',
                         'passwordHistory (0)', ' hashAlgorithm (pbkdf2)'):
            with self.subTest(override=override):
                realms = copy.deepcopy(self.realms)
                realms['customers']['passwordPolicy'] += ' and ' + override
                self.assertIn('REALM_PASSWORD_POLICY', self.findings(realms=realms))

    def test_proxy_ranges_cannot_collectively_trust_every_address(self):
        for proxies in ('0.0.0.0/1,128.0.0.0/1', '::/1,8000::/1',
                        '0.0.0.0/2,64.0.0.0/2,128.0.0.0/1',
                        '10.24.0.0/24,::/1,8000::/1'):
            with self.subTest(proxies=proxies):
                server = dict(self.server, **{'proxy-trusted-addresses': proxies})
                self.assertIn('SERVER_PROXY_TRUST', self.findings(server=server))

    def test_explicit_dual_stack_proxy_networks_remain_valid(self):
        server = dict(self.server, **{
            'proxy-trusted-addresses': '10.24.0.0/25,10.24.0.128/25,fd24::/64'})
        self.assertEqual([], self.findings(server=server))

    def test_management_tls_override_and_opaque_grant_switches_are_refused(self):
        server = dict(self.server, **{'https-management-protocols': 'TLSv1'})
        self.assertIn('SERVER_TRANSPORT', self.findings(server=server))
        for key in ('oauth2.device.authorization.grant.enabled', 'oidc.ciba.grant.enabled',
                    'standard.token.exchange.enabled'):
            realms = copy.deepcopy(self.realms)
            realms['customers']['clients'][0]['attributes'][key] = 'true'
            self.assertIn('REALM_CLIENT', self.findings(realms=realms))

    def test_unreviewed_spi_trust_override_cannot_disable_certificate_validation(self):
        server = dict(self.server, **{'spi-connections-http-client--default--disable-trust-manager': 'true'})
        self.assertTrue(self.findings(server=server))

    def test_temporary_lockout_budget_cannot_replace_direct_permanent_blocking(self):
        realms = copy.deepcopy(self.realms)
        realms['customers']['maxTemporaryLockouts'] = 5
        self.assertIn('REALM_POLICY', self.findings(realms=realms))

    def test_every_shared_brute_force_setting_must_match_the_catalogue(self):
        changes = {'bruteForceProtected': False, 'permanentLockout': False,
                   'failureFactor': 4, 'bruteForceStrategy': 'LINEAR',
                   'waitIncrementSeconds': 0, 'maxFailureWaitSeconds': 0,
                   'maxDeltaTimeSeconds': 0, 'quickLoginCheckMilliSeconds': 1000,
                   'minimumQuickLoginWaitSeconds': 0, 'maxTemporaryLockouts': 1}
        for profile in self.realms:
            for key, value in changes.items():
                with self.subTest(profile=profile, key=key):
                    realms = copy.deepcopy(self.realms)
                    realms[profile][key] = value
                    self.assertIn('REALM_POLICY', self.findings(realms=realms))

    def test_missing_shared_brute_force_settings_are_refused(self):
        for profile in self.realms:
            for key in self.catalogue['defaults']:
                with self.subTest(profile=profile, key=key):
                    realms = copy.deepcopy(self.realms)
                    del realms[profile][key]
                    self.assertIn('REALM_POLICY', self.findings(realms=realms))

    def test_shared_brute_force_settings_require_exact_types(self):
        changes = {'bruteForceProtected': 1, 'permanentLockout': 1,
                   'failureFactor': 3.0, 'bruteForceStrategy': ['MULTIPLE'],
                   'waitIncrementSeconds': 900.0, 'maxFailureWaitSeconds': 900.0,
                   'maxDeltaTimeSeconds': 43200.0, 'quickLoginCheckMilliSeconds': False,
                   'minimumQuickLoginWaitSeconds': 60.0, 'maxTemporaryLockouts': False}
        for profile in self.realms:
            for key, value in changes.items():
                with self.subTest(profile=profile, key=key):
                    realms = copy.deepcopy(self.realms)
                    realms[profile][key] = value
                    self.assertIn('REALM_POLICY', self.findings(realms=realms))

    def test_administrator_maximum_session_requires_a_positive_bounded_integer(self):
        for value in (3601, 0, -1, None, True, 3600.0, '3600'):
            with self.subTest(value=value):
                realms = copy.deepcopy(self.realms)
                realms['administrators']['ssoSessionMaxLifespan'] = value
                self.assertIn('REALM_SESSION_POLICY', self.findings(realms=realms))
        realms = copy.deepcopy(self.realms)
        del realms['administrators']['ssoSessionMaxLifespan']
        self.assertIn('REALM_SESSION_POLICY', self.findings(realms=realms))

    def test_shorter_administrator_maximum_sessions_remain_valid(self):
        for value in (1, 3599, 3600):
            with self.subTest(value=value):
                realms = copy.deepcopy(self.realms)
                realms['administrators']['ssoSessionMaxLifespan'] = value
                self.assertEqual([], self.findings(realms=realms))

    def test_jwt_grant_and_unsafe_logout_returns_are_refused(self):
        for key, value in [('oauth2.jwt.authorization.grant.enabled', 'true'),
                           ('post.logout.redirect.uris', '*'),
                           ('post.logout.redirect.uris', 'http://app.example.net/logout'),
                           ('post.logout.redirect.uris', 'https://app.example.net/*')]:
            with self.subTest(key=key, value=value):
                realms = copy.deepcopy(self.realms)
                realms['customers']['clients'][0]['attributes'][key] = value
                self.assertIn('REALM_CLIENT', self.findings(realms=realms))

    def test_reserved_jdbc_substrings_cannot_suppress_upstream_tls_injection(self):
        for name in ('identity_sslmode', 'identity_sslrootcert', 'identity_sslfactory'):
            with self.subTest(name=name):
                server = dict(self.server, **{'db-url': 'jdbc:postgresql://db.example.net/' + name})
                self.assertIn('SERVER_DATABASE', self.findings(server=server))

    def test_non_oidc_or_incomplete_application_clients_are_refused(self):
        for protocol in ('saml', None):
            with self.subTest(protocol=protocol):
                realms = copy.deepcopy(self.realms)
                realms['customers']['clients'][0]['protocol'] = protocol
                self.assertIn('REALM_CLIENT', self.findings(realms=realms))

    def test_service_accounts_require_a_confidential_noninteractive_client(self):
        realms = copy.deepcopy(self.realms)
        client = realms['customers']['clients'][0]
        client.update(publicClient=False, standardFlowEnabled=False, serviceAccountsEnabled=True,
                      redirectUris=[], webOrigins=[])
        self.assertEqual([], self.findings(realms=realms))
        client['publicClient'] = True
        self.assertIn('REALM_CLIENT', self.findings(realms=realms))

    def test_unreviewed_public_health_override_is_refused(self):
        server = dict(self.server, **{'http-management-health-enabled': 'false'})
        self.assertIn('SERVER_UNREVIEWED_OPTION', self.findings(server=server))

    def test_cli_secure_candidate_and_secret_bearing_bad_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'candidate.conf').write_text('\n'.join(f'{k}={v}' for k, v in self.server.items()))
            command = [sys.executable, str(ROOT / 'scripts/check_production.py'),
                       '--server-config', str(path / 'candidate.conf')]
            for profile, realm in self.realms.items():
                filename = path / (profile + '.json')
                filename.write_text(json.dumps(realm))
                command.extend(['--realm', profile + '=' + str(filename)])
            clean = {k: v for k, v in os.environ.items() if not k.startswith(('KC_', 'KCRAW_', 'QUARKUS_', 'KEYCLOAK_ADMIN'))
                     and k not in ('JAVA_OPTS', 'JAVA_OPTS_APPEND', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS')}
            result = subprocess.run(command, env=clean, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertTrue(json.loads(result.stdout)['candidate_checks_passed'])
            result = subprocess.run(command + ['--DO-NOT-PRINT'], env=clean, capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn('DO-NOT-PRINT', result.stdout + result.stderr)

    def test_candidate_audit_does_not_ignore_keycloak_process_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidate.conf'
            path.write_text('\n'.join(f'{k}={v}' for k, v in self.server.items()))
            env = dict(os.environ, KC_HTTP_ENABLED='true')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/check_production.py'),
                                     '--server-config', str(path)], env=env, capture_output=True, text=True)
            self.assertIn('EXTERNAL_CONFIG_SOURCE', json.loads(result.stdout)['findings'])
