"""Offline deployment contracts; these do not qualify a running Keycloak."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class DeploymentGenerationTest(unittest.TestCase):
    def run_generator(self, output, *args):
        theme = output.parent / 'built-theme'
        for kind in ('login', 'account', 'admin', 'email', 'welcome'):
            (theme / kind).mkdir(parents=True, exist_ok=True)
            (theme / kind / 'theme.properties').write_text('parent=base\n')
        return subprocess.run([sys.executable, str(ROOT / 'scripts/generate.py'),
                               '--output', str(output), '--theme-dir', str(theme), *args], text=True, capture_output=True)

    def test_production_refuses_unselected_contract_without_creating_secrets(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'production'
            result = self.run_generator(output, '--mode', 'production')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('production contract', result.stderr.lower())
            self.assertFalse(output.exists())

    def test_optional_configuration_lookup_client_is_isolated_from_human_clients(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox',
                    '--configuration-lookup-client-id', 'configuration-lookup',
                    '--configuration-lookup-realm', 'customers',
                    '--configuration-lookup-tenant', 'synthetic-platform-namespace')
            self.assertEqual(result.returncode, 0, result.stderr)
            customer = json.loads((output / 'realms/sandbox-customers-realm.json').read_text())
            service = next(client for client in customer['clients'] if client['clientId'] == 'configuration-lookup')
            self.assertTrue(service['serviceAccountsEnabled'])
            self.assertFalse(service['publicClient'])
            for grant in ('standardFlowEnabled', 'directAccessGrantsEnabled', 'implicitFlowEnabled', 'fullScopeAllowed'):
                self.assertFalse(service[grant])
            self.assertEqual(service['redirectUris'], [])
            self.assertEqual(service['optionalClientScopes'], [])
            self.assertEqual(service['defaultClientScopes'], ['basic'])
            claims = {mapper['config']['claim.name']: mapper['config'].get('claim.value')
                      for mapper in service['protocolMappers'] if 'claim.name' in mapper['config']}
            self.assertEqual(claims, {'tenant_id': 'synthetic-platform-namespace', 'client_id': 'configuration-lookup', 'principal_kind': 'MACHINE'})
            self.assertFalse(any(client['serviceAccountsEnabled'] for client in customer['clients'] if client is not service))
            secret = (output / 'secrets/configuration-lookup-client-secret').read_text().strip()
            self.assertGreaterEqual(len(secret), 48)
            self.assertEqual(service['secret'], secret)
            self.assertNotIn(secret, result.stdout + result.stderr)
            metadata = json.loads((output / 'configuration-lookup-client.json').read_text())
            self.assertNotIn('subject', metadata)
            self.assertNotIn(secret, json.dumps(metadata))
            self.assertEqual(metadata['audience'], 'sandbox-api')

    def test_lookup_provisioning_rejects_incomplete_or_conflicting_input_before_state_creation(self):
        for inputs in [('--configuration-lookup-client-id', 'configuration-lookup'),
                       ('--configuration-lookup-client-id', 'sandbox-api', '--configuration-lookup-realm', 'customers', '--configuration-lookup-tenant', 'opaque'),
                       ('--configuration-lookup-client-id', 'lookup', '--configuration-lookup-realm', 'customers', '--configuration-lookup-tenant', 'opaque\nnamespace')]:
            with self.subTest(inputs=inputs), tempfile.TemporaryDirectory() as parent:
                output = pathlib.Path(parent) / 'sandbox'
                result = self.run_generator(output, '--mode', 'sandbox', *inputs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

    def test_sandbox_generation_is_explicit_and_cannot_overwrite_retained_state(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            self.assertNotEqual(self.run_generator(output).returncode, 0)
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            credentials = (output / 'secrets/admin-password').read_text()
            self.assertGreaterEqual(len(credentials.strip()), 32)
            self.assertNotIn(credentials.strip(), result.stdout)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            again = self.run_generator(output, '--mode', 'sandbox')
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((output / 'secrets/admin-password').read_text(), credentials)

    def test_generated_boundaries_disable_unsafe_grants_and_forged_attributes(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            realms = [json.loads(path.read_text()) for path in (output / 'realms').glob('*.json')]
            self.assertEqual({r['realm'] for r in realms},
                             {'sandbox-customers', 'sandbox-workforce', 'sandbox-institutions'})
            for realm in realms:
                self.assertFalse(realm['registrationAllowed'])
                self.assertTrue(realm['resetPasswordAllowed'])
                self.assertTrue(realm['internationalizationEnabled'])
                self.assertEqual(realm['supportedLocales'], ['en', 'es'])
                self.assertEqual(realm['defaultLocale'], 'en')
                component = realm['components']['org.keycloak.userprofile.UserProfileProvider'][0]
                profile = json.loads(component['config']['kc.user.profile.config'][0])
                # Keycloak 26.8.1 UPConfig has ENABLED/ADMIN_VIEW/ADMIN_EDIT only;
                # JSON null is the disabled policy, not the UI label DISABLED.
                self.assertIsNone(profile['unmanagedAttributePolicy'])
                protected = {a['name']: a for a in profile['attributes']}
                for name in ('tenant_id', 'party_id', 'staff_actor_id'):
                    self.assertEqual(protected[name]['permissions']['edit'], ['admin'])
                for client in realm['clients']:
                    self.assertFalse(client['directAccessGrantsEnabled'])
                    self.assertFalse(client['implicitFlowEnabled'])
                    self.assertFalse(client['serviceAccountsEnabled'])
                    if client['clientId'] == 'sandbox-api':
                        self.assertFalse(client['standardFlowEnabled'])
                        self.assertFalse(client['publicClient'])
                        self.assertEqual(client['defaultClientScopes'], [])
                        self.assertEqual(client['protocolMappers'], [])
                        self.assertEqual(client['redirectUris'], [])
                        continue
                    self.assertIn('basic', client['defaultClientScopes'])
                    self.assertTrue(client['standardFlowEnabled'])
                    self.assertEqual(client['attributes']['pkce.code.challenge.method'], 'S256')
                    self.assertFalse(any('*' in uri for uri in client['redirectUris']))
                    self.assertNotIn('*', client['attributes']['post.logout.redirect.uris'])
                user_attrs = realm['users'][0]['attributes']
                self.assertEqual(user_attrs['tenant_id'], ['synthetic-tenant'])
                if realm['realm'] == 'sandbox-workforce':
                    self.assertNotIn('party_id', user_attrs)
                    self.assertRegex(user_attrs['staff_actor_id'][0], r'^[a-f0-9-]{36}$')
                    expected_kind = 'STAFF'
                else:
                    self.assertNotIn('staff_actor_id', user_attrs)
                    self.assertRegex(user_attrs['party_id'][0], r'^[a-f0-9-]{36}$')
                    expected_kind = 'HUMAN'
                for app_client in realm['clients']:
                    if app_client['clientId'] == 'sandbox-api':
                        continue
                    mappers = {m['name']: m for m in app_client['protocolMappers']}
                    self.assertEqual(mappers['principal_kind']['config']['claim.value'], expected_kind)
                    self.assertEqual(mappers['client_id']['config']['claim.value'], app_client['clientId'])
                    if expected_kind == 'STAFF':
                        self.assertNotIn('party_id', mappers)
                    else:
                        self.assertNotIn('staff_actor_id', mappers)
                self.assertEqual(realm['smtpServer']['host'], 'mailpit')
                for user in realm['users']:
                    self.assertEqual(user['clientRoles'], {'account': ['manage-account', 'view-profile']})
                    self.assertNotIn('realmRoles', user)
                self.assertEqual(realm['users'][0]['email'].split('@')[1], 'example.invalid')

    def test_extended_accounts_are_separate_and_require_server_owned_verification_and_mfa(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            credentials = json.loads((output / 'credentials.json').read_text())
            self.assertIn('verify_email', credentials)
            self.assertNotEqual(credentials['customers']['password'], credentials['verify_email']['password'])
            customers = json.loads((output / 'realms/sandbox-customers-realm.json').read_text())
            users = {user['username']: user for user in customers['users']}
            primary = users['synthetic-customers']
            verification = users['synthetic-verify-email']
            self.assertTrue(primary['emailVerified'])
            self.assertFalse(verification['emailVerified'])
            self.assertEqual(verification['requiredActions'], ['VERIFY_EMAIL'])
            self.assertEqual(verification['email'], 'verify-email@example.invalid')
            self.assertEqual(verification['credentials'][0]['value'], credentials['verify_email']['password'])
            self.assertNotEqual(primary['attributes']['party_id'], verification['attributes']['party_id'])
            workforce = json.loads((output / 'realms/sandbox-workforce-realm.json').read_text())
            self.assertEqual(workforce['users'][0]['requiredActions'], ['CONFIGURE_TOTP'])
            self.assertEqual(workforce['otpPolicyType'], 'totp')
            self.assertEqual(workforce['otpPolicyAlgorithm'], 'HmacSHA1')
            self.assertEqual(workforce['otpPolicyDigits'], 6)
            self.assertEqual(workforce['otpPolicyPeriod'], 30)
            self.assertFalse(workforce['otpPolicyCodeReusable'])
            factor_state = output / 'secrets/workforce-totp.json'
            self.assertEqual(factor_state.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(factor_state.read_text()), {'status': 'pending-enrollment'})
            for account in credentials.values():
                self.assertNotIn(account['password'], result.stdout)

    def test_population_policies_are_loaded_from_configuration_and_enforce_three_failures(self):
        configured = json.loads((ROOT / 'config/authentication-policies.json').read_text())
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            for kind, minimum, history in [('customers', 16, 5), ('workforce', 20, 10), ('institutions', 16, 5)]:
                with self.subTest(population=kind):
                    realm = json.loads((output / f'realms/sandbox-{kind}-realm.json').read_text())
                    policy = realm['passwordPolicy']
                    self.assertEqual(policy, configured['profiles'][kind]['realmSettings']['passwordPolicy'])
                    for required in (f'length({minimum})', 'maxLength(128)', f'passwordHistory({history})',
                                     'notUsername', 'notEmail', 'hashAlgorithm(argon2)',
                                     'passwordBlacklist(firefly-baseline.txt)'):
                        self.assertIn(required, policy.split(' and '))
                    for unnecessary in ('digits(', 'upperCase(', 'lowerCase(', 'specialChars(', 'forceExpiredPasswordChange('):
                        self.assertNotIn(unnecessary, policy)
                    self.assertTrue(realm['bruteForceProtected'])
                    self.assertTrue(realm['permanentLockout'])
                    self.assertEqual(realm['failureFactor'], 3)
                    self.assertEqual(realm['maxTemporaryLockouts'], 0)
                    self.assertEqual(realm['bruteForceStrategy'], 'MULTIPLE')
                    self.assertEqual(realm['waitIncrementSeconds'], 900)
                    self.assertEqual(realm['maxFailureWaitSeconds'], 900)
                    self.assertEqual(realm['quickLoginCheckMilliSeconds'], 0)
                    self.assertGreater(realm['maxDeltaTimeSeconds'], realm['maxFailureWaitSeconds'])
                    self.assertEqual(realm['ssoSessionIdleTimeout'], 900 if kind == 'workforce' else 300)
                    self.assertEqual(realm['ssoSessionMaxLifespan'], 28800)
                    self.assertEqual(realm['accessTokenLifespan'], 300)
            self.assertTrue(configured['profiles']['workforce']['mfaRequired'])
            self.assertTrue(configured['profiles']['administrators']['mfaRequired'])
            self.assertEqual(configured['profiles']['administrators']['application'], 'explicit-admin-api-after-bootstrap')
            administration = configured['profiles']['administrators']['realmSettings']
            self.assertEqual(administration['ssoSessionIdleTimeout'], 300)
            self.assertEqual(administration['ssoSessionMaxLifespan'], 3600)
            self.assertEqual(administration['accessTokenLifespan'], 60)

    def test_generator_consumes_policy_changes_instead_of_duplicating_a_hardcoded_policy(self):
        import importlib.util
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('generate_policy', ROOT / 'scripts/generate.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        configured = json.loads((ROOT / 'config/authentication-policies.json').read_text())
        configured['profiles']['customers']['realmSettings']['passwordPolicy'] = 'length(24) and maxLength(128)'
        with tempfile.TemporaryDirectory() as parent:
            path = pathlib.Path(parent) / 'policies.json'
            path.write_text(json.dumps(configured))
            with patch.object(module, 'POLICIES_PATH', path):
                realm = module.realm('customers', 'random-test-password-without-a-server', 'random-test-client-secret')
            self.assertEqual(realm['passwordPolicy'], 'length(24) and maxLength(128)')

    def test_workforce_browser_requires_otp_even_for_users_without_an_imported_required_action(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            self.assertEqual(self.run_generator(output, '--mode', 'sandbox').returncode, 0)
            realm = json.loads((output / 'realms/sandbox-workforce-realm.json').read_text())
            flows = {flow['alias']: flow for flow in realm['authenticationFlows']}
            browser = flows[realm['browserFlow']]
            self.assertTrue(browser['topLevel'])
            forms = next(execution for execution in browser['authenticationExecutions'] if execution['authenticatorFlow'])
            executions = flows[forms['flowAlias']]['authenticationExecutions']
            self.assertEqual([(execution['authenticator'], execution['requirement']) for execution in executions],
                             [('auth-username-password-form', 'REQUIRED'), ('auth-otp-form', 'REQUIRED')])
            self.assertFalse(any(execution['requirement'] == 'CONDITIONAL' for execution in executions))

    def test_policy_fixtures_and_denylist_mount_do_not_reuse_main_accounts_or_expose_credentials(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            credentials = json.loads((output / 'credentials.json').read_text())
            for key, kind in [('policy_customers', 'customers'), ('policy_workforce', 'workforce')]:
                fixture = credentials[key]
                self.assertNotEqual(fixture['username'], credentials[kind]['username'])
                self.assertNotEqual(fixture['password'], credentials[kind]['password'])
                self.assertNotIn(fixture['password'], result.stdout + result.stderr)
                realm = json.loads((output / f'realms/sandbox-{kind}-realm.json').read_text())
                user = next(user for user in realm['users'] if user['username'] == fixture['username'])
                self.assertEqual(user['credentials'][0]['value'], fixture['password'])
                self.assertTrue(user['emailVerified'])
            compose = json.loads((output / 'compose.json').read_text())
            mount = next(volume for volume in compose['services']['keycloak']['volumes']
                         if volume['target'] == '/opt/keycloak/data/password-blacklists/firefly-baseline.txt')
            self.assertEqual(mount['source'], str(ROOT / 'config/password-blacklist.txt'))
            self.assertTrue(mount['read_only'])
            denied = (ROOT / 'config/password-blacklist.txt').read_text().splitlines()
            self.assertGreaterEqual(len(denied), 8)
            self.assertTrue(all(len(value) >= 20 for value in denied))
            self.assertIn('firefly identity customer password', denied)

    def test_generated_compose_has_private_pinned_database_and_reachable_issuer(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            compose = json.loads((output / 'compose.json').read_text())
            services = compose['services']
            self.assertNotIn('ports', services['postgres'])
            self.assertEqual(services['postgres']['networks'], ['identity'])
            self.assertIn('ingress', services['keycloak']['networks'])
            self.assertIn('ingress', services['mailpit']['networks'])
            self.assertNotIn('1025', ' '.join(services['mailpit']['ports']))
            for service in services.values():
                self.assertRegex(service['image'], r':[^:@]+@sha256:[a-f0-9]{64}$')
                self.assertTrue(all(p.startswith('127.0.0.1:') for p in service.get('ports', [])))
            env = services['keycloak']['environment']
            self.assertEqual(env['KC_HOSTNAME'], 'http://id.firefly.test:8180')
            self.assertEqual(env['KC_HTTP_PORT'], '8180')
            self.assertIn('id.firefly.test', services['keycloak']['networks']['identity']['aliases'])
            self.assertNotIn('KC_DB_PASSWORD', env)
            self.assertTrue(compose['networks']['identity']['internal'])


class ExtendedOtpAlgorithmTest(unittest.TestCase):
    def test_totp_matches_rfc_vector_without_loading_browser_dependencies(self):
        script = """
import assert from 'node:assert/strict';
import { totpCode } from './tooling/extended-runtime.mjs';
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
assert.equal(totpCode(secret, 59, 8), '94287082');
assert.equal(totpCode(secret, 59), '287082');
assert.equal(totpCode(secret, 0), '755224');
assert.throws(() => totpCode('invalid-secret!', 59));
"""
        result = subprocess.run(['node', '--input-type=module', '-e', script],
                                cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_policy_assertions_reject_attempt_counts_and_account_status(self):
        script = """
import assert from 'node:assert/strict';
import { normalizePublicText, assertNoPublicDisclosure } from './tooling/policy-runtime.mjs';
assert.equal(normalizePublicText('  Unable\\n to sign in.  '), 'Unable to sign in.');
assertNoPublicDisclosure('Unable to sign in. Check your details and try again.');
for (const text of ['2 attempts remaining', 'Remaining attempts: 2', 'Account is disabled', 'Unknown user', 'User not found',
  'Account temporarily locked', 'This email is registered', '1 attempt left']) {
  assert.throws(() => assertNoPublicDisclosure(text));
}
"""
        result = subprocess.run(['node', '--input-type=module', '-e', script],
                                cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class SandboxLifecycleTest(unittest.TestCase):
    def test_remote_docker_endpoints_are_refused(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('sandbox', ROOT / 'scripts/sandbox.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for endpoint in ('ssh://operator@host', 'tcp://localhost:2375', 'unix://remote/socket', ''):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(RuntimeError, 'local Unix'):
                module.require_local_endpoint(endpoint)
        module.require_local_endpoint('unix:///var/run/docker.sock')

    def test_missing_build_is_rejected_without_creating_state(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'state'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/generate.py'),
                                     '--mode', 'sandbox', '--output', str(output),
                                     '--theme-dir', str(pathlib.Path(parent) / 'missing')],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('build', result.stderr.lower())
            self.assertFalse(output.exists())

    def test_unsafe_disk_gate_is_rejected_before_docker_is_invoked(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('sandbox', ROOT / 'scripts/sandbox.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaisesRegex(RuntimeError, '12 GiB'):
            module.check_capacity(11 * 1024 ** 3)
        module.check_capacity(12 * 1024 ** 3)

    def test_retained_state_with_changed_compose_is_rejected(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('sandbox', ROOT / 'scripts/sandbox.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as parent:
            state = pathlib.Path(parent) / 'state'
            result = DeploymentGenerationTest().run_generator(state, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(module.load_owned_state(state)['project'].startswith('firefly-id-sandbox-'))
            (state / 'compose.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                module.load_owned_state(state)


if __name__ == '__main__':
    unittest.main()
