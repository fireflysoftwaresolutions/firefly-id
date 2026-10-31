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
                    mappers = {m['name']: m for m in app_client['protocolMappers']}
                    self.assertEqual(mappers['principal_kind']['config']['claim.value'], expected_kind)
                    self.assertEqual(mappers['client_id']['config']['claim.value'], app_client['clientId'])
                    if expected_kind == 'STAFF':
                        self.assertNotIn('party_id', mappers)
                    else:
                        self.assertNotIn('staff_actor_id', mappers)
                self.assertEqual(realm['smtpServer']['host'], 'mailpit')
                self.assertEqual(realm['users'][0]['email'].split('@')[1], 'example.invalid')

    def test_generated_compose_has_private_pinned_database_and_reachable_issuer(self):
        with tempfile.TemporaryDirectory() as parent:
            output = pathlib.Path(parent) / 'sandbox'
            result = self.run_generator(output, '--mode', 'sandbox')
            self.assertEqual(result.returncode, 0, result.stderr)
            compose = json.loads((output / 'compose.json').read_text())
            services = compose['services']
            self.assertNotIn('ports', services['postgres'])
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
