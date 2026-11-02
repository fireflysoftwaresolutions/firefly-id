"""Offline ownership, exact-candidate and effective-control boundaries."""
import copy
import importlib.util
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_privileged_profile import source

ROOT = Path(__file__).resolve().parents[1]


class MasterTransitionTest(unittest.TestCase):
    def module(self):
        path = ROOT / 'tooling/master_transition_fixture.py'
        self.assertTrue(path.is_file(), 'Owned master fixture is missing')
        spec = importlib.util.spec_from_file_location('master_transition_fixture', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_import_normalization_is_measured_and_limited_to_closed_native_clients(self):
        module = self.module(); document = source()
        resource = next(client for client in document['clients'] if client['clientId'] == 'realm-management')
        resource.update(clientId='master-realm', enabled=True, publicClient=False, bearerOnly=True,
                        standardFlowEnabled=True, attributes={'realm_client': 'true'})
        resource.pop('protocol')
        document['roles']['client'] = {'master-realm': [{'name': 'view-realm'}, {'name': 'manage-realm'}]}
        candidate = module.profile.build_profile(document, realm='master', origin='https://id.example.test', acknowledge_master=True)
        effective = copy.deepcopy(candidate)
        internal = next(client for client in effective['clients'] if client['clientId'] == 'master-realm')
        internal['protocol'] = 'openid-connect'
        internal['attributes'].update({'client.secret.creation.time': '100', 'post.logout.redirect.uris': '+'})
        effective['clients'][0]['attributes']['post.logout.redirect.uris'] = '+'
        before = copy.deepcopy(effective)
        module.verify_effective(candidate, effective, import_window={'minimum': 99, 'maximum': 101})
        self.assertEqual(effective, before)
        with self.assertRaises(ValueError): module.verify_effective(candidate, effective)
        for mutation in ({'client.secret.creation.time': '102'}, {'client.secret.creation.time': '0100'},
                         {'post.logout.redirect.uris': '*'}, {'unknown': 'PRIVATE'}):
            invalid = copy.deepcopy(effective)
            next(client for client in invalid['clients'] if client['clientId'] == 'master-realm')['attributes'].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.verify_effective(candidate, invalid, import_window={'minimum': 99, 'maximum': 101})
        for field, value in [('publicClient', True), ('bearerOnly', False), ('directAccessGrantsEnabled', True), ('protocol', 'saml')]:
            invalid = copy.deepcopy(effective)
            next(client for client in invalid['clients'] if client['clientId'] == 'master-realm')[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.verify_effective(candidate, invalid, import_window={'minimum': 99, 'maximum': 101})
        invalid = copy.deepcopy(effective); invalid['clients'][-1]['attributes']['post.logout.redirect.uris'] = '+'
        with self.assertRaises(ValueError): module.verify_effective(candidate, invalid, import_window={'minimum': 99, 'maximum': 101})
        for secret in ('', 'existing'):
            existing = copy.deepcopy(candidate)
            next(client for client in existing['clients'] if client['clientId'] == 'master-realm')['secret'] = secret
            with self.assertRaises(ValueError): module.verify_effective(existing, effective, import_window={'minimum': 99, 'maximum': 101})

    def test_component_readback_requires_full_database_material_and_exact_api_projection(self):
        module = self.module()
        self.assertTrue(hasattr(module, 'verified_component_readback'))
        kind = 'org.keycloak.keys.KeyProvider'
        component = {'id': 'key-id', 'name': 'hmac', 'providerId': 'hmac-generated',
                     'config': {'priority': ['100'], 'algorithm': ['HS512'], 'secret': ['PRIVATE'], 'kid': ['key-id']}}
        candidate = {'id': 'realm-id', 'realm': 'master', 'components': {kind: [component]}}
        effective = copy.deepcopy(candidate)
        effective['components'][kind][0]['config'] = {'priority': ['100'], 'algorithm': ['HS512']}
        row = {'id': 'key-id', 'name': 'hmac', 'providerId': 'hmac-generated', 'providerType': kind,
               'realmId': 'realm-id', 'parentId': 'realm-id', 'subType': None, 'config': component['config']}
        unchanged = copy.deepcopy(effective)
        self.assertEqual(module.verified_component_readback(candidate, effective, [row]), candidate)
        self.assertEqual(effective, unchanged)
        for key, value in [('providerId', 'aes-generated'), ('parentId', 'foreign'), ('id', 'other'),
                           ('config', {**row['config'], 'secret': ['ALTERED']}),
                           ('config', {**row['config'], 'unknown': ['PRIVATE']})]:
            with self.subTest(key=key), self.assertRaises(ValueError) as error:
                module.verified_component_readback(candidate, effective, [{**row, key: value}])
            self.assertNotIn('PRIVATE', str(error.exception))
        for config in ({'priority': ['101'], 'algorithm': ['HS512']}, {'priority': ['100']},
                       {**unchanged['components'][kind][0]['config'], 'unknown': ['PRIVATE']}):
            invalid = copy.deepcopy(effective); invalid['components'][kind][0]['config'] = config
            with self.assertRaises(ValueError): module.verified_component_readback(candidate, invalid, [row])
        for rows in ([], [row, row]):
            with self.assertRaises(ValueError): module.verified_component_readback(candidate, effective, rows)
        unknown = copy.deepcopy(candidate); unknown['components'][kind][0]['config']['unknown'] = ['PRIVATE']
        with self.assertRaises(ValueError): module.verified_component_readback(unknown, effective, [row])

    def test_component_sql_is_read_only_and_bound_to_active_owned_phase(self):
        module = self.module()
        self.assertTrue(hasattr(module, 'read_component_rows'))
        for phase, database in [('imported', 'master_imported'), ('retained', 'master_retained')]:
            with patch.object(module, 'inspect_container', return_value=('owned', {'State': {'Running': True}})) as inspect, \
                 patch.object(module, 'psql', return_value='[]') as query:
                self.assertEqual(module.read_component_rows(Path('/owned'), {'phase': phase}), [])
                self.assertEqual(inspect.call_args.args[1], phase)
                self.assertEqual(query.call_args.args[3], database)
                self.assertTrue(query.call_args.kwargs['read_only'])
                self.assertTrue(query.call_args.args[2].startswith('SELECT '))
        for phase in ['candidate', 'enrollment', 'foreign']:
            with patch.object(module, 'psql') as query, self.assertRaises(ValueError):
                module.read_component_rows(Path('/owned'), {'phase': phase})
            query.assert_not_called()
        with patch.object(module, 'inspect_container', return_value=('owned-db', {})), \
             patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'[]', b'')) as process:
            module.psql(Path('/owned'), {}, 'SELECT 1;', 'master_imported', read_only=True)
            self.assertIn('PGOPTIONS=-c default_transaction_read_only=on', process.call_args.args[0])

    def test_native_key_projection_restores_only_database_verified_material_for_full_comparison(self):
        module = self.module(); document = source(); document['id'] = 'realm-id'
        kind = 'org.keycloak.keys.KeyProvider'
        configurations = [
            ('rsa-generated', {'priority': ['100'], 'algorithm': ['RS256']},
             {'privateKey': ['PRIVATE-RSA'], 'certificate': ['CERTIFICATE'], 'keyUse': ['SIG']}),
            ('rsa-enc-generated', {'algorithm': ['RSA-OAEP']}, {'privateKey': ['PRIVATE-ENC'], 'certificate': ['CERTIFICATE']}),
            ('hmac-generated', {'secretSize': ['128']}, {'secret': ['PRIVATE-HMAC'], 'kid': ['hmac-kid']}),
            ('aes-generated', {'secretSize': ['32']}, {'secret': ['PRIVATE-AES'], 'kid': ['aes-kid']}),
            ('ecdsa-generated', {'ecdsaEllipticCurveKey': ['P-256']},
             {'ecdsaPrivateKey': ['PRIVATE-EC'], 'ecdsaPublicKey': ['PUBLIC-EC']}),
        ]
        document['components'][kind] = [{'id': provider, 'name': provider, 'providerId': provider,
                                         'config': {**visible, **hidden}} for provider, visible, hidden in configurations]
        candidate = module.profile.build_profile(document, realm='master', origin='https://id.example.test', acknowledge_master=True)
        effective = copy.deepcopy(candidate)
        rows = []
        for component, (_, visible, _) in zip(effective['components'][kind], configurations):
            rows.append({'id': component['id'], 'name': component['name'], 'providerId': component['providerId'],
                         'providerType': kind, 'subType': None, 'parentId': 'realm-id', 'realmId': 'realm-id',
                         'config': copy.deepcopy(component['config'])})
            component['config'] = visible
        restored = module.verified_component_readback(candidate, effective, rows)
        module.verify_effective(candidate, restored)
        altered = copy.deepcopy(restored)
        altered['components'][kind][0]['config']['privateKey'] = ['ALTERED']
        with self.assertRaises(ValueError): module.verify_effective(candidate, altered)
        altered = copy.deepcopy(effective); altered['components'][kind][0]['name'] = 'changed'
        with self.assertRaises(ValueError):
            module.verify_effective(candidate, module.verified_component_readback(candidate, altered, rows))
        invalid = copy.deepcopy(candidate); invalid['components'][kind][0]['providerId'] = 'unknown-provider'
        with self.assertRaises(ValueError): module.verified_component_readback(invalid, effective, rows)

    def test_retained_component_rows_detect_hidden_key_changes(self):
        module = self.module()
        before = {'components': ['component-hash'], 'componentConfig': ['secret-hash'], 'events': ['e'], 'adminEvents': ['a']}
        for key in ('components', 'componentConfig'):
            with self.assertRaises(ValueError): module.verify_retained(before, {**before, key: ['changed']})
        with patch.object(module, 'psql', return_value='[]') as query:
            snapshot = module.snapshot(Path('/owned'), {})
        self.assertIn('components', snapshot)
        self.assertIn('componentConfig', snapshot)
        self.assertTrue(any('FROM component_config t' in call.args[2] for call in query.call_args_list))

    def test_component_database_profile_comparison_preserves_reviewed_policy_semantics(self):
        module = self.module(); kind = module.profile.USER_PROFILE_PROVIDER
        configuration = copy.deepcopy(module.profile.DEFAULT_USER_PROFILE)
        component = {'id': 'profile', 'providerId': 'declarative-user-profile',
                     'config': {'kc.user.profile.config': [json.dumps(configuration)]}}
        candidate = {'realm': 'master', 'id': 'realm-id', 'components': {kind: [component]}}
        effective = copy.deepcopy(candidate)
        for attribute in configuration['attributes']: attribute['multivalued'] = False
        row = {'id': 'profile', 'providerId': 'declarative-user-profile', 'providerType': kind,
               'name': None, 'subType': None, 'realmId': 'realm-id', 'parentId': 'realm-id',
               'config': {'kc.user.profile.config': [json.dumps(configuration, sort_keys=True)]}}
        module.verified_component_readback(candidate, effective, [row])
        configuration['attributes'][0]['permissions']['edit'] = ['user']
        row['config']['kc.user.profile.config'] = [json.dumps(configuration)]
        with self.assertRaises(ValueError): module.verified_component_readback(candidate, effective, [row])

    def test_ownership_refuses_stale_run_arbitrary_path_symlink_and_container(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            directory = root / '.state/master-123-1'
            directory.mkdir(parents=True)
            owner = {'run': '123-1', 'root': str(directory), 'kind': 'master-transition',
                     'project': 'ff-master-123-1', 'containers': ['ff-master-123-1-postgres']}
            self.assertEqual(module.validate_owner(root, directory, owner, '123-1'), owner)
            for mutation in ({'run': '122-1'}, {'root': '/tmp/other'}, {'project': 'shared'},
                             {'containers': ['production']}, {'kind': 'native-integration'}):
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    module.validate_owner(root, directory, {**owner, **mutation}, '123-1')
            nested = directory / 'logs'; nested.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError): module.validate_owner(root, directory, owner, '123-1')
            nested.unlink()
            link = root / '.state/master-124-1'; link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                module.validate_owner(root, link, {**owner, 'run': '124-1', 'root': str(link),
                                                 'project': 'ff-master-124-1', 'containers': []}, '124-1')

    def test_candidate_receipt_detects_byte_changes_and_target_substitution(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            candidate = directory / 'candidate.json'; candidate.write_text('{"realm":"master"}\n')
            receipt = module.candidate_receipt(directory)
            module.verify_candidate(directory, receipt)
            candidate.write_text('{ "realm":"master"}\n')
            with self.assertRaises(ValueError): module.verify_candidate(directory, receipt)
            candidate.unlink(); candidate.symlink_to(directory / 'elsewhere.json')
            with self.assertRaises(ValueError): module.verify_candidate(directory, receipt)

    def test_effective_normalization_accepts_generated_ids_but_never_drops_controls(self):
        module = self.module()
        document = source()
        candidate = module.profile.build_profile(document, realm='master', origin='https://id.example.test', acknowledge_master=True)
        effective = copy.deepcopy(candidate)
        effective['authenticationFlows'].reverse()
        for flow in effective['authenticationFlows']:
            flow['id'] = 'generated'; flow['description'] = 'Server display metadata'
            for execution in flow['authenticationExecutions']: execution['id'] = 'generated'
        effective['requiredActions'].reverse()
        module.verify_effective(candidate, effective)
        mutations = [('sslRequired', 'none'), ('enabled', False), ('identityProviders', [{'alias': 'unreviewed'}]),
                     ('clientAuthenticationFlow', 'unreviewed'), ('webAuthnPolicyUserVerificationRequirement', 'preferred'), ('eventsEnabled', False),
                     ('resetCredentialsFlow', 'reset credentials'), ('verifyEmail', False), ('webAuthnPolicyExtraOrigins', ['https://evil.test'])]
        for key, value in mutations:
            invalid = copy.deepcopy(effective); invalid[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): module.verify_effective(candidate, invalid)
        for kind in ('flow', 'action', 'client', 'extra-execution'):
            invalid = copy.deepcopy(effective)
            if kind == 'flow': invalid['authenticationFlows'][1]['authenticationExecutions'][0]['requirement'] = 'ALTERNATIVE'
            elif kind == 'action': invalid['requiredActions'][0]['enabled'] = True
            elif kind == 'client': invalid['clients'][0]['directAccessGrantsEnabled'] = True
            else: invalid['authenticationFlows'][1]['authenticationExecutions'].append({'authenticator': 'auth-cookie', 'priority': 30})
            with self.subTest(kind=kind), self.assertRaises(ValueError): module.verify_effective(candidate, invalid)

    def test_readback_preserves_builtin_client_authentication_and_bounds_retirement_watermark(self):
        module = self.module(); document = source()
        document['authenticationFlows'] = [{'alias': 'clients', 'providerId': 'client-flow', 'topLevel': True,
            'builtIn': True, 'authenticationExecutions': [{'authenticator': 'client-secret', 'authenticatorFlow': False,
                                                        'requirement': 'REQUIRED', 'priority': 10}]}]
        document['clientAuthenticationFlow'] = 'clients'; document['notBefore'] = 0
        candidate = module.profile.build_profile(document, realm='master', origin='https://id.example.test', acknowledge_master=True)
        invalid = copy.deepcopy(candidate); invalid['authenticationFlows'][-1]['authenticationExecutions'][0]['requirement'] = 'DISABLED'
        with self.assertRaises(ValueError): module.verify_effective(candidate, invalid)
        effective = copy.deepcopy(candidate); effective['notBefore'] = 100
        module.verify_effective(candidate, effective, {'minimum': 99, 'maximum': 101})
        for invalid_watermark in (98, 102, -1):
            effective['notBefore'] = invalid_watermark
            with self.assertRaises(ValueError): module.verify_effective(candidate, effective, {'minimum': 99, 'maximum': 101})

    def test_registration_events_classify_only_fixed_types_and_errors(self):
        module = self.module()
        self.assertTrue(hasattr(module, 'bounded_events'))
        actual = module.bounded_events([{'type': 'UPDATE_CREDENTIAL_ERROR', 'error': 'invalid_registration', 'details': 'PRIVATE'},
                                        {'type': 'PRIVATE', 'error': 'PRIVATE'}, {'type': 'LOGIN', 'error': None}])
        self.assertEqual(actual, [{'type': 'UPDATE_CREDENTIAL_ERROR', 'error': 'invalid_registration'},
                                  {'type': 'OTHER', 'error': 'OTHER'}, {'type': 'LOGIN', 'error': None}])
        self.assertNotIn('PRIVATE', json.dumps(actual))

    def test_profile_failure_gate_and_known_schema_names_never_expose_input_values(self):
        module = self.module(); self.assertTrue(hasattr(module, 'profile_diagnostic'))
        result = module.profile_diagnostic({'realm': 'master', 'unknown-private-field': 'PRIVATE', 'userManagedAccessAllowed': False},
                                           ValueError('Unsupported realm fields refused'))
        self.assertEqual(result['gate'], 'UNSUPPORTED_REALM_FIELDS')
        self.assertNotIn('PRIVATE', json.dumps(result)); self.assertNotIn('unknown-private-field', json.dumps(result))
        self.assertEqual(module.profile_diagnostic({}, ValueError('PRIVATE'))['gate'], 'UNCLASSIFIED')

    def test_every_static_profile_rejection_has_a_bounded_gate_and_profile_source_positions(self):
        import ast
        module = self.module()
        tree = ast.parse((ROOT / 'tooling/privileged_profile.py').read_text())
        for call in ast.walk(tree):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'require' and len(call.args) > 1:
                message = call.args[1]
                if isinstance(message, ast.Constant) and isinstance(message.value, str):
                    with self.subTest(message=message.value):
                        self.assertNotEqual(module.profile_diagnostic({}, ValueError(message.value))['gate'], 'UNCLASSIFIED')
        document = source(); document['verifyEmail'] = False
        try:
            module.profile.prerequisites(document, 'master', 'https://id.example.test')
        except ValueError as failure:
            diagnostic = module.profile_diagnostic(document, failure)
        self.assertTrue(diagnostic['profileSourceLines'])
        self.assertTrue(all(isinstance(value, int) and 0 < value < 10000 for value in diagnostic['profileSourceLines']))
        self.assertEqual(diagnostic['clients'][0]['scopes']['defaultClientScopes'],
                         {'present': True, 'isList': True, 'count': 0, 'offlineAccessPresent': False})

    def test_profile_diagnostic_inventories_later_gates_without_exposing_unknown_names_or_values(self):
        module = self.module()
        document = {'privateKey': 'PRIVATE', 'scimApiEnabled': False, 'PRIVATE_FIELD': 'PRIVATE',
                    'attributes': {'cibaExpiresIn': '120', 'frontendUrl': 'PRIVATE', 'PRIVATE_ATTRIBUTE': 'PRIVATE'},
                    'clients': [{'clientId': 'PRIVATE', 'authorizationSettings': 'PRIVATE',
                                 'PRIVATE_FIELD': 'PRIVATE', 'attributes': {'jwks.url': 'PRIVATE',
                                 'oidc.ciba.grant.enabled': 'true', 'PRIVATE_ATTRIBUTE': 'PRIVATE'}}],
                    'authenticationFlows': [{'authenticationExecutions': [
                        {'authenticator': 'organization'}, {'authenticator': 'PRIVATE'}]}],
                    'authenticatorConfig': [{'alias': 'review profile config', 'config': {'PRIVATE': 'PRIVATE'}}],
                    'requiredActions': [{'alias': 'UPDATE_PASSWORD', 'providerId': 'PRIVATE'}],
                    'components': {module.profile.USER_PROFILE_PROVIDER: [{'config': {'kc.user.profile.config': [json.dumps({
                        'attributes': [{'name': 'PRIVATE', 'displayName': 'PRIVATE', 'required': None}], 'PRIVATE': 'PRIVATE'})]}}]}}
        result = module.profile_diagnostic(document, ValueError('Unsupported realm fields refused'))
        self.assertIn('privateKey', result['knownUnsupportedRealmFields'])
        self.assertEqual(result['realmNativeDefaults'], {'cibaExpiresIn': True})
        self.assertIn('authorizationSettings', result['clients'][0]['knownUnsupportedFields'])
        self.assertIn('jwks.url', result['clients'][0]['knownAttributes'])
        self.assertIn('organization', result['knownAuthenticators'])
        self.assertEqual(result['unknownAuthenticatorCount'], 1)
        self.assertFalse(result['authenticatorConfigs'][0]['reviewedDefault'])
        self.assertEqual(result['requiredActions'][0]['alias'], 'UPDATE_PASSWORD')
        self.assertEqual(result['requiredActions'][0]['provider'], 'OTHER')
        self.assertEqual(result['clients'][0]['clientId'], 'OTHER')
        self.assertTrue(result['nativeUserProfiles'][0]['jsonObject'])
        self.assertEqual(result['nativeUserProfiles'][0]['unknownKeyCount'], 1)
        self.assertEqual(result['nativeUserProfiles'][0]['attributes'][0]['name'], 'OTHER')
        self.assertNotIn('PRIVATE', json.dumps(result))
        result = module.profile_diagnostic({'clients': [{'clientId': 'broker', 'attributes': {
            'client.secret.creation.time': 'PRIVATE'}}]}, ValueError('Unsupported client attributes refused'))
        self.assertEqual(result['clients'][0]['clientId'], 'broker')
        self.assertEqual(result['clients'][0]['knownAttributes'], ['client.secret.creation.time'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_native_default_profile_readback_normalizes_serialization_only_after_strict_review(self):
        module = self.module(); document = source(); kind = module.profile.USER_PROFILE_PROVIDER
        configuration = copy.deepcopy(module.profile.DEFAULT_USER_PROFILE)
        document['components'][kind] = [{'id': 'retained-profile', 'providerId': 'declarative-user-profile',
                                         'config': {'kc.user.profile.config': [json.dumps(configuration)]}}]
        candidate = module.profile.build_profile(document, realm='master', origin='https://id.example.test', acknowledge_master=True)
        before = copy.deepcopy(candidate); effective = copy.deepcopy(candidate)
        for attribute in configuration['attributes']: attribute['multivalued'] = False
        effective['components'][kind][0]['config']['kc.user.profile.config'] = [json.dumps(configuration, sort_keys=True, indent=2)]
        module.verify_effective(candidate, effective)
        self.assertEqual(candidate, before)
        configuration['attributes'][0]['permissions']['edit'] = ['user']
        effective['components'][kind][0]['config']['kc.user.profile.config'] = [json.dumps(configuration)]
        with self.assertRaises(ValueError): module.verify_effective(candidate, effective)

    def test_readback_preserves_master_profile_required_field_policy_variant(self):
        module = self.module(); document = source(); kind = module.profile.USER_PROFILE_PROVIDER
        configuration = copy.deepcopy(module.profile.DEFAULT_USER_PROFILE)
        document['components'][kind] = [{'id': 'profile', 'providerId': 'declarative-user-profile',
                                         'config': {'kc.user.profile.config': [json.dumps(configuration)]}}]
        candidate = module.profile.build_profile(document, realm='master', origin='https://id.example.test', acknowledge_master=True)
        effective = copy.deepcopy(candidate)
        for attribute in configuration['attributes']: attribute.pop('required', None)
        effective['components'][kind][0]['config']['kc.user.profile.config'] = [json.dumps(configuration)]
        with self.assertRaises(ValueError): module.verify_effective(candidate, effective)
        module.profile.reviewed_native_components(effective['components'], realm='master')
        relaxed_candidate = module.profile.build_profile({**document, 'components': effective['components']},
            realm='master', origin='https://id.example.test', acknowledge_master=True)
        module.verify_effective(relaxed_candidate, copy.deepcopy(relaxed_candidate))

    def test_owned_single_file_export_admits_only_pinned_supported_user_strategy_and_target(self):
        module = self.module(); directory = Path('/owned/fixture')
        arguments = ['export', '--realm', 'master', '--users', 'same_file', '--file', '/run/exchange/source.json']
        command = module.native_command(directory, 'export', 'master_retained', arguments)
        self.assertEqual(command[-len(arguments):], arguments)
        for index, value in ((4, 'realm_file'), (2, 'production'), (6, '/tmp/other.json')):
            invalid = list(arguments); invalid[index] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.native_command(directory, 'export', 'master_retained', invalid)

    def test_retained_snapshot_requires_same_credentials_ids_roles_and_original_audit_rows(self):
        module = self.module()
        before = {'users': ['u'], 'credentials': ['c'], 'roles': ['r'], 'events': ['e'], 'adminEvents': ['a']}
        after = {**before, 'events': ['e', 'e2'], 'adminEvents': ['a', 'a2']}
        module.verify_retained(before, after)
        for key in before:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.verify_retained(before, {**after, key: ['changed']})
