"""Offline privileged-profile behavior; no identity service or credentials are used."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source():
    return {
        'realm': 'master', 'enabled': True, 'sslRequired': 'all',
        'verifyEmail': True, 'eventsListeners': ['jboss-logging', 'firefly-native-recovery-invalidation'],
        'enabledEventTypes': ['LOGIN', 'LOGIN_ERROR', 'UPDATE_CREDENTIAL'],
        'clients': [{
            'clientId': client, 'enabled': client == 'security-admin-console',
            'protocol': 'openid-connect', 'publicClient': True,
            'standardFlowEnabled': client == 'security-admin-console',
            'directAccessGrantsEnabled': False, 'implicitFlowEnabled': False,
            'serviceAccountsEnabled': False, 'authorizationServicesEnabled': False,
            'authenticationFlowBindingOverrides': {},
            'attributes': {'pkce.code.challenge.method': 'S256'} if client == 'security-admin-console' else {},
            'redirectUris': ['https://id.example.test/admin/master/console/*'] if client == 'security-admin-console' else [],
            'webOrigins': ['https://id.example.test'] if client == 'security-admin-console' else [],
            'defaultClientScopes': [], 'optionalClientScopes': [],
        } for client in ('account', 'account-console', 'admin-cli', 'broker', 'realm-management', 'security-admin-console')],
        'identityProviders': [], 'identityProviderMappers': [], 'userFederationProviders': [], 'components': {},
        'users': [{'id': 'named-admin', 'username': 'named-admin', 'enabled': True,
                   'emailVerified': True, 'requiredActions': [], 'credentials': [{'type': 'password'}, {'type': 'webauthn'}]}],
        'roles': {'realm': [{'name': 'admin'}]},
    }


class PrivilegedProfileTest(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'tooling/privileged_profile.py'
        self.assertTrue(path.is_file(), 'Offline privileged profile is not implemented')
        spec = importlib.util.spec_from_file_location('privileged_profile', path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def candidate(self, value=None, acknowledge_master=True):
        return self.module.build_profile(value or source(), realm='master', origin='https://id.example.test',
                                         acknowledge_master=acknowledge_master)

    def test_complete_candidate_preserves_accounts_roles_and_clients_without_mutating_input(self):
        original = source()
        before = copy.deepcopy(original)
        result = self.candidate(original)
        self.assertEqual(original, before)
        for key in ('users', 'roles', 'clients', 'eventsListeners', 'enabledEventTypes'):
            self.assertEqual(result[key], before[key])
        self.module.validate_profile(result, realm='master', origin='https://id.example.test')
        self.assertEqual(result['webAuthnPolicyUserVerificationRequirement'], 'required')
        self.assertFalse(result['webAuthnPolicyPasswordlessPasskeysEnabled'])

    def test_real_master_internal_role_resource_preserves_inert_standard_flow_default(self):
        document = source()
        resource = next(client for client in document['clients'] if client['clientId'] == 'realm-management')
        resource.update(clientId='master-realm', enabled=True, publicClient=False, bearerOnly=True,
                        standardFlowEnabled=True, attributes={'realm_client': 'true'})
        document['roles']['client'] = {'master-realm': [{'name': 'view-realm'}, {'name': 'manage-realm'}]}
        candidate = self.candidate(document)
        self.assertEqual(candidate['clients'], document['clients'])
        self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')
        native = copy.deepcopy(document)
        del next(client for client in native['clients'] if client['clientId'] == 'master-realm')['protocol']
        self.assertEqual(self.candidate(native)['clients'], native['clients'])
        for client in (native['clients'][0], native['clients'][-1]):
            original = client.pop('protocol')
            with self.assertRaises(ValueError): self.candidate(native)
            client['protocol'] = original
        for mutation in ({'bearerOnly': False}, {'publicClient': True}, {'directAccessGrantsEnabled': True},
                         {'authenticationFlowBindingOverrides': {'browser': 'weak'}}, {'attributes': {}},
                         {'clientId': 'masquerading-realm'}):
            invalid = copy.deepcopy(document)
            next(client for client in invalid['clients'] if client['clientId'] == 'master-realm').update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.candidate(invalid)

    def test_master_requires_explicit_acknowledgment_and_exact_target(self):
        with self.assertRaises(ValueError):
            self.candidate(acknowledge_master=False)
        with self.assertRaises(ValueError):
            self.module.build_profile(source(), realm='other', origin='https://id.example.test')

    def test_native_export_defaults_are_preserved_without_enabling_alternate_authority(self):
        document = source()
        document['scimApiEnabled'] = False
        document['attributes'] = {'cibaBackchannelTokenDeliveryMode': 'poll', 'cibaExpiresIn': '120',
                                  'cibaInterval': '5', 'cibaAuthRequestedUserHint': 'login_hint',
                                  'oauth2DeviceCodeLifespan': '600', 'oauth2DevicePollingInterval': '5',
                                  'parRequestUriLifespan': '60'}
        before = copy.deepcopy(document)
        candidate = self.candidate(document)
        self.assertEqual(document, before)
        self.assertEqual(candidate['attributes'], dict(document['attributes'], **{
            'firefly.privileged-administration': self.module.PROFILE}))
        self.assertIs(candidate['scimApiEnabled'], False)
        self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')
        for field, value in [('scimApiEnabled', True), ('scimApiEnabled', 'false')]:
            invalid = copy.deepcopy(document); invalid[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.candidate(invalid)
        for key in document['attributes']:
            invalid = copy.deepcopy(document); invalid['attributes'][key] = 'unreviewed'
            with self.subTest(attribute=key), self.assertRaises(ValueError): self.candidate(invalid)
        for key in ('oidc.ciba.grant.enabled', 'oauth2.device.authorization.grant.enabled'):
            invalid = copy.deepcopy(document); invalid['clients'][-1]['attributes'][key] = 'true'
            with self.subTest(grant=key), self.assertRaises(ValueError): self.candidate(invalid)

    def test_native_registration_policies_preserve_complete_exact_controls(self):
        self.assertTrue(hasattr(self.module, 'DEFAULT_REGISTRATION_POLICIES'))
        document = source(); kind = self.module.REGISTRATION_POLICY_PROVIDER
        policies = [{**copy.deepcopy(value), 'id': 'policy-' + str(i)}
                    for i, value in enumerate(self.module.DEFAULT_REGISTRATION_POLICIES)]
        document['components'][kind] = policies
        self.assertEqual(self.candidate(document)['components'], document['components'])
        for mutation in ('missing', 'duplicate', 'subtype', 'config', 'provider'):
            invalid = copy.deepcopy(document); values = invalid['components'][kind]
            if mutation == 'missing': values.pop()
            elif mutation == 'duplicate': values.append(copy.deepcopy(values[0]))
            elif mutation == 'subtype': values[0]['subType'] = 'authenticated'
            elif mutation == 'config': values[0]['config']['host-sending-registration-request-must-match'] = ['false']
            else: values[0]['providerId'] = 'extension'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.candidate(invalid)
        policies[0]['config']['trusted-hosts'] = []
        self.candidate(document)
        policies[0]['config']['trusted-hosts'] = ['unreviewed.example']
        with self.assertRaises(ValueError): self.candidate(document)

    def test_enabled_client_bypasses_and_unsupported_extensions_are_refused_without_repair(self):
        mutations = [
            ('directAccessGrantsEnabled', True), ('implicitFlowEnabled', True),
            ('serviceAccountsEnabled', True), ('authorizationServicesEnabled', True),
            ('protocol', 'saml'), ('authenticationFlowBindingOverrides', {'browser': 'weak'}),
            ('attributes', {'oauth2.device.authorization.grant.enabled': 'true'}),
            ('attributes', {'oidc.ciba.grant.enabled': 'true'}),
            ('attributes', {'standard.token.exchange.enabled': 'true'}),
            ('attributes', {'unknown.extension': 'true'}),
            ('redirectUris', ['https://other.example.test/*']), ('webOrigins', ['*']),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                document = source(); document['clients'][-1][key] = value
                before = copy.deepcopy(document)
                with self.assertRaises(ValueError):
                    self.candidate(document)
                self.assertEqual(document, before)

    def test_native_secret_creation_metadata_is_preserved_only_for_disabled_broker(self):
        document = source()
        broker = next(client for client in document['clients'] if client['clientId'] == 'broker')
        broker['attributes']['client.secret.creation.time'] = '1793510000'
        before = copy.deepcopy(document)
        self.assertEqual(self.candidate(document)['clients'], before['clients'])
        self.assertEqual(document, before)
        native = copy.deepcopy(document); del native['clients'][3]['authorizationServicesEnabled']
        self.assertEqual(self.candidate(native)['clients'], native['clients'])
        for timestamp in ('', '0', '-1', '01', '1.5', '2147483648', 1793510000, True, None, 'unreviewed'):
            invalid = copy.deepcopy(document)
            invalid['clients'][3]['attributes']['client.secret.creation.time'] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError): self.candidate(invalid)
        for key in ('enabled', 'standardFlowEnabled', 'implicitFlowEnabled', 'directAccessGrantsEnabled',
                    'serviceAccountsEnabled', 'authorizationServicesEnabled'):
            for value in (True, None):
                invalid = copy.deepcopy(document); invalid['clients'][3][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.candidate(invalid)
        invalid = source(); invalid['clients'][0]['attributes']['client.secret.creation.time'] = '1793510000'
        with self.assertRaises(ValueError): self.candidate(invalid)
        for key in ('client.secret.rotated', 'client.secret.expiration.time', 'unknown.extension'):
            invalid = copy.deepcopy(document); invalid['clients'][3]['attributes'][key] = '1793510000'
            with self.subTest(key=key), self.assertRaises(ValueError): self.candidate(invalid)

    def test_missing_builtin_clients_or_unknown_enabled_clients_refuse(self):
        for mutation in ('missing', 'extra', 'duplicate'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                document = source()
                if mutation == 'missing': document['clients'].pop(0)
                elif mutation == 'extra': document['clients'].append({'clientId': 'bypass', 'enabled': True})
                else: document['clients'].append(copy.deepcopy(document['clients'][0]))
                self.candidate(document)

    def test_actual_flow_shape_cannot_gain_cookie_otp_broker_or_enrollment(self):
        for authenticator in ('auth-cookie', 'auth-otp-form', 'identity-provider-redirector', 'webauthn-authenticator'):
            with self.subTest(authenticator=authenticator), self.assertRaises(ValueError):
                candidate = self.candidate()
                candidate['authenticationFlows'][0]['authenticationExecutions'][1]['authenticator'] = authenticator
                self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')
        for mutation in ('alternative', 'extra', 'reverse', 'subflow'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                candidate = self.candidate(); steps = candidate['authenticationFlows'][0]['authenticationExecutions']
                if mutation == 'alternative': steps[1]['requirement'] = 'ALTERNATIVE'
                elif mutation == 'extra': steps.append(copy.deepcopy(steps[0]))
                elif mutation == 'reverse': steps.reverse()
                else: steps[1]['authenticatorFlow'] = True
                self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')

    def test_realm_registration_reset_passwordless_and_required_action_bypasses_refuse(self):
        mutations = [('registrationAllowed', True), ('resetPasswordAllowed', True),
                     ('webAuthnPolicyPasswordlessPasskeysEnabled', True),
                     ('webAuthnPolicyUserVerificationRequirement', 'preferred'),
                     ('browserFlow', 'browser'), ('directGrantFlow', 'direct grant'),
                     ('registrationFlow', 'registration'), ('resetCredentialsFlow', 'reset credentials'),
                     ('identityProviders', [{'alias': 'external'}]), ('attributes', {'unknown': 'true'})]
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(ValueError):
                candidate = self.candidate(); candidate[key] = value
                self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')
        candidate = self.candidate(); candidate['requiredActions'][0]['enabled'] = True
        with self.assertRaises(ValueError):
            self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')

    def test_enrollment_is_a_prerequisite_not_something_generator_can_invent(self):
        for mutation in ('passwordless', 'missing-key', 'required-action', 'federated', 'service-account'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                document = source(); user = document['users'][0]
                if mutation == 'passwordless': user['credentials'][1]['type'] = 'webauthn-passwordless'
                elif mutation == 'missing-key': user['credentials'].pop()
                elif mutation == 'required-action': user['requiredActions'] = ['webauthn-register']
                elif mutation == 'federated': user['federationLink'] = 'external'
                else: user['serviceAccountClientId'] = 'service'
                self.candidate(document)

    def test_separate_admin_origin_changes_no_identity_rp_or_existing_client(self):
        document = source()
        document['clients'][-1]['redirectUris'] = ['https://admin.example.test/admin/master/console/*']
        document['clients'][-1]['webOrigins'] = ['https://admin.example.test']
        candidate = self.module.build_profile(document, realm='master', origin='https://id.example.test',
                                              admin_origin='https://admin.example.test', acknowledge_master=True)
        self.assertEqual(candidate['clients'], document['clients'])
        self.assertEqual(candidate['webAuthnPolicyRpId'], 'id.example.test')
        self.module.validate_profile(candidate, realm='master', origin='https://id.example.test',
                                     admin_origin='https://admin.example.test')

    def test_unknown_listeners_unverified_email_and_unsafe_origins_are_refused(self):
        for field, value in [('eventsListeners', ['unknown']), ('verifyEmail', False)]:
            document = source(); document[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.candidate(document)
        document = source(); document['users'][0]['emailVerified'] = False
        with self.assertRaises(ValueError): self.candidate(document)
        for origin in ('https://@id.example.test', 'https://id.example.test:bad',
                       'https://id.example.test:65536', 'https://id.example.test\\other',
                       'https://id.example.test\n', 'https://id.example.test:'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.module.build_profile(source(), realm='master', origin=origin, acknowledge_master=True)

    def test_generator_refuses_owned_custom_flows_instead_of_erasing_them(self):
        for addition in ({'authenticationFlows': [{'alias': 'custom', 'providerId': 'basic-flow',
                         'authenticationExecutions': [{'authenticator': 'organization-custom-login'}]}]},
                         {'authenticatorConfig': [{'alias': 'owned', 'config': {'policy': 'retain'}}]}):
            document = source(); document.update(addition)
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                self.candidate(document)

    def test_known_inactive_builtin_flows_and_client_authentication_are_preserved(self):
        document = source()
        document['authenticationFlows'] = [{'alias': 'clients', 'providerId': 'client-flow', 'topLevel': True,
                                             'builtIn': True, 'authenticationExecutions': [
                {'authenticator': 'client-secret', 'authenticatorFlow': False, 'requirement': 'ALTERNATIVE', 'priority': 10}]}]
        document['clientAuthenticationFlow'] = 'clients'
        document['authenticatorConfig'] = [{'alias': 'browser-conditional-credential',
                                             'config': {'credentials': 'webauthn-passwordless'}}]
        candidate = self.candidate(document)
        self.assertEqual(candidate['authenticationFlows'][2:], document['authenticationFlows'])
        self.assertEqual(candidate['clientAuthenticationFlow'], 'clients')
        self.assertEqual(candidate['authenticatorConfig'], document['authenticatorConfig'])
        self.module.validate_profile(candidate, realm='master', origin='https://id.example.test')

    def test_reviewed_keycloak_26_8_export_policy_fields_are_preserved(self):
        document = source()
        document.update(defaultSignatureAlgorithm='RS256', maxSecondaryAuthFailures=0, otpPolicyCodeReusable=False,
                        localizationTexts={}, webAuthnPolicyPasswordlessMediation='conditional')
        candidate = self.candidate(document)
        for key in ('defaultSignatureAlgorithm', 'maxSecondaryAuthFailures', 'otpPolicyCodeReusable',
                    'localizationTexts', 'webAuthnPolicyPasswordlessMediation'):
            self.assertEqual(candidate[key], document[key])

    def test_actual_user_managed_access_export_field_is_supported_only_when_disabled(self):
        document = source(); document['userManagedAccessAllowed'] = False
        self.assertFalse(self.candidate(document)['userManagedAccessAllowed'])
        document['userManagedAccessAllowed'] = True
        with self.assertRaises(ValueError): self.candidate(document)

    def test_native_default_user_profile_is_preserved_but_custom_profiles_are_refused(self):
        provider = 'org.keycloak.userprofile.UserProfileProvider'
        document = source()
        document['components'][provider] = [{'id': 'retained-profile', 'providerId': 'declarative-user-profile', 'config': {}}]
        self.assertEqual(self.candidate(document)['components'], document['components'])
        import json
        default = copy.deepcopy(self.module.DEFAULT_USER_PROFILE)
        document['components'][provider][0]['config'] = {'kc.user.profile.config': [json.dumps(default)]}
        self.assertEqual(self.candidate(document)['components'], document['components'])
        for mutation in ({'providerId': 'custom-profile'}, {'config': {'custom-setting': ['true']}},
                         {'subComponents': {'custom': [{}]}}):
            invalid = copy.deepcopy(document); invalid['components'][provider][0].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.candidate(invalid)
        default['attributes'][0]['permissions']['edit'] = ['user']
        document['components'][provider][0]['config']['kc.user.profile.config'] = [json.dumps(default)]
        with self.assertRaises(ValueError): self.candidate(document)

    def test_native_master_profile_relaxes_only_builtin_required_fields_and_normalizes_role_sets(self):
        import json
        kind = self.module.USER_PROFILE_PROVIDER
        configuration = copy.deepcopy(self.module.DEFAULT_USER_PROFILE)
        for attribute in configuration['attributes']:
            if attribute['name'] != 'username': attribute.pop('required', None)
            attribute['permissions']['view'].reverse(); attribute['permissions']['edit'].reverse()
        component = {'providerId': 'declarative-user-profile', 'config': {'kc.user.profile.config': [json.dumps(configuration)]}}
        document = source(); document['components'][kind] = [component]
        self.assertEqual(self.candidate(document)['components'], document['components'])
        with self.assertRaises(ValueError): self.module.reviewed_native_components(document['components'], realm='workforce')
        configuration['attributes'][0]['permissions']['view'].append('admin')
        component['config']['kc.user.profile.config'] = [json.dumps(configuration)]
        with self.assertRaises(ValueError): self.candidate(document)

    def test_nonstandard_json_numbers_are_refused(self):
        for number in ('NaN', 'Infinity', '-Infinity'):
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.module.parse_document('{"invalid":' + number + '}')

    def test_duplicate_json_properties_are_refused(self):
        with self.assertRaises(ValueError):
            self.module.parse_document('{"realm":"master","realm":"other"}')


if __name__ == '__main__':
    unittest.main()
