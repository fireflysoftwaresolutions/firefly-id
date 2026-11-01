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

    def test_master_requires_explicit_acknowledgment_and_exact_target(self):
        with self.assertRaises(ValueError):
            self.candidate(acknowledge_master=False)
        with self.assertRaises(ValueError):
            self.module.build_profile(source(), realm='other', origin='https://id.example.test')

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

    def test_nonstandard_json_numbers_are_refused(self):
        for number in ('NaN', 'Infinity', '-Infinity'):
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.module.parse_document('{"invalid":' + number + '}')

    def test_duplicate_json_properties_are_refused(self):
        with self.assertRaises(ValueError):
            self.module.parse_document('{"realm":"master","realm":"other"}')


if __name__ == '__main__':
    unittest.main()
