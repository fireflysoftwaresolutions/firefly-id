"""Offline ownership, exact-candidate and effective-control boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
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

    def test_retained_snapshot_requires_same_credentials_ids_roles_and_original_audit_rows(self):
        module = self.module()
        before = {'users': ['u'], 'credentials': ['c'], 'roles': ['r'], 'events': ['e'], 'adminEvents': ['a']}
        after = {**before, 'events': ['e', 'e2'], 'adminEvents': ['a', 'a2']}
        module.verify_retained(before, after)
        for key in before:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.verify_retained(before, {**after, key: ['changed']})
