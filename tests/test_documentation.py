"""Documentation publication contracts, independent of MkDocs dependencies."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DocumentationTest(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'tooling/documentation_support.py'
        if not path.exists():
            self.fail('Documentation source mapping and catalogue rendering are not implemented')
        spec = importlib.util.spec_from_file_location('documentation_support', path)
        self.support = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.support)

    def test_source_links_preserve_revision_fragment_and_reader_relative_links(self):
        rewrite = self.support.rewrite_target
        base = 'https://github.com/example/identity/blob/' + 'a' * 40
        self.assertEqual(rewrite('../config/authentication-policies.json#profiles', 'security.md', ROOT, base),
                         base + '/config/authentication-policies.json#profiles')
        self.assertEqual(rewrite('security.md#protocol-and-secrets', 'index.md', ROOT, base),
                         'security.md#protocol-and-secrets')
        self.assertEqual(rewrite('https://www.keycloak.org/docs/', 'index.md', ROOT, base),
                         'https://www.keycloak.org/docs/')

    def test_internal_plans_link_to_source_without_entering_published_handbook(self):
        base = 'https://github.com/example/identity/blob/' + 'b' * 40
        target = 'superpowers/specs/2026-11-01-identity-documentation-design.md'
        self.assertFalse(self.support.publishable(target))
        self.assertEqual(self.support.rewrite_target(target, 'index.md', ROOT, base),
                         base + '/docs/' + target)
        for path in ['.state/credentials.json', '.work/summary.json', 'overrides/main.html']:
            self.assertFalse(self.support.publishable(path))

    def test_invalid_source_paths_fail_instead_of_producing_unverified_links(self):
        base = 'https://github.com/example/identity/blob/' + 'c' * 40
        for target in ['../../outside', '../.state/credentials.json', '../missing-source.json']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.support.rewrite_target(target, 'index.md', ROOT, base)

    def test_canonical_images_resolve_locally_from_nested_pages(self):
        target = '../../assets/brand/firefly-id-dark.svg'
        self.assertEqual(self.support.rewrite_target(target, 'guide/brand.md', ROOT, 'https://example.invalid/source', image=True),
                         '../assets/brand/firefly-id-dark.svg')

    def test_repository_directories_use_tree_links(self):
        base = 'https://github.com/example/identity/blob/' + 'd' * 40
        self.assertEqual(self.support.rewrite_target('../examples/jafly/', 'index.md', ROOT, base),
                         base.replace('/blob/', '/tree/') + '/examples/jafly')

    def test_catalogue_reference_changes_with_source_and_keeps_mfa_scope(self):
        catalogue = json.loads((ROOT / 'config/authentication-policies.json').read_text())
        catalogue['profiles']['customers']['realmSettings']['passwordPolicy'] = 'length(22) and maxLength(128)'
        result = self.support.policy_reference(catalogue)
        self.assertIn('length(22) and maxLength(128)', result)
        self.assertIn('`failureFactor` | `3`', result)
        self.assertIn('Optional in the synthetic customer profile', result)
        self.assertIn('Required password and OTP in the workforce browser flow', result)
        self.assertIn('permanent administrator', result)
        self.assertIn('not a regulatory certification', result)

    def test_unknown_catalogue_schema_cannot_publish_a_misleading_reference(self):
        with self.assertRaises(ValueError):
            self.support.policy_reference({'schemaVersion': 99})

    def test_uncommitted_preview_is_not_publishable_exact_source_evidence(self):
        if not hasattr(self.support, 'source_provenance'):
            self.fail('Uncommitted source is not distinguished from a publishable revision')
        result = self.support.source_provenance('a' * 40, None, True)
        self.assertTrue(result['source_dirty'])
        self.assertFalse(result['publication_ready'])
        self.assertTrue(self.support.source_provenance('a' * 40, 'a' * 40, False)['publication_ready'])

    def test_requested_source_cannot_impersonate_another_checkout_revision(self):
        if not hasattr(self.support, 'source_provenance'):
            self.fail('An environment revision can still mislabel the source checkout')
        with self.assertRaises(ValueError):
            self.support.source_provenance('a' * 40, 'b' * 40, False)
