"""Publication boundaries and static architecture-diagram source contracts."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProductHandbookTest(unittest.TestCase):
    def test_internal_reviews_and_provider_evaluation_cannot_enter_product_search(self):
        spec = importlib.util.spec_from_file_location('docs_support', ROOT / 'tooling/documentation_support.py')
        support = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(support)
        for name in ('progress.md', 'evidence.md', 'identity-proofing-evaluation.md', 'documentation.md'):
            with self.subTest(name=name):
                self.assertFalse(support.publishable(name))
        self.assertTrue(support.publishable('integration-contract.md'))

    def diagram_support(self):
        filename = ROOT / 'tooling/documentation_diagrams.py'
        if not filename.exists():
            self.fail('Static diagram source extraction and publication are not implemented')
        spec = importlib.util.spec_from_file_location('diagram_support', filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_diagrams_extract_deterministically_without_treating_code_examples_as_figures(self):
        support = self.diagram_support()
        text = '# Sign in\n\n```mermaid\nsequenceDiagram\n  Browser->>Identity: Sign in\n```\n\n```sh\necho mermaid\n```\n'
        diagrams = support.extract(text, 'sign-in.md')
        self.assertEqual(1, len(diagrams))
        self.assertIn('Browser->>Identity', diagrams[0]['source'])
        self.assertEqual(diagrams, support.extract(text, 'sign-in.md'))
        self.assertNotEqual(diagrams[0]['id'], support.extract(text.replace('Sign in\n```', 'Return\n```'), 'sign-in.md')[0]['id'])

    def test_paired_static_figures_have_accessible_names_and_nested_local_asset_paths(self):
        support = self.diagram_support()
        text = '# Access <flow>\n\n```mermaid\nflowchart TD\n  A-->B\n```\n'
        rendered = support.replace(text, 'guide.md', 'guide/')
        self.assertNotIn('```mermaid', rendered)
        self.assertIn('../assets/diagrams/generated/', rendered)
        self.assertIn('diagram-light', rendered)
        self.assertIn('diagram-dark', rendered)
        self.assertIn('Access &lt;flow&gt;', rendered)
        self.assertNotIn('https://', rendered)

    def test_diagram_directives_cannot_override_strict_renderer_security(self):
        support = self.diagram_support()
        for text in ('```mermaid\n%%{init: {"securityLevel":"loose"}}%%\nflowchart TD\n A-->B\n```',
                     '```mermaid\n---\nconfig:\n securityLevel: loose\n---\nflowchart TD\n A-->B\n```'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                support.extract(text, 'guide.md')

    def test_message_semicolons_need_mermaid_entity_escaping(self):
        support = self.diagram_support()
        for kind in ('sequenceDiagram\n A->>B: Done; sign in', 'stateDiagram-v2\n A --> B: Verified; create'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                support.extract('```mermaid\n' + kind + '\n```', 'guide.md')
        self.assertEqual(1, len(support.extract('```mermaid\nsequenceDiagram\n A->>B: Done#59; sign in\n```', 'guide.md')))

    def test_static_figure_keeps_the_next_markdown_heading_outside_its_html_block(self):
        support = self.diagram_support()
        text = '# Flow\n\n```mermaid\nflowchart TD\n A-->B\n```\n\n## Configure the flow\n\nUse the settings.\n'
        result = support.replace(text, 'guide.md', 'guide/')
        self.assertIn('</figure>\n\n', result)
        self.assertIn('## Configure the flow', result)
