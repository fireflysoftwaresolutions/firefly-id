"""Reject incomplete or unsafe packaged diagram output without a browser dependency."""
import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('diagram_output', ROOT / 'tooling/validate_documentation.py')
output = importlib.util.module_from_spec(spec)
spec.loader.exec_module(output)


class DiagramOutputTest(unittest.TestCase):
    font = b'canonical-test-font'

    def svg(self, extra=''):
        encoded = base64.b64encode(self.font).decode()
        return ('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="80" viewBox="0 0 100 80" '
                'style="background-color: rgb(39, 40, 32);" aria-labelledby="title">'
                '<title id="title">Recovery</title><style>@font-face{font-family:Manrope;'
                f'src:url(data:font/woff2;base64,{encoded})}}</style>'
                '<text x="5" y="20">Recover access</text>' + extra + '</svg>')

    def check_svg(self, source):
        self.assertTrue(hasattr(output, 'validate_svg'), 'Packaged SVG validation is missing')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'example-dark.svg'
            path.write_text(source)
            return output.validate_svg(path, self.font, mode='dark')

    def test_packaged_svg_checks_its_actual_font_and_standalone_background(self):
        self.assertEqual([], self.check_svg(self.svg()))
        self.assertTrue(self.check_svg(self.svg().replace('rgb(39, 40, 32)', 'transparent')))
        self.assertTrue(self.check_svg(self.svg().replace(base64.b64encode(self.font).decode(), 'bm90LXRoZS1mb250')))

    def test_empty_invalid_or_executable_svg_cannot_pass_structure_check(self):
        for source in (self.svg().replace('100 80', '0 80'), self.svg().replace('100 80', 'NaN 80'),
                       self.svg().replace('<text x="5" y="20">Recover access</text>', ''),
                       self.svg('<script>alert(1)</script>'), self.svg('<g onclick="doSomething()"/>'),
                       self.svg('<image href="https://example.invalid/tracker.svg"/>'),
                       self.svg().replace('</svg>', '')):
            with self.subTest(source=source):
                self.assertTrue(self.check_svg(source))

    def test_exported_svg_dimensions_cannot_depend_on_the_viewer_viewport(self):
        self.assertTrue(self.check_svg(self.svg().replace('width="100" height="80"', 'width="100%"')))
        self.assertTrue(self.check_svg(self.svg().replace('height="80"', 'height="1200"')))

    def test_inventory_detects_missing_mode_or_stale_diagram(self):
        self.assertTrue(hasattr(output, 'validate_diagram_inventory'), 'Diagram inventory validation is missing')
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'a-light.svg').write_text(self.svg())
            (folder / 'stale-dark.svg').write_text(self.svg())
            failures = output.validate_diagram_inventory(folder, [{'id': 'a'}])
            self.assertTrue(any('a-dark.svg' in failure for failure in failures))
            self.assertTrue(any('stale-dark.svg' in failure for failure in failures))
            (folder / 'a-dark.svg').write_text(self.svg())
            self.assertTrue(output.validate_diagram_inventory(folder, [{'id': 'a'}]))
            (folder / 'stale-light.svg').write_text(self.svg())
            self.assertEqual([], output.validate_diagram_inventory(folder, [{'id': 'a'}, {'id': 'stale'}]))
