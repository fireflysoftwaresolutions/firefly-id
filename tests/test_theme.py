import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ThemePackagingTest(unittest.TestCase):
    def test_supported_parents_and_protocol_templates_are_inherited(self):
        for kind, parent in {"login": "keycloak.v2", "account": "keycloak.v3", "admin": "keycloak.v2", "email": "base", "welcome": "keycloak"}.items():
            props = (ROOT / "themes/firefly-id" / kind / "theme.properties").read_text()
            self.assertIn(f"parent={parent}\n", props)
        for page in ("login.ftl", "register.ftl", "login-reset-password.ftl", "login-otp.ftl", "webauthn-authenticate.ftl"):
            self.assertFalse((ROOT / "themes/firefly-id/login" / page).exists())

    def test_archive_is_reproducible_and_contains_self_hosted_assets(self):
        spec = importlib.util.spec_from_file_location("build_theme", ROOT / "tooling/build_theme.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            first = builder.build(output).read_bytes()
            second = builder.build(output).read_bytes()
            self.assertEqual(first, second)
            with zipfile.ZipFile(output / "firefly-id-theme.jar") as archive:
                names = archive.namelist()
                self.assertIn("META-INF/keycloak-themes.json", names)
                for kind in ("login", "account", "admin"):
                    self.assertIn(f"theme/firefly-id/{kind}/resources/img/wordmark-light.svg", names)
                    self.assertIn(f"theme/firefly-id/{kind}/resources/fonts/manrope.woff2", names)
                self.assertNotIn(".env", names)
                for variant in ("light", "dark", "mobile-light", "mobile-dark"):
                    self.assertIn(f"theme/firefly-id/login/resources/img/authentication-{variant}.svg", names)
                self.assertEqual(archive.testzip(), None)

    def test_email_layout_preserves_nested_server_generated_action(self):
        layout = (ROOT / "themes/firefly-id/email/html/template.ftl").read_text()
        self.assertIn("<#nested>", layout)
        self.assertNotIn("http://", layout)
        self.assertIn('${locale.language}', layout)
        self.assertIn("Firefly Identity", layout)


if __name__ == "__main__":
    unittest.main()
