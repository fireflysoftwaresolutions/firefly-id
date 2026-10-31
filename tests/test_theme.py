import importlib.util
import hashlib
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ThemePackagingTest(unittest.TestCase):
    def test_bilingual_messages_preserve_placeholders_and_generic_signin_failures(self):
        bundles = {}
        for kind in ("login", "email", "account", "admin"):
            bundles[kind] = {}
            for locale in ("en", "es"):
                source = ROOT / "themes/firefly-id" / kind / "messages" / f"messages_{locale}.properties"
                messages = dict(line.split("=", 1) for line in source.read_text().splitlines()
                                if line and not line.startswith("#"))
                bundles[kind][locale] = messages
            for key, english in bundles[kind]["en"].items():
                with self.subTest(kind=kind, key=key):
                    self.assertIn(key, bundles[kind]["es"])
                    self.assertEqual(sorted(re.findall(r"\{\d+\}", english)),
                                     sorted(re.findall(r"\{\d+\}", bundles[kind]["es"][key])))
        errors = ("invalidUserMessage", "invalidUsernameMessage", "invalidUsernameOrEmailMessage",
                  "invalidPasswordMessage", "accountDisabledMessage", "accountTemporarilyDisabledMessage",
                  "accountPermanentlyDisabledMessage", "invalidTotpMessage",
                  "accountTemporarilyDisabledMessageTotp", "accountPermanentlyDisabledMessageTotp")
        for locale in ("en", "es"):
            messages = bundles["login"][locale]
            self.assertEqual({messages[key] for key in errors}, {messages["invalidUserMessage"]})
            self.assertNotRegex(messages["invalidUserMessage"], r"\d|\{\d+\}")

    def test_generic_error_presentation_preserves_the_exact_upstream_protocol_template(self):
        template = (ROOT / "themes/firefly-id/login/template.ftl").read_text()
        header, body = template.split('\n', 1)
        self.assertIn('Keycloak 26.8.1', header)
        generic_branch = '''        <#if pageId == "login" && ((message?? && message.type == 'error') || messagesPerField.existsError('username','password'))>
            <div class="${properties.kcAlertClass!} pf-m-danger" role="alert" id="ffid-signin-error">
                <div class="${properties.kcAlertIconClass!}">
                    <span class="${properties.kcFeedbackErrorIcon!}"></span>
                </div>
                <span class="${properties.kcAlertTitleClass!} kc-feedback-text">${msg("invalidUserMessage")}</span>
            </div>
        <#elseif displayMessage'''
        self.assertEqual(body.count(generic_branch), 1)
        upstream = body.replace(generic_branch, '        <#if displayMessage')
        upstream = upstream.replace('kc-login-tooltip" type="button"\n', 'kc-login-tooltip" type="button" \n')
        self.assertEqual(hashlib.sha256(upstream.encode()).hexdigest(),
                         '6221a3176c73a3fd67abc97076deb9cef112378ce157735a78bd865800315b37')

    def test_password_fields_are_masked_without_a_visibility_control(self):
        fields = (ROOT / "themes/firefly-id/login/field.ftl").read_text()
        self.assertIn('type="password"', fields)
        self.assertNotIn('data-password-toggle', fields)
        self.assertIn('autocomplete="${autocomplete}"', fields)
        self.assertIn('url.loginResetCredentialsUrl', fields)
        self.assertEqual(fields.count('<#local error="">'), 2)

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
