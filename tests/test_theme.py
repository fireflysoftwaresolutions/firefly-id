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

    def test_presentation_changes_preserve_the_exact_upstream_protocol_template(self):
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
        upstream_locale_header = '''        <#if realm.internationalizationEnabled  && locale.supported?size gt 1>
        <div class="${properties.kcLoginMainHeaderUtilities!}">
          <div class="${properties.kcInputClass!}">
            <select
              aria-label="${msg("languages")}"
              id="login-select-toggle"
              onchange="if (this.value) window.location.href=this.value"
            >
              <#list locale.supported?sort_by("label") as l>
                <option
                  value="${l.url}"
                  ${(l.languageTag == locale.currentLanguageTag)?then('selected','')}
                >
                  ${l.label}
                </option>
              </#list>
            </select>
            <span class="${properties.kcFormControlUtilClass}">
              <span class="${properties.kcFormControlToggleIcon!}">
                <svg
                  class="pf-v5-svg"
                  viewBox="0 0 320 512"
                  fill="currentColor"
                  aria-hidden="true"
                  role="img"
                  width="1em"
                  height="1em"
                >
                  <path
                    d="M31.3 192h257.3c17.8 0 26.7 21.5 14.1 34.1L174.1 354.8c-7.8 7.8-20.5 7.8-28.3 0L17.2 226.1C4.6 213.5 13.5 192 31.3 192z"
                  >
                  </path>
                </svg>
              </span>
            </span>
          </div>
        </div>
        </#if>
'''
        heading = '        <h1 class="${properties.kcLoginMainTitle!}" id="kc-page-title"><#nested "header"></h1>\n'
        self.assertEqual(upstream.count(heading), 1)
        self.assertNotIn('login-select-toggle', body)
        upstream = upstream.replace(heading, heading + upstream_locale_header)
        upstream = upstream.replace('kc-login-tooltip" type="button"\n', 'kc-login-tooltip" type="button" \n')
        upstream = upstream.replace('class="ffid-icon ffid-icon--sync"', 'class="fa-sync-alt fas"')
        self.assertEqual(hashlib.sha256(upstream.encode()).hexdigest(),
                         '6221a3176c73a3fd67abc97076deb9cef112378ce157735a78bd865800315b37')

    def test_footer_keeps_native_server_generated_language_choices(self):
        footer = (ROOT / "themes/firefly-id/login/footer.ftl").read_text()
        self.assertEqual(footer.count('id="login-select-toggle"'), 1)
        self.assertIn('aria-label="${msg("languages")}"', footer)
        self.assertIn('locale.supported?sort_by("label")', footer)
        self.assertIn('value="${l.url}"', footer)
        self.assertIn("(l.languageTag == locale.currentLanguageTag)?then('selected','')", footer)
        self.assertIn('onchange="if (this.value) window.location.href=this.value"', footer)
        self.assertLess(footer.index("ffidCopyright"), footer.index('id="login-select-toggle"'))
        self.assertNotIn('<form', footer)
        self.assertNotIn('navigator.', footer)

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
            self.assertEqual((output / "themes/firefly-id/LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())
            self.assertEqual((output / "themes/firefly-id/NOTICE").read_bytes(), (ROOT / "NOTICE").read_bytes())
            with zipfile.ZipFile(output / "firefly-id-theme.jar") as archive:
                names = archive.namelist()
                self.assertIn("META-INF/keycloak-themes.json", names)
                self.assertIn("META-INF/LICENSE", names)
                self.assertIn("META-INF/NOTICE", names)
                self.assertIn("META-INF/licenses/lucide-ISC-MIT.txt", names)
                for kind in ("login", "account", "admin"):
                    self.assertIn(f"theme/firefly-id/{kind}/resources/css/firefly-tokens.css", names)
                    self.assertIn(f"theme/firefly-id/{kind}/resources/img/icons/16/error.svg", names)
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

    def test_packaged_footers_recognize_keycloak_without_losing_firefly_copyright(self):
        spec = importlib.util.spec_from_file_location("build_theme", ROOT / "tooling/build_theme.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            with zipfile.ZipFile(builder.build(Path(directory))) as archive:
                for path in ("login/footer.ftl", "email/html/template.ftl", "welcome/index.ftl"):
                    footer = archive.read("theme/firefly-id/" + path).decode()
                    self.assertIn('href="https://www.keycloak.org"', footer)
                    self.assertRegex(footer, r"ffidCopyright|© 2026 Firefly Software Foundation Inc\.")
                for kind in ("account", "admin"):
                    script = archive.read(f"theme/firefly-id/{kind}/resources/js/copyright.js").decode()
                    self.assertIn("https://www.keycloak.org", script)
                    self.assertIn("© 2026 Firefly Software Foundation Inc.", script)
                    self.assertIn("Powered by Keycloak", script)
                    self.assertIn("Con tecnología de Keycloak", script)
                for locale, label in (("en", "Powered by Keycloak"), ("es", "Con tecnología de Keycloak")):
                    for kind in ("login", "email"):
                        source = archive.read(f"theme/firefly-id/{kind}/messages/messages_{locale}.properties").decode()
                        messages = dict(line.split("=", 1) for line in source.splitlines()
                                        if line and not line.startswith("#"))
                        self.assertEqual(messages["ffidPoweredBy"], label)
                        if kind == "email":
                            bodies = [value for value in messages.values()
                                      if "© 2026 Firefly Software Foundation Inc." in value]
                            self.assertTrue(bodies)
                            for body in bodies:
                                self.assertIn(label, body)
                                self.assertIn("https://www.keycloak.org", body)


if __name__ == "__main__":
    unittest.main()
