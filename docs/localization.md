# English and Spanish

Firefly Identity supports English (`en`) and Spanish (`es`), with English as the default. Newly generated sandbox realms enable internationalization and advertise both languages. The login theme uses Keycloak's inherited language selector, locale resolution, and server-generated navigation links. Applications can request a language through the standard OIDC `ui_locales` parameter, for example `ui_locales=es`. Users can choose English or Español on the authentication screens.

The theme declares both languages for login, email, account, administration, and welcome. Authentication pages retain the pinned Keycloak 26.8.1 protocol templates. Their inherited Spanish bundle supplies form fields, buttons, recovery, authenticator challenges and enrollment, passkeys, recovery codes, required actions, logout, and session-expiry text. Firefly overrides translate the product copy, screen titles, permanent-lock warning, and generic authentication and recovery responses. Every customized English authentication message has a Spanish counterpart.

The warning appears before the shared authentication form content in either language. It explains that repeated unsuccessful sign-in attempts permanently block access and require secure recovery. Neither language displays a failure counter, remaining attempts, an account-existence result, or a timed-unlock promise. Localization does not change the three-failure policy or credential handling.

Transactional emails include Spanish subjects, plain-text bodies, HTML bodies, action labels, and the privacy footer. Server-generated action URLs, message placeholders, expiration formatting, and required-action identifiers remain intact. The expiration values are already formatted by Keycloak; Spanish copy does not append an extra unit such as “minutes.” Keycloak chooses the email locale from its user/session locale resolution; the theme does not send messages or choose recipients.

## Account and administration consoles

The account and administration applications use their own inherited message bundles and language resolution. Their `locales=en,es` declarations advertise available languages; a declaration alone is not evidence that every console route has switched language. Account translation requests use `resources/{realm}/account/{language}` and begin with the server-provided environment locale. Administration translation requests use `resources/{realm}/admin/{language}`. Both inherited applications fall back to English for missing translations. Firefly supplies the same product name in both console bundles.

The welcome theme advertises the same languages, while retaining the upstream welcome page. Its language selection and any text that upstream does not localize require separate runtime review; it is not an authentication language selector.

## Existing deployments

The generator only changes newly created synthetic sandboxes and still refuses to overwrite retained state. Installing this theme does not migrate an existing realm. An authorized administrator must enable internationalization, configure `en` and `es` as supported locales, and choose `en` as the default for each existing realm, including the administration realm if its login or console is in scope. Preserve all existing identities, sessions, credentials, recovery state, and authentication policies when applying those settings.

## Qualification

The source contracts cover generated locale settings, English/Spanish placeholder parity for Firefly overrides, and identical generic authentication failures within each language. The inherited upstream translation files are not copied into this repository. Keycloak's community translation resources contain Spanish and are included by its default `communityTranslations` build profile unless explicitly disabled.

`tooling/localization-runtime.mjs` implements a real isolated-provider lane for each language: requested `ui_locales`, the inherited two-language selector, generic invalid-credential text, a successful code/PKCE exchange, explicit logout confirmation and refresh refusal, recovery acknowledgement and protocol error. It records desktop/mobile login and mobile logout/recovery/error screenshots after Manrope loads, and checks language and horizontal bounds. The workflow runs this independently of the account-console lane. It uses synthetic users only and never uploads credentials, codes, tokens or raw browser errors. A written lane is not a passing result.

Hosted qualification still needs to establish those outcomes and verify email verification, required actions, authenticator setup/challenge, and account/administration language loading. Review both themes at desktop and mobile sizes, with special attention to Spanish wrapping, focus, and password masking. Inspect actual HTML and plain-text email delivery in each language. Local builds, tests, containers, and dependency downloads were not run for this change under the host restriction; source implementation does not establish provider, publication, or production acceptance.

## Pinned upstream references

- [Login Spanish messages](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources-community/theme/base/login/messages/messages_es.properties)
- [Email English keys and placeholders](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources/theme/base/email/messages/messages_en.properties) and [Spanish messages](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources-community/theme/base/email/messages/messages_es.properties)
- [Account locale resolution](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/account-ui/src/i18n.ts) and [Spanish bundle](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/account-ui/maven-resources-community/theme/keycloak.v3/account/messages/messages_es.properties)
- [Administration translation loading](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/admin-ui/src/i18n/i18n.ts) and [Spanish bundle](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/admin-ui/maven-resources-community/theme/keycloak.v2/admin/messages/messages_es.properties)
- [Community translation build profile](https://github.com/keycloak/keycloak/blob/26.8.1/themes/pom.xml)
