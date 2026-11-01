# Configure English and Spanish

Firefly Identity supports English (`en`) and Spanish (`es`). English is the fallback. Authentication follows the browser's supported language when no saved or explicit preference takes priority; a compact footer control lets the person choose a language without leaving the current journey.

## Configure a realm

In **Realm settings → Localization**, enable internationalization, add `en` and `es` as supported locales and select `en` as the default. Repeat for customer, workforce and administrative realms that you operate. The local environment generator applies these settings to new example realms.

Installing a theme does not update retained realm settings. Apply localization through the authorized administration process without recreating users or changing credentials, sessions or recovery state.

## How language is selected

Keycloak resolves supported locale preferences in this order:

1. Explicit selection in the authentication session/request.
2. The user's saved profile locale.
3. The application's OIDC `ui_locales` request.
4. The locale cookie.
5. The browser's `Accept-Language` preferences.
6. The realm default, then English.

Browser preferences such as `es-ES` match Spanish and `en-US` match English. An unsupported browser language falls back to the configured default. Browser language usually follows the operating system, but the browser can have its own setting. A deliberate saved/manual choice is preserved when system settings change.

## Choose browser matching or application preference

Applications that want browser matching should omit `ui_locales`. To request Spanish explicitly, include `ui_locales=es` in the authorization request created by the OIDC library. Keep all normal state, nonce, PKCE and redirect protections; language is an optional protocol preference.

The footer selector uses server-generated locale URLs and preserves the current authentication context. Do not implement an independent browser-language redirect that restarts sign-in or drops the original request.

## Translate custom messages

Edit the corresponding English/Spanish message bundles under the consuming theme, then rebuild the theme package. Keep message keys, variable placeholders, action URLs and required-action identifiers unchanged. Expiration text may already contain formatted units supplied by Keycloak; do not append another unit in translated text.

Use complete sentences rather than concatenated fragments. Public failures and recovery acknowledgements remain generic in both languages, without account-existence results, remaining attempts or timed-unlock promises. [Themes](themes.md) explains package/build steps.

## Account, administration and email

The account and administration consoles use their inherited translation bundles and locale resolution. Their `locales=en,es` declarations advertise the languages; configure the appropriate realm preference as well. Custom Firefly product/error copy lives in the matching console message resources.

Keycloak selects transactional email language from its user/session locale context. The theme supplies subjects, action labels, HTML/plain-text content and footer copy. It does not choose recipients or send mail itself. Configure and verify the real email channel separately.

The service's root welcome page is independent of any realm. Its self-hosted presentation script selects the first supported English or Spanish browser preference, without redirecting or changing an authentication session. It falls back to English when JavaScript is unavailable or no supported preference exists. Realm, profile and OIDC locale choices apply after entering the application's authentication journey.

## Verify the experience

Check a fresh English browser, a fresh Spanish browser, an unsupported browser language and an explicit application override. Continue through sign-in, refusal, logout, verification, recovery and enabled factor enrollment without losing the original flow. Review Spanish wrapping, keyboard focus, masked password fields and delivered HTML/plain-text messages in both appearances.
