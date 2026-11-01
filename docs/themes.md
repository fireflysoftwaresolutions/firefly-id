# Install and customize themes

The `firefly-id` theme gives login, logout, account management, administration, email and welcome pages a consistent Firefly identity. Web surfaces use self-hosted Manrope, the protected-identity logo, light/dark colors and English/Spanish messages.

## Theme variants

| Theme | Select for | Backend requirement |
| --- | --- | --- |
| `firefly-id` | Ordinary login, account, administration, email and welcome | Standard Keycloak distribution |
| `firefly-id-native` login | Adds the existing-factor **Unlock your account** entry | Installed/configured native provider, Domain gateway and Domain/Core SCA services |
| `firefly-id-native` account | Adds the customer support-PIN entry | Installed/configured native provider, customer profile and PIN keys |

Keep workforce account self-service on `firefly-id`; the customer support PIN is not an employee credential. Select the native login theme only after configuring its backend endpoints. Theme selection displays the entry point; it does not install the native API.

The ordinary `firefly-id` login also displays **Recover access** when the realm enables customer credential-loss recovery and configures its Domain origin. Install and configure the native provider, Core KYCB, customer Domain and verification adapter before enabling that feature. A deployment offering credential-loss recovery alone can keep the ordinary login theme; the supplied native image still bundles both provider JARs. See [credential-loss setup](credential-loss-recovery.md#configure-native-identity).

## Build the package

From the repository root:

```sh
python3 tooling/build_theme.py
```

The builder creates `dist/firefly-id-theme.jar` and an unpacked theme tree under `dist/themes/`. The JAR includes the theme descriptors, canonical artwork, local font, messages, styles and required notices. Production images load the JAR from Keycloak's `providers/` directory; the local environment mounts the unpacked built themes.

Build the optimized image after adding provider/theme JARs. See [deployment](operations.md) and [native installation](native-recovery.md).

## Select the realm themes

In the Admin Console, open the target realm's **Realm settings → Themes** and select the applicable login, account, administration and email themes. Configure each customer/workforce realm deliberately. Administration branding also applies to the master administrative realm; the distribution's default theme selection covers realms without an explicit override.

Installing the files does not migrate an existing realm's policy or enabled flows. Keep its users, credentials and sessions intact while changing presentation settings.

## Customize the right layer

| Source | Change here |
| --- | --- |
| `themes/firefly-id/login/` | Authentication/required-action resources, localized copy and illustrated layout |
| `themes/firefly-id/account/`, `admin/` | Supported console theme properties and resources |
| `themes/firefly-id/email/` | Transactional message layout and copy |
| `themes/console.css` | Shared account/administration styles |
| `themes/tokens.css` | Shared semantic color, typography, spacing and control roles |
| `assets/brand/` | Canonical product signatures, symbols and font |
| `assets/identity-backgrounds/` | Desktop/mobile isometric illustrations |

Rebuild after editing resources. Use an immutable new package/image for production updates and keep server theme caches enabled. Do not mount editable source or use development cache settings in production.

## Preserve authentication behavior

The theme inherits supported Keycloak forms and consoles. Server-generated actions, CSRF/action tokens, authenticator enrollment, credential APIs and sessions remain authoritative. The field adaptation keeps password inputs masked and removes reveal controls. Public login errors share generic presentation without account/attempt disclosure.

Customize layout and copy without changing protocol form actions, required-action identifiers or security attributes. A new feature needs its server flow configured as well as its screen. For native forms, preserve their origin/referrer and ceremony protections.

## Languages, appearances and email

Configure `en` and `es` as realm languages. [Language settings](localization.md) explains automatic browser matching and explicit preference precedence. Keep placeholders and server-formatted expiration values intact when translating.

Use [shared tokens](design-tokens.md) for light/dark changes. Review normal, focus, error, disabled and success states on desktop and mobile. Long Spanish text, account names, tables and dialogs must remain readable without page overflow.

Web surfaces use Manrope locally. Email keeps a system-font fallback because clients can block web fonts. HTML and plain-text messages preserve server-generated links and recipients. The footer retains the foundation copyright and Keycloak acknowledgement; distribute LICENSE/NOTICE and font/icon notices separately.

## Check an update

Exercise the changed journeys against the installed server: sign-in, generic refusal, logout, email verification, factor enrollment/challenge, recovery, account changes and administration. Check keyboard focus and both languages/appearances after fonts load. When upgrading Keycloak, compare inherited templates and the deliberately adapted macros against that supported version before deploying the rebuilt artifact.
