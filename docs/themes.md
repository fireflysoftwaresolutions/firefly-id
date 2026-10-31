# Theme architecture

The theme is named `firefly-id` for login, account, admin, email and welcome. A supported global default also brands the master realm when no explicit realm theme is selected. It extends Keycloak 26.8.1's supported themes: `keycloak.v2` login, `keycloak.v3` account, `keycloak.v2` administration and `base` email. The authoritative mechanism is [upstream theme inheritance](https://www.keycloak.org/ui-customization/themes).

Protocol forms and authenticator logic remain inherited. Firefly supplies CSS, the login footer, English presentation messages, transactional email layout, the logo and locally served Manrope. The stock server still generates action links, CSRF/action tokens, WebAuthn challenges, credential actions, account APIs and session behavior. Do not copy an old full template to change one color or bypass a required action in browser code.

## Flow coverage

| Surface | Mechanism | Qualification |
| --- | --- | --- |
| Username/password, account selection, broker choices | Inherited login forms | Real browser login in runtime lane |
| Registration and profile required actions | Inherited declarative-profile forms | Production policy and full flow review pending |
| Recovery and verification | Inherited action-token forms and email bodies, branded email layout | Synthetic recovery in runtime lane; full verification/expiry/reuse review pending |
| Logout, expiration and errors | Inherited server forms | Logout and protocol negatives in runtime lane |
| OTP, passkeys, recovery codes | Inherited authenticators and required actions | Actual enrollment/lost-factor/step-up review pending |
| Account self-service | Upstream React account console with branded supported properties/CSS | Full profile-forgery/session review pending |
| Administration | Upstream React admin console with branded supported properties/CSS | Production ingress/least privilege review pending |

These are implementation and test-lane descriptions, not claims that an unexecuted workflow has passed. Read [current evidence](progress.md) for actual results.

## Build and customize

Run `python3 tooling/build_theme.py`. The builder assembles source resources and canonical artwork/font into a deterministic JAR and unpacked `dist/themes/firefly-id`. The archive descriptor declares all five theme types. Production images use the JAR in `providers/`; the sandbox mounts the unpacked built directory. Never deploy source symlinks or missing generated resource files.

Edit presentation under `themes/`, shared console CSS in `themes/console.css`, and canonical editable artwork under `assets/brand/`. Rebuild after every asset change. Email uses a system font fallback because mail clients commonly block web fonts; authentication and account web surfaces use self-hosted Manrope.

Review desktop and narrow layouts in both color schemes, keyboard focus, real errors, long names and recovery strings. Confirm fonts/assets finish loading before screenshots. Test the actual identity server rather than treating standalone preview HTML as flow acceptance. Keep server theme caches enabled in production; use an immutable new artifact/image for updates.

The custom copy currently supports American English. Upstream translations alone do not qualify the branded copy in another locale. Add complete translations, then review actual screens and emails before advertising another locale.
