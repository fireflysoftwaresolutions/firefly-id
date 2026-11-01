# Theme architecture

The theme is named `firefly-id` for login, account, admin, email and welcome. A supported global default also brands the master realm when no explicit realm theme is selected. It extends Keycloak 26.8.1's supported themes: `keycloak.v2` login, `keycloak.v3` account, `keycloak.v2` administration and `base` email. The authoritative mechanism is [upstream theme inheritance](https://www.keycloak.org/ui-customization/themes).

Protocol forms and authenticator logic remain inherited. A narrow copy of the exact upstream 26.8.1 field macros removes password-visibility buttons while preserving labels, masked inputs, autocomplete, validation and recovery semantics. On the username/password login page, field and global errors share one generic alert before the form; this prevents a disabled-user global alert from differing visibly from an unknown-user field error. A checksum regression verifies that reversing the error-presentation change and one trailing-space cleanup recovers the pinned upstream layout. The adaptation does not depend on browser scripting or knowledge of an account. Firefly also supplies CSS, the login footer, English presentation messages, transactional email layout, the logo and locally served Manrope. The stock server still generates action links, CSRF/action tokens, WebAuthn challenges, credential actions, account APIs and session behavior. Do not copy an old template for cosmetic changes or bypass a required action in browser code.

## Flow coverage

| Surface | Mechanism | Qualification |
| --- | --- | --- |
| Username/password, account selection, broker choices | Inherited login forms | Real browser login in runtime lane |
| Registration and profile required actions | Inherited declarative-profile forms | Production policy and full flow review pending |
| Recovery and verification | Inherited action-token forms and email bodies, branded email layout | Real synthetic password replacement/fresh login and email verification/consumed-link handling; expiry, lost-factor and native secure unlock remain separate gates |
| Logout, expiration and errors | Inherited server forms | Logout and protocol negatives in runtime lane |
| OTP, passkeys, recovery codes | Inherited authenticators and required actions | Real workforce TOTP enrollment, invalid-code refusal and valid challenge; passkeys, lost-factor and recovery-code review pending |
| Account self-service | Upstream React account console with branded supported properties/CSS | Real customer/workforce protected-profile write/removal, unchanged stored attributes and fresh signed-claim checks; complete session administration remains separate |
| Administration | Upstream React admin console with branded supported properties/CSS | Production ingress/least privilege review pending |

These are implementation and test-lane descriptions, not claims that an unexecuted workflow has passed. Read [current evidence](progress.md) for actual results.

## Build and customize

Run `python3 tooling/build_theme.py`. The builder assembles source resources and canonical artwork/font into a deterministic JAR and unpacked `dist/themes/firefly-id`. The archive descriptor declares all five theme types. Production images use the JAR in `providers/`; the sandbox mounts the unpacked built directory. Never deploy source symlinks or missing generated resource files.

The same archive includes an opt-in inherited `firefly-id-native` variant for login and account. Its login theme exposes the native recovery entry; its customer account theme adds a support PIN link. Select these only with the [native extension and actual owners](native-recovery.md) installed and qualified. Keep employee account self-service on `firefly-id`; the customer PIN is unavailable to workforce identities. Theme-only installations retain the ordinary variant and do not advertise native endpoints.

Native unlock/PIN forms additionally select a same-origin document referrer policy through a server-only template attribute, preserving the Origin required by their CSRF boundary. The condition is absent from ordinary inherited action-token forms. The exact-upstream checksum test reverses this explicit metadata addition as well as the other intentional adaptations before comparing the pinned template.

Edit presentation under `themes/`, shared console CSS in `themes/console.css`, and canonical editable artwork under `assets/brand/`. Rebuild after every asset change. Email uses a system font fallback because mail clients commonly block web fonts; authentication and account web surfaces use self-hosted Manrope.

Review desktop and narrow layouts in both color schemes, keyboard focus, real errors, long names and recovery strings. Confirm fonts/assets finish loading before screenshots. Test the actual identity server rather than treating standalone preview HTML as flow acceptance. Keep server theme caches enabled in production; use an immutable new artifact/image for updates.

Authentication forms share a responsive isometric composition across login, logout, recovery, verification and required actions. The [artwork guide](isometric-backgrounds.md) records actual website/brand-kit sources, geometric depth ordering and the reduced mobile scene. The artwork remains presentation; server controls still own each journey.

Custom authentication and email copy supports American English and Spanish. The hosted localization lane exercises real login, refusal, logout, recovery acknowledgement and protocol errors in both languages, including native automatic locale selection and a discreet optional footer override. Upstream translations alone do not qualify additional branded locales; complete and review their custom copy before advertising them.

The account/admin consoles load a supported theme script that hides and disables their English/Spanish password-reveal controls and preserves masked fields. This is a separately maintained presentation adaptation: the upstream React component's reveal option is not a realm property. Real administration reset-password dialogs must be rechecked on upgrades. It does not claim to prevent the owner of a browser from inspecting their own input value. Copyright appears in all scoped web surfaces and branded HTML email.

All Firefly Identity web footers and branded HTML email place “Powered by Keycloak” beside © 2026 Firefly Software Foundation Inc., linking directly to [Keycloak](https://www.keycloak.org). Spanish authentication, console, and email surfaces use “Con tecnología de Keycloak”; the English welcome page retains the English attribution. Custom plain-text email bodies include the same attribution and official URL. This recognizes the upstream identity server in the footer while preserving Firefly Identity's product branding. It supplements the retained Apache license, NOTICE, and font OFL files; it does not replace those legal notices or establish legal compliance.

Fatal account/admin error dialogs use the family signature, Manrope, a responsive paper/charcoal card, clear localized copy and an amber retry action. Their visible detail is normalized to a recovery instruction; protocol errors and server failure causes must still be handled safely at the owning server. Styling a failure does not repair its cause. Login protocol errors use the shared illustrated layout and an explicit return action when the server supplies an approved application URL. [Localization](localization.md) tracks the English/Spanish browser qualification lane.
