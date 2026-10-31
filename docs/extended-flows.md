# Extended synthetic identity flows

`tooling/extended-runtime.mjs` adds real-provider verification, profile-integrity, and workforce MFA checks beyond the main browser runner. The latest profile-storage and verification-replay changes are implemented but have not been validated locally because the host is below the allowed disk floor. Hosted execution must establish their actual outcomes. It does not modify Jafly or prove business authorization.

## Fixtures and execution

Use a **freshly generated** sandbox from the current generator, after building the theme. Generation never overwrites retained state and never updates an already imported realm. The generator adds these synthetic fixtures:

| Fixture | Server policy | Protected local state |
| --- | --- | --- |
| `synthetic-verify-email` in customers | Unverified `verify-email@example.invalid`, required `VERIFY_EMAIL`; distinct party reference/password | `credentials.json` entry `verify_email` |
| Existing synthetic workforce user | Required `CONFIGURE_TOTP`; TOTP HmacSHA1, six digits, 30 seconds, one-step validation window, non-reusable codes | `secrets/workforce-totp.json`, initially `pending-enrollment` |
| Existing synthetic customer | Existing profile and current password; unchanged by extended generation | Existing `customers` credential entry |

The runner reads `credentials.json` when it starts, so it consumes a password updated by the main runner's actual recovery flow. Run the browser runners **sequentially** because both own the local callback listener on port 3000. Use the already pinned Playwright dependency/browser installation in the hosted runtime environment; do not download browsers or start this stack on a host below the capacity gate.

From the repository root, after the owned stack is healthy and the normal runner has finished:

```sh
node tooling/extended-runtime.mjs
```

Set `FIREFLY_ID_STATE` only when using another explicitly owned generated state directory. Default selected flows are `verify,profile,mfa`; any selected failure makes the process exit nonzero. A consumed email-verification fixture is not silently reset or granted another action: on a retained verified account the initial verification screen will be absent, and requesting that initial flow again fails. To rerun the independent profile and retained-factor paths without claiming another first verification:

```sh
FIREFLY_ID_EXTENDED_FLOWS=profile,mfa node tooling/extended-runtime.mjs
```

`profile` selects the customer integrity probe. The workforce integrity probe runs after successful authentication in `mfa`, using that real enrolled-factor session. Both selections are required to qualify integrity for both populations. Profile checks require the generated users' native `account` permissions and an authenticated sandbox bootstrap administrator for read-only snapshots. Administrative authentication is a separate browser session; its bearer is renewed through that existing SSO session when its lifetime is short. It never substitutes an admin token for an Account REST request or uses a password grant.

A different fresh output path creates another isolated sandbox/project; it does not migrate or reset an existing one. Preserve the old state and obtain explicit approval before deleting any old resources.

## Implemented paths

**Email verification:** the runner snapshots Mailpit message IDs before login, authenticates the separate unverified account using real authorization code with PKCE S256, and requires the actual verification screen. It reads only a newly arrived message addressed to the synthetic verification recipient. The server-generated action URL must have the expected issuer origin/path; a real browser link opens it in a popup. After any server confirmation, the original code flow must complete, the access and ID tokens must verify against live JWKS, and the ID token must contain signed `email_verified=true`. The action is then opened in a fresh isolated browser context: a recognized consumed/already-verified/invalid-action result must appear and neither a callback request nor a final callback URL may occur. A server 5xx fails the probe. The exact upstream English wording “Your email address has been verified already.” is recognized as consumed, not mislabeled as an HTTP error or another verification grant.

**Profile integrity:** the shared probe runs for the customer after real code/PKCE login and for the employee after the fresh workforce MFA challenge succeeds. It loads each population's actual account console and obtains the bearer header from its real authenticated profile request. It requires a permitted unchanged-profile POST with status 204 before attempting forgery, so blanket denial cannot masquerade as protected-field enforcement.

Before that baseline write and after every subsequent attempt, a separate authenticated administrator reads the exact user's `GET /admin/realms/{realm}/users/{id}` and `GET /admin/realms/{realm}/users/{id}/unmanagedAttributes`. Both complete attribute maps must remain unchanged. The initial managed tenant/population linkage must agree with the signed identity; the opposite population linkage and shadow `principal_kind`/`client_id` attributes must be absent. The unmanaged endpoint matters because the ordinary user representation is profile-filtered: an unknown attribute hidden from that response alone would not prove that it was never stored. These are supported read-only administrative operations; the probe does not change profile configuration or access the database directly. [Pinned user and unmanaged-attribute operations](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/UserResource.java).

Separate write and empty-value removal attempts target `tenant_id`, `party_id`, `staff_actor_id`, `principal_kind`, `client_id` and a newly generated arbitrary unmanaged sentinel. This covers admin-only attributes, adding the other population's identity link, and attempts to persist a shadow for claims normally supplied by hardcoded client mappers. Each response must be either 400 or 204; neither status is sufficient by itself. Both administrative storage views must remain unchanged, a subsequent authenticated Account GET must omit those fields from its values and metadata, and a new browser code/PKCE exchange must yield cryptographically validated tokens with the original subject and unchanged protected claims. Fresh workforce exchanges reuse only the already authenticated MFA browser SSO context; they do not bypass initial enrollment/challenge or create a new credential grant.

The probe deliberately does not change provider roles, user attributes, counters, passwords or claim mappers. If an attempted forbidden write actually persists, the lane fails and preserves the evidence state rather than silently repairing it. Administrative records, account bearers, signed claims, sentinel values and credentials remain only in memory or their existing protected credential files; none are printed or written to shareable evidence.

**Workforce MFA:** the runner completes required TOTP enrollment through the actual inherited form. It uses the server's manual setup display, captures that server-generated secret into the owner-only local factor file, enters a genuine current OTP, and finishes code/PKCE exchange. It never injects a prechosen secret into the hidden server field. The resulting signed token must have `principal_kind=STAFF`, canonical UUID-shaped `staff_actor_id`, opaque `tenant_id=synthetic-tenant`, and no `party_id`.

A fresh browser context must then challenge for the enrolled factor. The runner submits a wrong OTP selected outside the currently valid time window, requires the actual OTP error, and proves no callback happened. It then enters a fresh valid OTP and requires a real signed code exchange. Attempted and accepted counters are retained with the secret; the runner waits for the next interval when necessary, rather than weakening the server's non-reusable-code policy. On a later run it uses the preserved factor and labels that path as retained-factor authentication rather than claiming new enrollment. An enrolled server factor without the matching local secret fails; the runner does not remove/reset it or create another credential grant automatically.

## Evidence and confidentiality

The only shareable output is `.work/extended-runtime/summary.json`: selected flow names, completed fixed stage labels, and explicit pending coverage. The runner takes no screenshots, videos, trace, HAR, raw mail, token, QR, or authenticator-secret artifacts. All request/navigation errors use the existing sanitized error helper, and parallel callback/event promises have handled rejection paths. Do not enable `DEBUG=pw:*`, attach request loggers, or upload `.state` or temporary files.

The TOTP secret/counters are written atomically with mode 0600 under the protected state directory. Preserve this file with the same sandbox database if later challenge tests are needed. It is sensitive credential material even though the account is synthetic. The runner never changes the synthetic customer password, clears a server credential, overwrites retained generation output, or publishes token values.

Offline validation exercises fresh-fixture policy generation and RFC-compatible TOTP vectors using Node's standard library; importing the algorithm does not load Playwright or contact a service. `node --check tooling/extended-runtime.mjs` verifies syntax. These checks establish source behavior only.

## Still pending

- Genuine expiration rejection of a signed email-verification action after its configured lifetime; no forged timestamp or signature-corrupted token is presented as expiry proof.
- Passkey/WebAuthn enrollment and assertion with an actual configured RP and virtual/physical authenticator. No virtual-authenticator path is advertised as passed or silently skipped.
- Lost-factor recovery, recovery-code enrollment/use, phishing-resistant step-up, registration/broker profile forgery, and institution-specific authentication policy.
- Real backend authorization, current authoritative tenant/business relationship checks, permission enforcement, and production readiness.

The implementation follows the pinned upstream [verification form](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources/theme/base/login/login-verify-email.ftl), [verification handler](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/authentication/actiontoken/verifyemail/VerifyEmailActionTokenHandler.java), [account API](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/account/AccountRestService.java), [account request implementation](https://github.com/keycloak/keycloak/blob/26.8.1/js/apps/account-ui/src/api/request.ts), [TOTP setup form](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources/theme/base/login/login-config-totp.ftl), and [OTP challenge form](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources/theme/base/login/login-otp.ftl). Actual hosted observations take precedence over assumptions from source review.
