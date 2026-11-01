# Configuration reference

Use this reference to find server, realm/client, theme and optional recovery settings. Configure Core/Domain services independently from Keycloak. Read back the effective server values after applying a change, especially on an existing realm.

## Find the setting

| Source | Controls | How it takes effect |
| --- | --- | --- |
| [Policy catalogue](../config/authentication-policies.json) | Shared brute-force settings and four population password/session profiles | Generator applies application profiles to new imports; administrator profile is applied explicitly after bootstrap |
| [Generator](../scripts/generate.py) | Synthetic users, exact clients, claim mappers, user profile, events, SMTP, realm defaults and owned Compose | Creates a new state directory; refuses overwrite and production mode |
| [Image lock](../deploy/images.lock.json) | Exact Keycloak/PostgreSQL/Mailpit OCI references | Retrieve/build the pinned images and scan the result |
| [Production reference](../deploy/keycloak.production.conf.example) | TLS, canonical/private hostnames, database inputs, proxies, management and logging | Supply server inputs and provision realms through the Admin Console or authorized Admin API |
| [Theme sources](../themes/console.css) and [theme build](../tooling/build_theme.py) | Five theme surfaces, font, branding, localized presentation | Build immutable theme resources and select the supported themes |
| [Native provider guide](../extensions/native-recovery/README.md) | Recovery/PIN realm attributes, workload authority, keys and persistence | Explicit native/gateway installation and owning-service integration; additive schema registration occurs at installation |

The [generated policy catalogue](reference/effective-defaults.md) contains the exact current JSON values. The remaining sections cover the generator, client and process settings. Use the catalogue values when creating realms, then verify the imported or administratively updated result.

## Population authentication and sessions

Customers and institutional humans use 16–128-character passwords with history 5. Workforce and administrators use 20–128 with history 10. All profiles select Argon2, reject a password equal to username/email and use the supplied baseline blocklist. Spaces and long passphrases are supported; arbitrary composition recipes and routine expiry are not configured by this baseline. A small static list is not a maintained compromised-password service, and applicable sector rules may require interval changes. [Authentication policy rationale](authentication-policies.md) and [EU/US controls](controls-matrix.md) explain those distinctions.

All profiles select permanent blocking on the third failure, with no timed release. The catalogue retains upstream wait-related fields for explicit configuration, but they do not turn a permanent block into a fifteen-minute release. No public response discloses an account's existence, the verifier that failed or attempts remaining. Password reset and generic administrative enable cannot substitute for the tracked native unlock process.

The generator overlays the catalogue **after** its common realm values. Effective application idle times are 300 seconds for customers/institutional humans and 900 for workforce; access tokens are 300 seconds. The ordinary realm maximum is 28,800 seconds. Explicit administration values are idle 300, maximum 3,600 and access-token lifetime 60 seconds. IdP activity is not actual payer inactivity at the application; do not use token refresh to defeat an applicable inactivity control.

| Population | Browser behavior | Deployment task |
| --- | --- | --- |
| Customer | Base synthetic browser profile does not mandate OTP | Configure the factor/enrollment/step-up policy for each customer journey |
| Workforce | `firefly-workforce-browser`: existing authenticated session or forms with password and OTP both REQUIRED | TOTP is not phishing resistant; configure a stronger profile for access requiring phishing resistance |
| Institutional human | Base synthetic profile does not mandate OTP | Validate organization membership/mandates and applicable MFA separately |
| Master administrator | Catalogue marks MFA required, but this does not itself enroll or enforce a permanent phishing-resistant administrator flow | Configure permanent administrators and factors, then remove bootstrap access |

Workforce TOTP parameters are `totp`, `HmacSHA1`, six digits, 30 seconds, look-ahead window 1 and `otpPolicyCodeReusable=false`. The actual server supplies the enrollment secret; the client does not choose it. Enrollment uses the server-provided setup secret. Check client clock synchronization before changing period/window; use a reviewed profile when choosing another algorithm or authenticator.

## Realm behavior beyond passwords

| Setting | Selected synthetic value | Meaning and limit |
| --- | --- | --- |
| Registration | `registrationAllowed=false` | No public creation or self-assignment of a population/tenant |
| Username changes | `editUsernameAllowed=false` | Identity links do not follow a mutable profile name |
| Email | `verifyEmail=true`, `loginWithEmailAllowed=true`, `duplicateEmailsAllowed=false` | Verification and login convenience do not establish party ownership or KYC |
| Password reset | `resetPasswordAllowed=true` | Upstream action-token reset; does not clear permanent native blocking |
| Remember-me | `false` | No selected extended remember-me session |
| Refresh rotation | `revokeRefreshToken=true`, `refreshTokenMaxReuse=0` | Rotation/reuse enforcement; test actual clients and concurrent refresh behavior |
| Locales | Internationalization enabled; `en`, `es`, default `en` | Browser matching plus supported upstream preference precedence |
| Themes | `firefly-id` for login/account/admin/email | Native login/customer-account variants require the optional providers and owners |
| User/admin events | Enabled; expiry 604,800 seconds; admin detail representations disabled | Seven-day local retention; configure production retention and audit forwarding separately |
| SMTP | Local `mailpit:1025`, synthetic sender, auth/TLS off | A test sink only; never promote these settings to a real notification service |
| Realm SSL requirement | `none` in the local HTTP sandbox | Production browser/backchannel/database TLS is separately mandatory under the approved deployment |

## Clients, audiences and trusted attributes

`sandbox-web` is a public interactive client with the exact `http://localhost:3000/oidc/callback` and signed-out path. `sandbox-backend` is confidential and uses port 8081 with no browser web-origin allowlist. Both require authorization code and S256 PKCE, narrow scopes and exact returns. Direct password grants, implicit, device, CIBA and service accounts are disabled in the default interactive clients. There are no wildcard callbacks.

The `sandbox-api` confidential receiver has no interactive or service-account grant. Its separate secret permits the selected introspection role, not a business operation. The optional [Configuration lookup](configuration-service-client.md) is a separate client-credentials profile: a distinct nonreserved ID, explicit realm and opaque tenant, `MACHINE`, narrow resource audience, no person linkage and no financial authority. It is not enabled by ordinary generation and does not impersonate a customer.

The declarative profile disables unmanaged attributes. `tenant_id`, `party_id` and `staff_actor_id` are single-valued, administrator-managed references with bounded length. The ordinary email/name profile fields remain appropriately editable; username is administrator-edited. Access-token mappers emit only the population-appropriate party or staff link and the selected `principal_kind`/client; those business-reference mappers do not enter ID tokens or userinfo. A user-supplied shadow attribute cannot become a trusted claim. [Verified claims](provider-claim-profile.md), [audiences](receiver-audiences.md) and [zero trust](zero-trust.md) describe receiving checks.

## Generator and lifecycle inputs

The generator requires `--mode sandbox`; `--output` selects a new directory and `--theme-dir` the built theme. The optional machine profile requires **all three** `--configuration-lookup-client-id`, `--configuration-lookup-realm` and `--configuration-lookup-tenant`. Incomplete, conflicting, reserved or malformed values refuse before creating state. `--mode production` is not a deployment command: this generator is limited to the local evaluation environment. Provision real realms through the Admin Console or authorized Admin API.

The lifecycle helper accepts `preflight`, `pull`, `up`, `status`, `stop`, with `--state` selecting the exact existing generated directory. It checks the ownership marker and Compose hash before service operations, uses only local Unix Docker sockets and preserves volumes on stop. Browser fixtures may separately read `FIREFLY_ID_STATE`; that environment variable is not a substitute for the lifecycle helper's `--state`. [Start safely](getting-started.md) gives complete commands.

## Server and secret inputs

The production example declares `db=postgres`, exact public and administrative URLs, strict hostname validation, no dynamic backchannel, no HTTP listener and mounted certificate/key paths. `xforwarded` headers are trusted only from explicitly supplied proxy CIDRs. Management health/metrics use private port 9000 with inherited HTTPS on the isolated management network; that port is never a public browser endpoint. JSON console logs and bounded shutdown delay/timeout are selected.

| Input | Expected owner and value |
| --- | --- |
| `FIREFLY_ID_DATABASE_URL` | Dedicated plain PostgreSQL JDBC URL without query/driver overrides; `db-tls-mode=verify-server` and mounted CA establish verifying TLS |
| `FIREFLY_ID_DATABASE_USER` | Nonsuperuser application role with reviewed database/schema privileges |
| `KCRAW_DB_PASSWORD` or supported configuration keystore | Secret-manager injection; generic `KC_DB_PASSWORD_FILE` is not assumed |
| `FIREFLY_ID_PUBLIC_URL` | Exact canonical HTTPS issuer origin |
| `FIREFLY_ID_ADMIN_URL` | Approved private administrative hostname; ingress must still block public `/admin/` routes |
| `FIREFLY_ID_PROXY_CIDRS` | Exact trusted proxy address ranges; ingress overwrites forwarded headers |
| `/run/secrets/database-ca.pem` | Database trust anchor; preserve peer/hostname verification and check the actual server chain |
| `/run/secrets/tls.crt`, `/run/secrets/tls.key` | Mounted server certificate and private key with correct ownership and rotation procedure |

The sandbox entrypoint reads its explicit mounted files and exports literal `KCRAW_*` variables supported by the pinned release. PostgreSQL's image separately supports `POSTGRES_PASSWORD_FILE`. Changing initialization input does not rotate a retained database password. Never mount the PostgreSQL bootstrap-superuser secret into Keycloak or pass secrets through build arguments, CLI values or documentation examples.

## Optional native and platform-service settings

Known-password native recovery uses explicit `firefly.native-recovery.*` realm attributes: exact issuer/HTTPS origin, population (`HUMAN`/`STAFF`), client, server-owned tenant/link attributes, distinct Domain/Core audiences and grant-disabled workloads. Its lifetime is at most 300 seconds for customers or 180 for workforce. The gateway additionally needs the actual trusted Domain URL. See the [native provider reference](../extensions/native-recovery/README.md) and [installation/flow guide](native-recovery.md); there are no trusted guessed defaults.

Customer support PIN protection uses `FIREFLY_SUPPORT_PIN_KEYS_DIR`, `FIREFLY_SUPPORT_PIN_ACTIVE_KEY` and explicit `FIREFLY_SUPPORT_PIN_VERIFY_UNTIL_<version>` deadlines for old verification keys. Accepted key material is 32–4096 bytes, private nonsymlink files. The eight-digit PIN is not retrievable as plaintext; rotation requires fresh native factors. BPO verification requires a staff/customer/case/delegation authorization provider, which is not supplied. [Support PIN](support-pin.md) gives lifecycle details.

Lost-credential recovery uses separate `firefly.reproofing.*` settings, customer-only opt-in, exact provider origin, protected account/party binding and at most 600-second original ceremony. It requires distinct Native/Core/Domain workloads and `FIREFLY_REPROOFING_DOMAIN_SECRET_FILE`. Enrollment/notification encryption uses either an exact 32-byte single version or the explicitly versioned mounted keyring; do not combine modes or replace a needed decryption key. [Credential-loss recovery](credential-loss-recovery.md) lists every required realm property and key procedure.

Core's notification poller additionally requires both recovery and notification enable flags, separate sender and monitor secret files, trusted native HTTPS and bounded durations. Its defaults and private endpoints are documented in [notification operations](notification-operations.md). Core/Domain are independently configured services; none of these settings adds an Identity dependency to Jafly.

## Apply a configuration change

Identify the affected population and application, expected behavior and rollback procedure. Exercise the change in an isolated environment, read back realm/client settings and test accepted and refused requests. Use supported administration/migration operations for retained realms; import and regeneration do not update them.

Before rollout, check actual ingress, database TLS/privileges, secret rotation, factors, receivers and notification delivery. [Check production settings](production-readiness.md) provides the offline command and explains its results; [operations](operations.md) covers the deployment lifecycle.
