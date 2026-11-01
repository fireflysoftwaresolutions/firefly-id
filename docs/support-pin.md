# Telephone and customer support PIN

The customer support PIN is a separate CIAM knowledge credential for a future verified assistance process. The customer manages it inside Firefly Identity; an employee or BPO operator never retrieves it. It is not the account password, a card PIN, possession evidence, a payment approval, an unlock authorization or permission to impersonate a customer.

The native candidate implements customer self-service **status, create, replace and revoke**. Status exposes lifecycle state and available timestamps, never the PIN or its hash. The native verification service remains closed until a genuine support authorization owner is supplied. There is no public HTTP PIN verification route and no fallback allow-all implementation.

## Customer journey

With the native extension and customer account theme installed, account self-service provides **Customer support PIN / PIN de atención al cliente**. The page uses the shared self-hosted Manrope, Firefly artwork and light/dark tokens. It follows native locale negotiation and offers a return to account management.

An enabled, eligible local customer needs an ordinary SSO identity cookie plus a freshly verified password and pre-enrolled TOTP for creation, replacement or revocation. Each mutation requires exact-origin and one-time CSRF checks. The eight-digit PIN is entered twice in masked controls. Obvious repeated or sequential values are refused; password-visibility controls are absent. A failed step-up feeds the account's native brute-force protection. Workforce and administrator identities cannot use this customer credential surface.

Replacing the PIN advances its independent credential generation, invalidating previous proofs and attempts. Revocation removes the credential and records the lifecycle event. Three failed/reserved verification attempts hold the PIN; there is no automatic timed release. Its verification budget is separate from login and recovery budgets. A successful support PIN check cannot reset an account lock or revoke a fraud/HR hold.

Accepted lifecycle form submissions redirect with HTTP 303 to the authenticated status GET, so refreshing does not resubmit secrets or repeat a change. Status GET does not allocate a new native mutation ceremony. Any generic failure notice belongs to the same authenticated subject's consumed ceremony; a fresh set/revoke form creates its own one-time CSRF state.

## Credential protection and key rotation

Native storage uses an independently versioned HMAC-SHA-256 pepper followed by the native Argon2 password hash provider. HMAC input includes the realm and opaque subject. This protects a low-entropy PIN from database-only offline guessing; it does not make an eight-digit secret a high-entropy factor or establish factor independence by itself.

| Runtime setting | Required behavior |
| --- | --- |
| `FIREFLY_SUPPORT_PIN_KEYS_DIR` | Mounted directory containing version-named external key files |
| `FIREFLY_SUPPORT_PIN_ACTIVE_KEY` | Current version identifier: 1–64 ASCII letters, digits, `_` or `-` |
| `FIREFLY_SUPPORT_PIN_VERIFY_UNTIL_<version>` | UTC ISO expiry for verification with a previous version |

Provision random keys of at least 32 bytes through the actual secret manager. Key files must be readable by the Keycloak runtime identity, with no group/other read or write access; symlinked files are refused. Keys are never stored in identity tables, user attributes or credential metadata. Do not expose them in shell output, build context, logs, backups without separate encryption or CI artifacts.

To rotate, mount a new key version and make it active. Permit a reviewed bounded overlap for the old version with its explicit verification expiry. New/replaced PINs use the active version; existing stored values cannot be rehashed offline without the customer's PIN. Require strong-authenticated replacement during the transition, then retire the old key after approved expiry and recovery planning. An unavailable or expired key causes refusal, never unpeppered fallback. Backups and disaster recovery must preserve the separately protected key versions needed by retained credentials.

## Support and BPO integration boundary

The owning support service must establish the actual case/call, operator, provider/employer, customer, tenant, purpose, requested action, independent possession evidence, current workforce/BPO authority and policy obligations. Caller ID, an already verified phone contact, account history and a staff login do not establish those facts. A contact CRUD API is not an authorization service.

The native `NativeSupportAuthorization.Factory` is the explicit fail-closed integration point. No qualified implementation currently supplies those owner facts. Its current grant shape is a proposal, not an approved producer contract or generated SDK. Before enabling verification, align typed contracts with the actual owner, then issue and verify a short-lived, one-time case-bound authorization. It must bind the actual authenticated relying service/client, intended receiver/audience and current case/call/delegation generation or revocation state, as well as the customer and operator. Reject cross-customer/tenant/case/operator/service substitution, replay, revoked contracts and stale delegation, and retain an audit that identifies the employee/BPO operator separately from the customer. A machine identity alone cannot stand in for customer proof.

The customer should enter the PIN through the approved private capture channel; do not ask an operator to view it or put it in notes, recordings, transcripts or business DTOs. The native credential boundary returns only the approved opaque verification result. Knowledge and possession must remain independently verified under the bank's actual risk policy. The native permitted action is knowledge verification only. Each subsequent business operation still needs its own current policy decision and scoped staff authorization at every hop; a native grant or its two authority checks cannot substitute for them. The authorized support action stays narrowly scoped and expires; it does not become a general customer session or financial permission.

This owner contract and its real UI/channel, consent, abuse controls, recording suppression, notifications, workforce delegation, audit retention and operational acceptance remain required work in the support platform. CIAM lifecycle implementation alone does not complete a BPO or telephone-banking service. See [zero trust boundaries](zero-trust.md) and [native recovery](native-recovery.md) for the separate identity and unlock mechanisms.
