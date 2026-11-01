# Customer support PIN

The support PIN is a separate eight-digit customer knowledge credential. Customers can view its status, create it, replace it or revoke it in Firefly Identity. Nobody can retrieve the stored PIN.

The PIN is not an account password, card PIN, payment approval, possession factor, unlock permission or impersonation credential. Telephone and BPO verification are **not activated**. The customer lifecycle and native evidence boundary are available in source, but no support platform currently provides the required production authorization owner. The approved initial scope is consultation/support; the PIN does not grant authority for financial actions.

## Customer lifecycle

Open **Customer support PIN** in customer account management after normal online sign-in. The native route is `{issuer}/firefly-recovery/support-pin`.

| Action | What the customer supplies | Result |
| --- | --- | --- |
| View status | Active online SSO session | Not set, active or replacement required, with available lifecycle timestamps |
| Create or replace | Current password, fresh enrolled TOTP, new PIN and confirmation | New protected PIN; previous PIN authority invalidated |
| Revoke | Current password and fresh enrolled TOTP | PIN removed and revocation time recorded |

The customer must be enabled, local and nonprivileged in a configured `HUMAN` realm. Workforce and administrator identities are excluded. An offline token or surviving browser cookie without a real online session is insufficient for account/PIN navigation.

```mermaid
stateDiagram-v2
    state "Not set" as NotSet
    state "Replacement required" as ReplacementRequired
    [*] --> NotSet
    NotSet --> Active: Password and TOTP verified — create PIN
    Active --> Active: Password and TOTP verified — replace PIN
    Active --> ReplacementRequired: Verification budget exhausted or authority invalidated
    ReplacementRequired --> Active: Authenticated replacement
    Active --> NotSet: Authenticated revoke
    ReplacementRequired --> NotSet: Authenticated revoke
    Active --> NotSet: Authorized security revocation or credential-loss recovery
```

Eight digits are required. Repeated digits, repeated halves or pairs, and ascending/descending sequences are refused. Controls stay masked. Never put a PIN in notes, transcripts, recordings, a URL or a business DTO.

Mutation forms expire after 120 seconds and require the authenticated subject, Secure/HttpOnly/Strict cookie, exact Origin and one-time CSRF value. Accepted POSTs redirect with 303 to status; refreshing status does not repeat the mutation. A failed password/TOTP step-up participates in ordinary native brute-force protection.

The PIN verification budget is separate. Three failed verifications hold it without timed release; outstanding reserved checks also count against the three-slot admission limit. Replacement advances its independent generation and invalidates previous proofs. It never resets an account lock or another hold.

## Install and protect keys

Install [native Identity](native-recovery.md), select the `firefly-id-native` account theme for customers, and keep normal password/TOTP authentication available. Manage pepper keys independently of the database and credential-replacement encryption key.

| Environment setting | Required configuration |
| --- | --- |
| `FIREFLY_SUPPORT_PIN_KEYS_DIR` | Mounted directory containing version-named secret key files |
| `FIREFLY_SUPPORT_PIN_ACTIVE_KEY` | Active version: 1–64 ASCII letters, digits, `_` or `-` |
| `FIREFLY_SUPPORT_PIN_VERIFY_UNTIL_<version>` | UTC ISO-8601 expiry permitting an older version during a reviewed overlap |

Keys contain 32–4,096 bytes and must be readable by Keycloak without group/other read or write permission. Symlinked key files are refused. The native boundary applies subject/realm-bound HMAC-SHA-256 peppering followed by its Argon2 password hash provider.

To rotate, provision a new key version and activate it. Keep a bounded explicit verification overlap for the old version and require authenticated PIN replacement. Existing PINs cannot be rehashed without the customer's input. Missing or expired keys cause refusal; no unpeppered fallback exists. Back up required old keys separately and securely alongside the retained credential database.

## Security administration

An authenticated, authorized Keycloak administrator may revoke a compromised PIN through the target user's credential-management operation. This is revocation only: it cannot create or replace a PIN, clear an account lock or impersonate the customer. Generic Account REST deletion of this custom credential is refused; customers use the native step-up flow.

Administrative revocation records the actual administrator realm, subject, client and administrative event together with the native revocation. Missing attribution refuses the transaction. Login, recovery and verification budgets are preserved. Use private administrative ingress, named least-privileged identities, strong MFA and the institution's incident procedure.

## Native evidence boundary

`NativeSupportAuthorization.Factory` is the fail-closed extension point. There is no supplied production owner implementation or public PIN-verification HTTP endpoint. Exactly one installed factory must explicitly qualify itself before a native caller can use the service. An implementation that returns a plausible grant without independently checking current authorization is not a valid owner.

The contract binds these facts:

| Binding | Native requirement |
| --- | --- |
| Target | Exact configured HTTPS customer issuer and realm, local enabled nonprivileged customer subject, tenant and customer link |
| Staff | Separate HTTPS workforce issuer and actual staff subject; both issuers exclude user information, query strings and fragments |
| Owner context | Nonblank nonce, genuine case reference and call reference |
| Action and purpose | Exactly `VERIFY_SUPPORT_PIN` and `TELEPHONE_SUPPORT_KNOWLEDGE` |
| Lifetime | Future expiry with at most 120 seconds remaining at admission; a recheck must preserve the exact original expiry |
| Field bounds | Customer subject: 128 characters; action/purpose: 64; other string fields: 512. Blank, surrounding whitespace and control characters are refused |

The native service reserves one of three per-generation check slots before checking the PIN. The database enforces a unique digest of the configured target realm ID, issuer and nonce. Changing the subject, tenant, case, staff identity or expiry cannot turn the same nonce into another attempt. A separate digest binds the complete exact grant. The service checks current owner authorization again outside database locks before it performs the reserved check.

Proof state progresses from `RESERVED` to `REJECTED` or `VERIFIED`, then from `VERIFIED` to `CONSUMED` at most once. A bad PIN consumes its reservation and increments the failed-check counter. Three failed checks hold the PIN without a timer. An owner outage, changed authorization, unavailable pepper/hash provider or expired request leaves the reservation unavailable; it does not refund a slot or count as a bad PIN. Three pending reservations therefore also prevent admission. Authenticated PIN replacement creates a new generation; it does not revive evidence from the old generation.

`NativeSupportPinServiceImpl.consume(signedSupportContext, reference)` is native-only. It reauthorizes the caller through the same owner before acquiring native locks, then locks the customer, state and proof in that order. It requires the exact original grant, current customer and credential eligibility, original PIN generation, credential and pepper-key version, unexpired proof, enabled account and absence of account/PIN holds. Expiry is checked after acquiring locks. Consumption and its audit record commit in the same native transaction; consumption does not issue a customer token or authorize any business operation.

Each transition appends the proof reference, full-grant and nonce digests, actual staff issuer/subject, case/call, tenant/customer, action/purpose and PIN generation to the native audit journal. PostgreSQL's existing append-only audit trigger protects those records. PINs, signed contexts, raw tokens and provider payloads are not audit fields. Restrict access to the journal because its attribution still identifies people and cases.

The additive migration preserves historical proof rows. New binding/status columns remain nullable for those retained rows; a legacy `verified` flag alone cannot make a proof consumable. Preserve the proof table and audit journal together. Never delete nonce records, reset attempt counters or create replacement authorization to resolve an uncertain result.

If verification or consumption commits but its response is lost, the caller must reconcile the original reference with the owner and native journal. Repeating verification or consumption is refused, including a consumed reference. Receipt loss is an unknown result until reconciliation; it is not permission to ask for another PIN or mint a replacement nonce.

A support integration must first establish a genuine case/call, actual employee or BPO operator, employer/delegation, target customer and tenant, permitted action, current approvals and independent possession evidence. It must authenticate the requesting service and bind those facts to a short-lived, one-time authorization with replay and revocation checks.

Capture the PIN through an approved private customer input channel, not through an operator. The native verifier may return only an opaque knowledge-verification result. Every subsequent support or financial action still needs its own authorization. Caller ID, account history, a verified contact or a staff login cannot replace this owner integration. Until the channel, authorization service, recording suppression, consent and operating procedures exist, do not offer telephone or BPO verification.


## Activation and acceptance

The institution still needs to name the genuine case/authorization owner and protocol, establish tenant/delegation mappings and permitted consultation actions, approve private PIN collection with recording suppression, define independent possession evidence, and assign audit and incident custody. Support PIN evidence cannot be substituted for forgotten-password recovery, lost-authenticator recovery, payment approval or customer impersonation.

Source regression tests cover grant constraints, altered-grant replay identity, reservation budgets, owner refusal/outage, one-time consumption, lock order, audit attribution, expiry and credential/hold invalidation. These tests and the additive migration require actual native compilation and PostgreSQL execution in owned hosted qualification. The native image workflow includes a hosted-only storage probe for cross-customer nonce contention, nullable legacy bindings, proof/audit rollback and append-only attribution on its fresh, empty PostgreSQL database. That probe does not exercise the native service or upgrade retained data. In particular, qualify concurrent same-nonce attempts across different customers, concurrent different-nonce budget exhaustion, consume races, rollback after audit failure, migration over retained legacy rows and response-loss reconciliation. Mocked transaction tests do not prove database uniqueness, atomic commit or concurrency behavior. Production activation remains blocked until the genuine owner and complete channel pass acceptance.
