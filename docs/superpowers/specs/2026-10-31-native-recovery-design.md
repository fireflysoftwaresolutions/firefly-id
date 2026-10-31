# Native recovery, support credentials and zero-trust integration

## Authorized outcome

Complete the existing permanent-unlock design with a real Keycloak extension, owning Core SCA evidence, genuine generated-SDK Domain orchestration and branded native journeys. Keep customers and workforce separate. Jafly stays provider-neutral and independently usable. The owner's subsequent instructions add a CIAM-owned telephone/support PIN and per-service zero-trust checks. This extends the previously approved design; implementation is explicitly requested.

Keycloak 26.8.1 is the latest stable release verified on October 31, 2026 using the official download page and GitHub latest-release API. The distribution already pins that release and its OCI digest. Native extensions target its Java 21 runtime; platform services retain their genuine Jafly 26.10.23/Java 25 baseline. No released artifact or shared framework train is overwritten.

## Ownership

- Keycloak owns credentials, restricted browser ceremonies, native lock generations, administrative holds, provider attestations and the atomic unlock/execution journal.
- Core SCA owns recovery operations, verification budgets, immutable factor evidence, consumption and durable boundary/decision audit.
- `domain-common-sca` orchestrates through the actual Core producer-generated SDK. It owns no credentials, challenges or business persistence.
- Experience, Domain and Core each authenticate and authorize their own requests. Infrastructure and workload identity add protection; neither supplies human proof or business authority.
- The parent coordination session owns generic Jafly secure-default/current-state/delegation work and OpenPlatform terminal changes. Product-specific code stays outside Jafly.
- Telephone/support case and BPO delegation are separate owning-service contracts being coordinated with the parent. A native support PIN never creates those business records or grants.

## Recovery protocol

1. A native branded page creates unpredictable HttpOnly/SameSite ceremony state and a one-use CSRF token. Username/password go only to Keycloak. Known, unknown, held, blocked and ineligible inputs follow the same public steps and generic messages; they expose no remaining attempts or factor-specific error.
2. Verify the existing password while keeping the user disabled. Persist the native attempt reservation before credential verification. Bind a successful ceremony to issuer, realm, subject, opaque tenant, canonical customer/staff link, intended recovery client, purpose, credential revisions and the durable current permanent-lock generation. No ordinary OAuth code, user session, refresh token or business audience is created. A short-lived restricted signed assertion is held only by the server-side orchestrator.
3. The native backend invokes Domain; Domain independently validates the restricted assertion and current narrow recovery policy, then invokes Core through its genuine SDK. Core independently validates caller/current policy/native admission and creates the operation and pre-existing knowledge/possession challenges. Missing qualification or policy denies.
4. Core exposes a reservation operation so its durable verification budget commits **before** native password/TOTP evidence is verified for the recovery challenge. The bootstrap password check in step 2 supplies admission only. After Core commits the knowledge reservation, the native backend performs a second password verification using the same browser POST's still-ephemeral secret; it is never persisted or relayed. The user need not type it twice. Native completion verifies the already enrolled TOTP inside Keycloak after a separate committed possession reservation. Each yields an opaque attestation bound to the exact operation, challenge, reservation, credential/enrollment, generation and expiry. Raw submitted passwords/PINs/TOTP codes and reusable factor secrets never cross into Domain/Core DTOs or persistence.
5. Domain submits opaque attestations for completion. Core refreshes native admission and verifies the native evidence, independent categories/provenance and exact reservation before storing each proof. Attempts and issuance cannot be reset by a new request key, client or ceremony for the same generation.
6. Core consumes the independent proof pair once. Its receipt is an opaque execution-bound online reference. A new online authorization verification operation rechecks the stored consumed operation, binding, owner link, execution ID, expiry, pending outcome and committed consumption audit under current admission/policy.
7. The native executor verifies that receipt online. In one native transaction and consistent lock order it rechecks local storage, permanent-lock reason, exact generation, absence of holds, credential revisions and expiry; journals the execution; retires online/offline sessions; raises user not-before; and performs only the eligible state transition. Response loss reuses the durable execution journal. A timeout or UNKNOWN outcome never creates a second authorization.
8. Core records the authoritative native journal outcome. Completion always leads to fresh ordinary sign-in and the population's MFA. Recovery supplies no financial authority and restores no old session.

The native provider's internal transport requires authenticated workload credentials and the actual signed restricted actor assertion in an explicitly defined request envelope. Both are independently checked; a workload secret alone cannot admit recovery. No unsigned actor headers, client-submitted success flag, invented delegation or generic Admin REST enable operation is accepted.

## Native implementation constraints

- Register a version-pinned BruteForceProtector implementation that captures permanent-lock generation and audit in the same transaction as native disable. Use the protected permanent-event hook; do not infer authority from an asynchronous after-commit event or a counter supplied by a caller.
- Existing untracked permanent locks require assisted recovery; they acquire no automatic recovery eligibility merely by installing the extension.
- Use native JPA entities/indexing and the owning Keycloak transaction. Persist lock generations, holds, budgets and execution identities across restarts. Reject federated, read-only, service-account and unqualified storage paths.
- Administrative/credential changes invalidate outstanding recovery. Generic enable requests for an extension-owned permanent block are refused. Event listeners must mark the actual JTA transaction rollback-only or install a mandatory prepare guard; throwing or setting only the outer Keycloak flag is insufficient on explicit administrative commit paths.
- Resolve native enrolled TOTP credentials; reject HOTP, new enrollment and reusable-code policy. Preserve native replay protection plus a durable recovery consumption fence. Credential rehash callbacks and concurrent changes must invalidate or reconcile correctly.
- Separate customer/workforce realm/client/issuer/link mappings and policies. Master administrator, institution, fraud and employment holds are outside this self-service flow.
- TLS, trusted origins and bounded input/network timeouts are mandatory outside explicitly owned synthetic fixtures. Never disable browser/JVM certificate validation to qualify the flow.
- Native browser orchestration has explicit transaction phases: commit and release native generation/user/credential/attestation locks before any Domain/Core HTTP request. Core ports synchronously call native admission/factor/journal endpoints; an outer native transaction must not hold locks or hide uncommitted evidence across that round trip. Verify this with the real callback topology.

## Additive owning Core contracts

Retain the five existing operations. Add `reserveRecoveryVerification`, `completeRecoveryVerification` and `verifyRecoveryAuthorization`, with typed request/response records and current PDP actions. Reservation/complete are separate so actual native credential checks follow a committed Core reservation. Existing generic verification cannot bypass the native reservation contract.

The reservation request contains `binding` and `challengeId`; its canonical response contains `operationId`, `challengeId`, `reservationId` (UUIDs), `providerChallengeId` (opaque string), `category` and `expiresAt`. A retry for the same still-pending challenge/binding returns the same reservation without charging or allocating again. Completion contains `binding`, `challengeId`, `reservationId` and `attestation` (opaque provider reference), always uses provider-attestation proof, and loads the exact pending stored reservation without charging another attempt. Completed-reservation retries acknowledge generically without re-verifying a factor or reopening consumption. Native browser input contains only ceremony state/CSRF and the masked secret: reservation IDs come exclusively from authenticated server-to-server Domain/Core responses. Core returns the reference only after the actual database commit, with cross-connection qualification.

The additive paths are `POST /{operationId}/verifications/reservations` (201), `POST /{operationId}/verifications/complete` (202), and `POST /{operationId}/authorizations/verify` (200), beneath the existing recovery-operation root. Preserve the original generic verification path. Online authorization verification takes `binding`, `executionId` and the exact stored receipt `expiresAt`, and returns the existing canonical receipt. It cannot allocate another execution or convert UNKNOWN into permission to execute.

Use mapped repositories and owning R2DBC transactions; no raw service SQL. Add a separate append-only boundary audit with no operation/target FK for unknown/malformed/anonymous denials. Keep existing operation audit constraints and separately reviewed offline installation. A committed sink acknowledgement is required; logging is not a durable sink.

Recovery endpoints opt out of generic HTTP idempotency/response caching. Their durable body keys and stored execution identities remain authoritative. Producer OpenAPI must declare actual success statuses and all eight bearer operations. Generate the SDK from that real producer, not handwritten Java or manually edited specifications. Hosted source integration uses distinct candidate SDK coordinates and flattened descriptors in a private temporary Maven repository; it neither installs a modified released parent/GAV nor claims publication.

## Support PIN

Add a distinct CIAM credential for telephone/customer-support knowledge. The selected default is eight numeric digits, masked entry/confirmation, weak-sequence rejection, salted slow hashing, separate three-failure budget/hold and credential generation. PIN failure does not reset or silently unlock ordinary login. A PIN is knowledge only.

An eight-digit PIN additionally requires a versioned HMAC pepper before native slow hashing. Pepper keys contain at least 256 random bits and live in an external vault/secret mount, outside the identity database, images, logs and repository. Bind the keyed input to realm and subject. Store only its key version with credential metadata. Missing/revoked keys refuse verification. Rotation retains an explicitly approved old verification key only for its configured transition window; re-entry/replacement upgrades the credential. Emergency key revocation invalidates the affected PINs and requires strong-authenticated replacement. No background process can reconstruct the PIN. Hardware-backed production key custody is recommended; the external pepper requirement is a selected product control, not a claim of universal European law.

Creation, replacement, rotation and revocation require fresh native password plus enrolled possession through a dedicated ordinary-authentication step-up flow. The account surface shows status and lifecycle dates; forgotten PINs are replaced after strong authentication. Submitted PINs and hashes are not returned, logged or forwarded to business services. Support operators receive only a short-lived, context-bound verification reference through the qualified owning support contract. Caller ID and an existing verified phone record are not possession proof. The result cannot authorize login, unlock, payment or staff impersonation.

Workforce acting for a customer preserves the actual STAFF actor. Purpose, customer, tenant, permitted actions, case/call, expiry and required approval come from the owning authorized service and are rechecked at every hop. Support PIN knowledge never substitutes for that delegation.

## UX and documentation

Use the approved identity/lockup, self-hosted Manrope, shared tokens and isometric artwork. Native recovery and PIN pages use the existing authentication composition, masked credentials, meaningful generic failures, accessible labels/focus and English/Spanish browser locale. Review mobile/desktop light/dark; preserve the existing qualified account/admin branding.

Document installation, issuer/population configuration, API/state sequence, supported storage, audit/retention, factor enrollment, self-service versus assisted recovery, support PIN lifecycle, upgrades, failure reconciliation and evidence. Repository description/topics explain the actual CIAM scope. Documentation distinguishes implementation, source qualification, generated artifacts, real provider/consumer acceptance and production/regulatory approval.

## Required proof

Real native password/enrolled-TOTP unlock for customer and workforce; wrong/missing/replayed factors; no enrollment during recovery; swapped realm/subject/tenant/client/generation; held/manual/federated/service accounts; generic failures; CSRF/origin refusal; operation expiry; persisted budgets; concurrent consumption/execution; admin enable bypass; credential/hold races; restart retention; response-loss reconciliation; online/offline session retirement and fresh sign-in. Exercise actual Core persistence and Domain generated SDK, not mocked success ports. PIN tests cover strong-auth lifecycle, hashing/no retrieval, wrong/replayed/out-of-context verification, separate lockout and BPO authority refusal. Record unexecuted or external gates explicitly.
