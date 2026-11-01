# Credential-loss recovery wire contract v1

Companion to `2026-10-31-credential-loss-recovery-design.md`. Product-private protocol, independently implemented DTOs; no Jafly or Keycloak dependency in the customer/Core contracts. Timestamps are UTC ISO-8601, canonical UUID strings; DTO toString must redact binding/authorization/evidence. Root path at Core and Domain: `/api/v1/identity-recovery/cases`.

## Data

`ReproofingBinding`: `issuer` (HTTPS issuer), `realm`, `tenant`, `subject`, `partyId` (UUID), `population` (HUMAN only in customer owners), `purpose` (exact CREDENTIAL_REPLACEMENT), `generation`, `credentialRevision` (complete supported credential snapshot), `nonce` (unpredictable native ceremony ID). Strings bounded to 512, nonce to 128; no credentials, email, documents or biometric templates. Strict exact comparison; do not auto-link.

`CreateReproofingCaseRequest`: `binding`.

`ReproofingCaseResponse`: `caseId` UUID, `binding`, `status` (PENDING, VERIFIED, CONSUMED, EXECUTED, DENIED, EXPIRED), `providerId`, `policyId`, `providerSessionId` nullable, `expiresAt`, `authorization` nullable.

`BindReproofingSessionRequest`: `binding`, `providerSessionId` (opaque, max512). Provider and policy are server configuration, not request choices.

`ConfirmReproofingRequest`: `binding`. No user-supplied decision/proof/approval. Core calls the authenticated evidence-verifier endpoint using its stored exact case/session/provider/policy. Domain's adapter queries the actual provider server-to-server. Asynchronous providers may implement their own authenticated callbacks internally; no generic unauthenticated approval endpoint is supplied.

`ReproofingAuthorization`: `caseId`, `authorizationId` UUID, `executionId` UUID (canonical once-generated), `binding`, `evidenceDigest`, `policyId`, `expiresAt`. The unguessable authorization ID stays on private server calls; native browser receives no grant. First grant expiry <= min(caseExpiry, databaseNow+120 seconds), preserved forever on retry.

`ReproofingAuthorizationRequest`: `binding`, `authorizationId`, `executionId`.

`RecordReproofingExecutionRequest`: `binding`, `authorizationId`, `executionId`, `outcome` (exact CREDENTIALS_REPLACED).

`ReproofingEvidenceRequest`: `caseId`, `binding`, `providerId`, `policyId`, `providerSessionId`.

`VerifiedReproofingEvidence`: `caseId`, `binding`, `providerId`, `policyId`, `providerSessionId`, `evidenceId` (opaque), `evidenceDigest`, `referenceId` (exact existing party UUID), `verifiedAt`, `expiresAt`, `documentAuthentic`, `liveMatch`, `fraudCleared`, `referenceMatched`. Core requires all checks true, exact matching fields/reference, approved configured provider/policy, freshness, <=caseExpiry, plus native current admission. This response is private verified adapter output; it is never accepted from browser or the public controller body. Adapter authenticates the provider response and approved reference binding, not just parsed booleans. Test adapter only in src/test.

`ReproofingAdmission`: `binding`, `eligible` boolean, `expiresAt`. PREPARE validates an existing native ceremony and exact snapshot (including decoy), not replacement eligibility. ADMIT must require a genuine eligible local HUMAN and current immutable snapshot; no hold/admin/service/federated/unsupported authenticator. Domain/Core validate returned binding and expiry (never beyond original ceremony).

`ReproofingExecution`: `caseId`, `executionId`, `binding`, `outcome`, `committedAt`. Native journal returns an exact committed execution, including original binding after replacement. It is not authority to mutate again.

## Endpoints

Core (all private, feature disabled by default):
- POST root: create idempotent case by immutable native binding/nonce; configured provider/policy, 600-second case TTL bounded by native original expiry. Calls Native PREPARE before opening.
- GET /{caseId}: exact workload authorization and requested binding; use POST /{caseId}/inspect with binding instead of GET if avoiding identifiers in query. Canonical inspection operation is **POST /{caseId}/inspect**.
- POST /{caseId}/provider-session: bind session once (same value retry allowed), preserve expiry.
- POST /{caseId}/confirm: require exact binding/session, reserve durable failed-confirmation opportunity, verify Domain evidence remotely and Native ADMIT outside DB locks, recheck under lock; create authorization once. No provider, failure/unavailable result => no grant. Finalized successful confirmations return same grant without re-verifying evidence; expired grants never renew.
- POST /{caseId}/authorizations/consume: fresh Native ADMIT outside DB transaction, exact current immutable binding, atomic one-time transition VERIFIED→CONSUMED for canonical execution. Identical request can return same consumed receipt for that same execution only until original expiry; a different execution is refused. No second consumption/audit.
- POST /{caseId}/authorizations/verify: returns same still-live CONSUMED authorization only for exact request; VERIFIED is not enough.
- POST /{caseId}/executions: verify exact native committed journal over authenticated RPC outside DB lock; transactionally record once without replacing original grant/case/expiry/budgets. Expired EXECUTED can reconcile audit only against the exact journal, never authorize mutation.

Domain exposes the same root, create/inspect/confirm/consume/verify/executions operations as native-facing orchestration using genuine generated Core SDK. It does not expose provider-session directly to native. Its create operation calls Core create, adapter begin bound to case/nonce/digest, then Core bind-session. The browser-safe provider URL is returned only by Domain in `ReproofingJourney` = `case` (ReproofingCaseResponse), `verificationUrl` (nullable HTTPS, exact configured origin; never substitute a caller URL). On create retries, adapter begin is idempotent on caseId and must not generate another proofing opportunity. Domain cannot reconstruct session state from a JVM map.

Private Domain verifier: POST `/internal/identity-recovery/evidence`, consumes ReproofingEvidenceRequest and calls adapter verify for the stored provider session with cryptographic provider binding. Only Core evidence-verifier workload may call it; native workload is refused.

Native private RPC: POST `/firefly-recovery/lost-credentials/rpc/{prepare,admit,journal}`; request `ReproofingNativeRequest` = `binding`, `caseId` nullable for prepare/admit, `executionId` nullable for prepare/admit. PREPARE/ADMIT respond ReproofingAdmission, JOURNAL responds ReproofingExecution. Core and Domain have separate grant-disabled clients; only Core can query journal, exact allowed route/client policy. TLS and no redirects. Native never uses these clients for ordinary OAuth grants.

## Workload security

Each service receives product-specific **HTTP Basic over validated TLS** through Spring Security, with distinct explicit identities/secrets for native→Domain orchestration, Domain→Core case operations, and Core→Domain evidence verification. Secrets read from mounted files/environment, not committed defaults. Authenticate first, then enforce exact action/client, configured issuer/realm/single population/purpose and fresh admission. Core/Domain use the independent generic framework normally but acquire no Identity/Jafly provider coupling. Default-off feature paths still have a deny-by-default chain; application-wide unrelated routes retain their existing policy.

Native private RPC validates its distinct grant-disabled realm clients using the existing native private-workload approach. Realm/server attributes are administrative configuration, never writable user-profile attributes. Domain and Core must not accept a successful transport identity as replacement proof. Core calls both Domain evidence verification and Native current admission independently.

## Concurrency, budgets and native activation rulings

Core stores cases/grants/binding/evidence/audits under installer-owned SQL with uniqueness on issuer+nonce and canonical authorization/execution IDs; actual PostgreSQL time/row locks or conditional updates provide authority. A separate durable verified-grant ledger keyed by issuer+subject+generation prevents restarting a case from creating more than three fully verified replacement authorizations in the same recovery epoch. Unknown targets use private decoy identities, same generic initiation/provider flow, and can never pass ADMIT. Do not expose case status publicly.

Native supports an enabled local user or an eligible permanent authentication lock; it never reuses existing known-password `eligible()` as the whole predicate. It snapshots all credentials and refuses unsupported types (passkeys/foreign stores) rather than leaving one usable. Native enrollment secrets require explicitly provisioned 256-bit encryption at rest; passwords never persist. Old password/TOTP and support-PIN authority are retired atomically with activation/session retirement/journal and durable notification intent. Existing locked-user counters and case budgets are never cleared merely for retry. Real notification delivery/biometric and workforce acceptance are separate external gates, production remains disabled.

## Independent builder review rulings (authoritative clarifications)

- Unauthenticated claims must not exhaust a victim's target recovery budget or disable their enabled account. Provider refusals are bounded to the server ceremony/provider session (three by default); provider outages are operational unavailability, never customer failure. The durable subject/generation budget counts at most three grant issuances only after ALL required identity-proofing checks and fresh native admission pass. Invalid document, failed liveness/fraud or a candidate reference match alone cannot debit this ledger. A successful same-case retry does not charge again. Native separately bounds new-factor enrollment failures under the proven grant. No caller-supplied identifier/mismatched reference charges another person's budget. Cross-case tests must prove preservation of this verified-grant budget. Deployment additionally requires its approved source-abuse/rate policy; no remaining attempts are exposed.
- Enabled local users acquire a stable persisted recovery epoch under their user/state lock, shared by ceremonies. Do not reset that epoch or any budget on new initiation; only a canonical completed credential transition advances it. The known-password path retains its existing purpose/behavior.
- Core persists a once-generated provider-start reservation key before external begin; Domain must use that case-bound key as the provider's genuine idempotency key. Provider session binding is immutable. If the selected provider cannot reconcile an ambiguous begin, refuse/review rather than creating another session. A Domain restart has no authority to retry with a new key. Include `providerStartId` UUID in ReproofingCaseResponse, generated once by Core at create.
- Core evidence requests use only Core's stored immutable provider/session/case/binding/policy. Domain evidence endpoint authenticates the exact Core verifier identity and independently retrieves the actual provider-owned result, never accepts accepted/reference/evidence claims from that request. Native and Domain case callers cannot invoke this endpoint.
- Add a new native transactional notification outbox, snapshotting the previously verified email destination and its digest. Contact verification/destination changes invalidate unexecuted authorizations. A bounded native dispatcher with durable attempts/delivery state uses the approved Keycloak email provider; after expiry it can only deliver an already committed notification. It never unlocks, alters contacts or grants authority. Synthetic activation requires durable enqueue; real delivery/channel/bank acceptance remains an explicit production gate, with retries/failures retained. No raw email/message/credentials in evidence logs.
- New private native exact-journal RPC may read a canonical committed journal after grant/ceremony expiry using its separate authorized workload identity and exact original binding/case/execution. It cannot extend expiry, sign a human assertion, consume or mutate. An expired unexecuted grant is always refused. Native final mutation uses database time under lock, after remote calls have completed.
- Retiring native sessions/not-before does not prove immediate rejection of old self-contained JWTs at all receiving services. Keep receiving-service live enforcement as a separate unqualified gate; do not change Jafly or claim platform-wide immediate JWT revocation.

- Core additionally claims each authenticated provider/evidence ID once across cases (database uniqueness), preserving exact same-case idempotency. A provider must not recycle one evidence authorization for a new case/nonce. This is independent of the subject verified-grant budget.

- PREPARE always authenticates the exact server ceremony without asserting replacement eligibility (`eligible=false` is valid). Domain create AND confirm use this preparation predicate. Core evaluates native ADMIT only after independently verified provider results; Domain consume/verify continue to require current eligible ADMIT. This preserves generic pre-proofing handling and does not treat a case-start workload as an authenticated customer.
- `VerifiedReproofingEvidence` denotes an authenticated, fresh, case-bound provider result, including a genuine negative outcome. Domain validates the signed provider envelope and stored case/session/policy, but does not suppress authentic negative document/liveness/fraud/reference flags as an operational outage. Core independently requires every affirmative check and the exact existing reference to grant; genuine rejected evidence spends only that case's failure budget, never another customer's verified-grant ledger. Forgery, untrusted responses and provider outages remain errors, never successful proof or a fabricated rejection.
