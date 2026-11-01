# Third-party proofing and the KYC/KYB system of record

The selected operating model keeps Core KYCB as the authoritative KYC/KYB record owner and Domain as the integration/orchestration layer for a third-party verifier. Native Identity retains credentials and current account eligibility. The eIDAS framework is a design baseline; no verifier, biometric engine, notified scheme, qualified service or bank-approved procedure is selected by this repository.

This page explains the implemented recovery extension points and what the eventual vendor integration must add. It is not an invented vendor API or a success adapter. The [Domain system-of-record contract](https://github.com/fireflysoftwaresolutions/domain-customer-kyc-kyb/blob/68fa0b7fc849dd3e4dab7756493e344a331bb478/docs/identity-system-of-record.md) is the owning reference; [EU/US controls](controls-matrix.md) explains legal applicability.

## Separate the decisions

| Decision | Owner | What it does not establish |
| --- | --- | --- |
| A recorded KYC/KYB status | Core, written through the approved workflow | That authentic external checks occurred, that a mandate is current, or that credentials may be replaced |
| Provider result authentication | Domain adapter and the approved verifier trust profile | That the result matches the existing bank customer or satisfies every use-case policy |
| Evidence/reference/purpose acceptance | Core under the selected policy, with authoritative reference validation | Current Native account eligibility or financial authority |
| Credential replacement | Native Identity after exact consumed-grant validation and locked current-state checks | Customer onboarding approval, payment consent, workforce recovery or staff impersonation |
| Banking CIP/AML/mandate acceptance | The institution's designated business/compliance owners | A generic identity-login capability |

The issuer/opaque subject is the identity reference. A protected canonical party UUID links it to Core. Email, name, phone number, provider redirect parameters and browser-supplied `approved=true` cannot establish that relationship.

## What is persisted today

Core already stores party-linked KYC/KYB workflow outcomes, document/corporate/UBO references and power-of-attorney records. Credential-loss recovery separately persists cases, provider-start reservations, immutable provider sessions, original expiry, bounded refusals and grants, evidence references, canonical authorization/execution and transition audit.

The verified evidence envelope carries the exact case/binding/provider/policy/session, evidence ID/digest, reference UUID, verification/expiry times and document, live-match, fraud and reference checks. Core requires all four checks, `referenceId == binding.partyId`, freshness and current Native admission before a grant. That equality is a binding check; no live authoritative resolver authenticating the existing party has been supplied.

`policyId` is currently opaque, without a separate policy-version model. `evidenceDigest` is a bounded opaque value, not a defined algorithm/canonical representation calculated and verified at this boundary. Successful evidence ID/digest are persisted with the grant; the complete richer assurance envelope is not a structured trust dossier. Those limits are explicit so a production adapter cannot be accepted merely by filling mandatory strings.

Power-of-attorney records contain parties, scope, signing/joint-signature conditions, limits and validity flags/dates. Company registration, UBO status or a stored `signingAuthorized` flag does not implement issuer trust, legal mandate validation or revocation monitoring. Customer credential-loss authority does not confer corporate representative or employee authority.

## Implement the existing port

The production recovery extension point is Domain's `ReproofingProviderPort`:

| Operation | Required behavior |
| --- | --- |
| `providerId()` | Identifies the explicitly selected provider; cannot silently select a synthetic verifier |
| `begin(ReproofingCaseResponse)` | Start or reconcile the provider session using Core's persisted `providerStartId` as the actual provider idempotency key; return the exact provider session and allowlisted HTTPS journey URL |
| `verify(ReproofingEvidenceRequest)` | Independently retrieve and authenticate the provider-owned result for Core's exact stored case/session/nonce/customer/policy; return genuine positive or negative evidence only |

For ordinary KYB workflows the existing `KybVerificationPort`/`KybProviderPort` are separate product extension points. Implementing onboarding verification does not automatically implement recovery evidence or an unlock decision.

An ambiguous start timeout must reconcile the original reservation/session. Do not create another session, renew expiry or invent a new verification opportunity. A callback/redirect is a notification to retrieve evidence, not proof of approval. Authenticate issuer signatures/transport and verify the approved trust profile, payload binding, freshness, replay and current result status.

The provider journey opens separately while the native ceremony retains its Strict same-site cookie. Returning to the native page checks the result; it does not accept arbitrary cross-site callback parameters as authority. Core independently obtains evidence through the separately authenticated private verifier and obtains fresh Native admission before issuing a purpose-bound one-time grant.

Pending/unavailable/malformed results remain operational errors, not fabricated rejection or approval. Genuine authenticated negative checks can finalize only that case's refusal budget. Fully verified grant issuance separately charges the durable subject/epoch ledger. See [credential-loss recovery](credential-loss-recovery.md) for the complete protocol and budgets.

## Establish the vendor assurance contract

The following are production acceptance requirements; they are **not structured fields or validators already implemented**:

| Area | Evidence that must be agreed and verified |
| --- | --- |
| Scheme and assurance | Scheme/jurisdiction, notification/status evidence, claimed level separately from the relying party's validated trust profile and decision time |
| Existing identity | Authenticated natural/legal person identifiers and approved mapping to the existing party UUID; no account creation or email/name auto-linking |
| Representatives | Mandate issuer/source, scope, delegation and joint-signature limits, validity, suspension/revocation and current organization linkage |
| Provenance | Actual issuer trust, verification methods/time, freshness/expiry, status/revocation, fraud checks and original provider-session correlation |
| Policy/evidence | Immutable policy version and decision basis, retrievable evidence reference, specified hash algorithm/canonical representation and verified retrieval |
| Data handling | Purpose, lawful processing, minimization, biometric/document ownership, retention/access, residency/transfers, processors/subprocessors and deletion obligations |
| Operations | Idempotent reconciliation, availability/pending semantics, incident escalation, alternate evidence and vendor/bank conformance environment |

An authenticated JWT proves an assertion under the approved key/algorithm/issuer checks; it does not make a vendor legally qualified or every claim true. An `acr` authentication context is not a substitute for verified identity-claim provenance. [OpenID Connect for Identity Assurance](https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html) is a possible representation reference, not an integration installed here.

eIDAS assurance, GDPR biometric processing, bank customer-identification requirements and corporate mandate acceptance are related but distinct decisions. The [controls matrix](controls-matrix.md) provides their scope and evidence owners. Do not attach raw document images or biometric templates to Keycloak attributes, these application tokens or generic audit logs.

## Prove conformance before activation

Run the actual adapter against the documented vendor interface and approved controlled environment. Cover successful and genuine negative outcomes; pending/outage/malformed assertions; wrong/forged issuer; stale/replayed/swapped sessions; changed account/party/contact/hold state; expired evidence; missing mandate/revocation; and original-reservation reconciliation after timeout/restart.

Verify evidence retrieval/hash and policy-version traceability under the agreed model. Prove that Core independently accepts only the exact reference/purpose and Native independently rejects no-longer-eligible accounts. Verify notification, alternate-evidence and escalation procedures with the institution. No test-classpath success fixture can satisfy those gates.

Until those decisions and integration are accepted, recovery remains disabled for real deployment. The [open-source evaluation](identity-proofing-evaluation.md) is research history; it does not select or install a verification engine. Jafly stays provider-neutral and acquires no Identity dependency.
