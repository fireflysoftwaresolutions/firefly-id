# Integrate third-party identity verification

Credential-loss recovery requires a third-party verifier that can establish the person's identity against an existing customer reference. Core KYCB owns the KYC/KYB records and recovery decision. Customer Domain integrates the verifier. Native Identity owns credentials and current account eligibility.

No production verifier, biometric engine or approved vendor procedure is included. Select the provider and its assurance profile before enabling [credential-loss recovery](credential-loss-recovery.md). Existing KYC/KYB status, corporate records or a staff assertion alone do not authorize credential replacement.

## Assign the responsibilities

| Participant | Responsibility |
| --- | --- |
| Institution | Approves reference-identity matching, required checks, vendor trust, data handling and escalation |
| Third-party verifier | Performs the agreed external checks and exposes authenticated results |
| Domain adapter | Starts/reconciles sessions and authenticates retrieved provider results |
| Core KYCB | Persists cases and evidence references, accepts exact purpose-bound evidence and issues one-time authorizations |
| Native Identity | Independently confirms current local eligibility and performs the exact credential transition |

Keep the issuer/subject and protected party UUID relationship authoritative. Email, name, phone number, browser parameters and a supplied approval boolean must not create or relink that relationship.

## Implement the Domain provider port

Supply exactly one selected implementation of `ReproofingProviderPort`:

| Operation | Input | Output and obligations |
| --- | --- | --- |
| `providerId()` | Server configuration | The explicitly selected provider identity |
| `begin(ReproofingCaseResponse)` | Stored case, immutable customer binding, configured policy and `providerStartId` | Provider session ID and optional HTTPS journey URL at the configured verification origin |
| `verify(ReproofingEvidenceRequest)` | Core's stored case, binding, provider, policy and provider session | Independently authenticated provider evidence or a genuine operational/negative outcome |

Use `providerStartId` as the provider's actual idempotency key. Following a timeout or restart, retrieve or reconcile that same session. If the provider cannot resolve an ambiguous start, stop for review; do not create another opportunity or renew the case.

A provider callback can notify an adapter to retrieve results, but browser redirects and callback fields are not proof. Implement the selected vendor's signature/authentication, issuer trust, session binding, freshness and replay requirements. There is no generic public approval callback.

Ordinary KYB ports such as `KybVerificationPort` and `KybProviderPort` serve separate workflows. Implementing an onboarding check does not automatically implement credential-loss proofing.

## Return evidence for the exact existing customer

The private evidence response contains the case and immutable binding, provider/policy/session identifiers, opaque evidence ID/digest, reference UUID, verification/expiry times and these checks:

| Check | Required meaning |
| --- | --- |
| `documentAuthentic` | Agreed document and issuer authenticity checks passed |
| `liveMatch` | Agreed live capture and matching policy passed |
| `fraudCleared` | Required fraud checks passed |
| `referenceMatched` | Approved authoritative evidence binds the existing customer reference |

Core requires all checks, freshness, the exact stored case/session/policy and `referenceId == binding.partyId`, plus fresh Native admission. That equality does not itself authenticate the party reference: the institution and adapter must supply the approved authoritative mapping process.

Evidence verification uses Domain's private `POST /internal/identity-recovery/evidence`, callable only by the separate Core verifier identity. Native's case-orchestration identity is refused. Use dedicated Basic credentials over validated HTTPS, exact origins, mounted secrets and bounded timeouts; never send those credentials to the browser.

Provider-pending or unavailable results must remain operational conditions. Only genuine authenticated negative evidence should spend a case refusal opportunity. Forged, stale, swapped, replayed or incompletely bound results cannot issue a grant. See [case limits and retries](credential-loss-recovery.md#limits-errors-and-retries).

## Agree the production assurance profile

Before connecting real customers, define and verify:

- Provider/scheme trust, jurisdiction and the relying party's accepted assurance profile.
- Authentic existing-person identifiers and their mapping to the protected party UUID.
- Required document, live-match, fraud, freshness, status and revocation checks.
- Policy versioning, decision basis, retrievable evidence references and a defined digest algorithm/canonical representation.
- Document/biometric ownership, processing purpose, retention, access, residency/transfers and deletion responsibilities.
- Pending/outage behavior, ambiguous-start reconciliation, alternate evidence, incident response and human escalation.
- Any separate representative/mandate issuer, scope, delegation, joint-signature, validity and revocation rules.

The current `policyId` and `evidenceDigest` are bounded opaque fields; they do not provide a structured assurance dossier, policy-version model or independently specified digest scheme by themselves. Company registration, UBO status or a stored signing flag does not establish current legal representative authority. Credential replacement does not grant banking or corporate permissions.

Keep raw documents and biometric templates with the approved evidence owner, outside Keycloak profile attributes, application tokens and generic logs. Configure notification delivery and its operator response separately. Third-party integration also needs the institution's data, security and operational approval; a successful technical response is not vendor certification.

## Activate and operate

Configure the selected provider/policy and allowlisted verification origin in all owning services, as described in [credential-loss configuration](credential-loss-recovery.md#configure-core-and-domain). Verify positive, negative, pending, outage, replay, substitution, expiry and interrupted-start behavior against the actual vendor environment. Confirm that changed native credentials, contacts, links or holds prevent unfinished recovery and that notifications reach the previously verified channel.

Keep recovery disabled until those prerequisites and the operating procedure are satisfied. Telephone/BPO verification, workforce recovery, privileged recovery, passkey/external-store replacement and institution-specific mandate enforcement need their own implementations and owners; none is created by this provider port. See [support PIN](support-pin.md) for the available customer lifecycle and the absent assisted-verification service.
