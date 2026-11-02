# Decide how your institution will operate identity

Use this guide to turn deployment choices into approved settings, operating procedures and acceptance evidence. Complete it for the actual legal entity, environment, user populations and receiving applications. Keep names, infrastructure details and evidence in the institution's controlled records, outside this public handbook.

The [production checker](production-readiness.md) checks supplied configuration files. Its `decisions_required` output identifies work that needs real deployment inputs; it does not certify deployed controls or grant production approval. A completed decision record also does not install a factor flow, establish a support mandate or connect an application policy owner. Verify the selected behavior before opening the affected journey.

## Recommended first activation proposal

The approved direction is consultation/support for BPO, and named password-plus-user-verifying FIDO2 administration with separate named emergency accounts. The following is a concrete proposal for the remaining choices, **pending institutional selection and destination acceptance**. Every person and production service remains unassigned until the institution names them. Copy the stable choice identifiers into the controlled decision record and select, amend or reject each recommendation. They refine the checker decisions below; they do not change its output contract.

The numeric targets below are engineering recommendations and unimplemented acceptance objectives, not regulatory mandates or measured operating guarantees. The rationale for the hardware recommendation is [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html): phishing resistance depends on cryptographic binding to the verifier, and protected hardware can prevent extraction of an authentication key; syncable keys have different export and custody properties. A device label or user-verification flag alone establishes neither those properties nor an AAL certification.

### BPO consultation proposal

| Choice | Recommendation | Alternative and tradeoff | Exact institutional decision to record |
| --- | --- | --- | --- |
| `BPO_OWNER` | An accountable internal customer-service owner, with security approval, appoints a named case/authorization service and its integration/operating team. Outsourcing management owns provider delegation. | Keeping verification unavailable avoids unowned authority; selecting a vendor still requires an accountable internal owner and an accepted protocol. | Name the person, approving security owner, service/protocol/version, real case/call source, provider/tenant delegation source and escalation contacts. No owner or service is selected by this proposal. |
| `BPO_SCOPE` | Start with masked case-summary, customer-identity/contact and case-status reads, plus narrowly bounded support-case assistance. Proposed receiver actions are reading those fields, appending a non-sensitive case note and requesting a human follow-up on that same case. | Read-only consultation reduces mutation exposure; additional assistance increases permission and audit requirements. Financial/account changes, impersonation and customer tokens remain outside this initial scope. | Approve each exact receiver action, endpoint/resource, masked fields, customer/tenant/case binding and approval rule; reject unlisted actions. These descriptions are proposed permissions, not supplied APIs. Native `VERIFY_SUPPORT_PIN` remains knowledge verification only. |
| `BPO_CHANNEL` | Prefer an existing authenticated first-party customer application with independently proven enrolled possession, explicit binding to the same case/call and private PIN entry. Exclude the operator, recordings, transcripts, analytics and logs from the PIN. Propose possession evidence no older than 60 seconds at grant admission. | Private IVR is a fallback only after independently accepting its input/recording boundary and a separate possession check. Caller ID, a PIN match or staff login supplies no possession proof. If neither channel is qualified, verification stays unavailable. | Name the existing application or IVR service, possession owner/mechanism, freshness bound, case/call-binding protocol, private-input path and channel/privacy acceptance evidence. No application or IVR integration is supplied or assumed. |
| `BPO_GRANT` | Recommend a 60-second original grant TTL, within the native 120-second admission ceiling, and bind its use to one approved consultation operation. Preserve native one-time consumption and the three-attempt hold. | A shorter TTL can expire during a call; longer authority increases exposure and would need explicit review within the native ceiling. | Approve TTL, operation binding, customer/operator/tenant/purpose and original-reference reconciliation. No renewal, replacement nonce, replay, refunded slot or counter reset may repair an ambiguous outcome. |
| `BPO_CURRENT_AUTH` | At every protected receiver operation, check current employment, provider delegation, case/customer/tenant scope, approvals and holds. Propose no positive authorization caching for initial high-risk access, a two-second policy timeout and refusal on outage or indeterminate state. | Accepted caching can improve availability but creates a measurable revocation window; it requires a separately approved exposure bound and invalidation tests. | Name each authoritative source and receiver owner; approve timeout, zero positive-cache TTL, revocation bound and queued-work commit checks. A consumed native proof does not authorize business access. |
| `BPO_OPERATIONS` | Assign service operations to stop new checks and reconcile the original proof/reference with the case owner and native journal; assign independent audit custody and security incident ownership. Propose alert delivery within 60 seconds, responder acknowledgment within 15 minutes, reconciliation triage within four hours and access/delegation review every 30 days. | Slower targets reduce staffing cost but extend uncertainty; dependent consultation remains suspended until the original result is established. | Name on-call, reconciliation and audit owners; approve targets, retention/custody, alert tests and the stop/resume authority. These objectives are not implemented monitoring. Preserve original proof, generation, attempts and journal when response or audit status is unknown. |

The missing production authorization factory, private caller/channel and receiving-service policy checks must still be implemented and qualified through the [BPO activation procedure](support-pin.md#activation-and-acceptance). The [repository evidence scope](support-pin.md#scope-of-repository-checks) describes the existing source and synthetic retained-database exercises; it does not accept the proposed channel or service.

### Privileged administration proposal

| Choice | Recommendation | Alternative and tradeoff | Exact institutional decision to record |
| --- | --- | --- | --- |
| `ADMIN_FACTORS` | Keep the approved named password plus pre-enrolled user-verifying WebAuthn key baseline. Issue two institution-owned, device-bound hardware keys per ordinary administrator, with primary and spare in separate approved custody. Qualify approved AAGUIDs and attestation policy on real devices. | Platform or synced factors have different custody/recovery and key-export risks. They require separate risk/assurance approval and qualification and are outside the proposed initial profile. Two hardware keys add inventory and spare-custody work. | Approve models, algorithms, hardware/non-exportability evidence, AAGUID allowlist, attestation trust/enforcement, browsers, spare release and lost-key handling. A preference setting alone cannot prove hardware provenance or refusal of an unapproved key. |
| `ADMIN_ROLES` | Use named accounts with task-specific minimum roles; separate ordinary and emergency permissions. No shared daily superadmin. | Broad roles simplify operations but enlarge damage and weaken separation of duties. | Approve the exact per-person, per-realm/client role-to-operation matrix, forbidden-operation tests, approvers and revocation owner. The role matrix remains to be selected. |
| `ADMIN_INGRESS` | Fix authentication origin/RP ID and console origin before enrollment. Keep `/admin/` and `/realms/master/` private, restrict backend ingress to approved proxies and isolate management port 9000. Test unauthorized/public and direct-backend denial, including forged forwarding headers. | A later origin/RP change requires enrollment/transition planning; a separate admin hostname alone does not deny public ingress. | Approve exact RP/origins, redirects, TLS/proxy trust, source networks, route filters and backend/management access rules, with positive and denial evidence. |
| `ADMIN_ENROLLMENT` | Supervise enrollment and replacement with distinct verifier and approver, authoritative HR/current-employment proof and restricted setup access. No support-PIN or customer-recovery fallback. | More supervision adds staffing and recovery time; any alternative needs separately approved identity evidence and custody. | Name verifier, approver, enrollment operator and lost-factor authority; approve identity checks, setup window, device inventory, replacement and all-keys-lost procedure. A password reset cannot prove the lost factor. |
| `ADMIN_EMERGENCY` | Keep separate named emergency accounts with the same password-plus-UV-key factors. Name custodians and require a two-person authorization/custody release procedure, monitored and rehearsed. Close access after use by retiring sessions and temporary grants and resealing custody; preserve the account and audit history. | Separate custody limits ordinary-factor dependence but requires available custodians and rehearsal. This is an institutional procedure, not a native dual-control capability or weaker factor path. | Name requester, approvers, password/key custodians, alternate custodians and incident scope; approve maximum access duration, release/return evidence and post-use review. Do not destructively delete accounts to close emergency access. |
| `ADMIN_OPERATIONS` | Retain the actual catalogue limits: 300-second SSO idle, 3,600-second maximum session and 60-second access token. Propose alert delivery within 60 seconds, acknowledgment within 15 minutes, review of every emergency use within one business day, role/custody review every 30 days and emergency exercise every 90 days. | Tighter limits add reauthentication and staffing; longer exposure needs separate approval. Session limits alone do not retire every issued token. | Name monitoring, incident, role-review and custody owners; approve targets and measurement scenarios. Monitoring/review/exercise targets are recommendations awaiting implementation and destination acceptance; the existing catalogue is configuration evidence only. |
| `ADMIN_TRANSITION` | Use a controlled settings-level retained transition: preserve original identities, credentials, mappings, holds, counters and journals; prove valid ordinary/emergency access; retire earlier authority; remove bootstrap secret injection. | Exact-candidate import belongs in an empty owned database; overriding a retained realm is destructive and does not preserve the original state. | Approve checkpoint, change/recovery owners, readback, retained-state inventory and all retirement tests, including original signed-action-link expiry when immediate revocation is unavailable. Keep access closed until original/preconfirmation links and all other earlier authority are proven unusable. |

The [Keycloak reverse-proxy guide](https://www.keycloak.org/server/reverseproxy) supports restricting administrative routes and direct backend/management exposure; configuring a private admin origin alone is insufficient. Carry out the [ordered administration procedure](workforce-administration.md#supervise-enrollment-and-transition), using its [qualification and limits](workforce-administration.md#qualification-and-limits) to separate existing offline/native synthetic evidence from real hardware, network, roles, custody and destination acceptance.

### Approval record for the first activation

Before approving a scoped activation, complete this record:

- [ ] Select, amend or reject every `BPO_*` and `ADMIN_*` choice; name accountable people, approval authorities, production services and operating/escalation contacts.
- [ ] List exact allowed actions, receivers, resources, masked fields, tenants/providers and forbidden operations; attach the current-authorization and revocation tests.
- [ ] Accept the private input channel, independent enrolled-possession mechanism, freshness and case/call binding; identify the implemented authorization factory and private integration.
- [ ] Approve actual hardware, attestation/AAGUID enforcement, role matrix, RP/origins, private routes and backend/management denial evidence.
- [ ] Name enrollment/replacement verifiers and approvers, emergency authorization/custodians and the all-keys-lost authority; attach supervised enrollment and custody receipts.
- [ ] Approve measurable operations, response, reconciliation, review/exercise and retention/custody objectives; record observed results and stop/resume authority, preserving original state and proof.
- [ ] Record the exact destination, deployed revision/configuration, accepted accounts/journeys/actions and evidence references. Separate implemented/tested repository controls from missing integration and institutional selections. Unresolved fields keep that scope unavailable; a proposal or passing offline audit activates nothing.

## Maintain one decision record

For every decision below, record:

| Field | Required content |
| --- | --- |
| Scope | Legal entity, environment, exact issuers, populations, applications and operations covered |
| Accountable owner | Named approver, implementing team, operating team and escalation contact |
| Choice | Selected alternative, rejected alternatives and the risk/availability/accessibility tradeoff |
| Inputs | Configuration references, authoritative services, dependencies and custody locations; no secrets |
| Acceptance | Numeric limits where relevant, test scenario, expected refusal/success, observation time and evidence location |
| Operating procedure | Monitoring, outage response, restoration, access review and rotation responsibilities |
| Status | Pending, accepted for the recorded scope, or rejected; unavailable journeys remain disabled |
| Review | Approval date, next review, expiry of exceptions and changes that invalidate approval |

Choose measurable limits before running acceptance exercises. Terms such as “immediate,” “highly available,” “short retention” or “regular review” need explicit durations and owners. An untested or unknown outcome is pending. A later change of domain, factor flow, client, receiver, key provider, supplier or deployment topology requires review of the affected decisions.

The following identifiers match the checker. Multiple decisions can share an operating procedure, but each needs a recorded outcome.

| Checker decision | Where to resolve it |
| --- | --- |
| `LEGAL_APPLICABILITY` | [Entity, jurisdictions and information](#entity-jurisdictions-and-information) |
| `CUSTOMER_FACTOR_FLOW` | [Customer and institutional-human factors](#customer-and-institutional-human-factors) |
| `PRIVILEGED_FACTOR_FLOW` | [Workforce and administrators](#workforce-and-administrators) |
| `TRUSTED_IDENTITY_BINDING` | [Authoritative identity and lifecycle](#authoritative-identity-and-lifecycle) |
| `KYC_ASSURANCE_PROVIDER` | [Keep KYC assurance separate](#keep-kyc-assurance-separate) |
| `WORKFORCE_ADMIN_RECOVERY` | [Recovery ownership](#recovery-ownership) |
| `BPO_DELEGATION` | [Support and BPO mandate](#support-and-bpo-mandate) |
| `NETWORK_CERTIFICATES_DATABASE_PRIVILEGES` | [Public ingress and private infrastructure](#public-ingress-and-private-infrastructure) |
| `BOOTSTRAP_ACCOUNT_REMOVAL` | [Workforce and administrators](#workforce-and-administrators) |
| `RETAINED_DATA_HA` | [Availability, recovery points and recovery time](#availability-recovery-points-and-recovery-time) |
| `NOTIFICATION_CHANNEL` | [Notifications and customer communications](#notifications-and-customer-communications) |
| `CONSUMER_CURRENT_STATE` | [Current authorization at every receiver](#current-authorization-at-every-receiver) |
| `AUDIT_PRIVACY_INCIDENTS` | [Telemetry, privacy and retention](#telemetry-privacy-and-retention) |

Key custody is a shared dependency of infrastructure, retained-data recovery, notifications and audit. Record it explicitly using [Keys and custody](#keys-and-custody).

## Entity, jurisdictions and information

**Owner:** legal/compliance, with privacy, security and the relevant business owner.

**Inputs:** legal entities and licenses, operating/customer/workforce locations, services and journeys, processors/subprocessors, support access locations, categories of information and data flows. Use the applicability worksheet and primary-source references in [EU and US controls](controls-matrix.md). This guide adds no jurisdiction-wide retention period, reporting deadline or certification claim.

Choose whether entities share logically separated realms or need separate instances, databases and operating teams. Shared infrastructure can simplify operation but increases shared-failure and administrative exposure. Separate infrastructure increases cost and coordination and still requires authorization at each receiver. Hosting region alone does not determine legal applicability or prevent remote support access and transfers.

**Conservative default:** keep unassessed entities, cross-border data flows and journeys closed. Do not infer payment authority, an institutional mandate or a legal exemption from a realm name or successful sign-in.

**Acceptance:** every enabled journey and data flow has an owner and a recorded applicability outcome, including documented exclusions and exceptions. Verify that the approved locations match actual storage, backup, telemetry and support access. Route incident classification and reporting to the assigned legal/privacy owners using [incident procedures](observability-incidents.md).

## Customer and institutional-human factors

**Owner:** identity security and the customer/institutional product owner, with fraud, accessibility and the payment-service owner where applicable.

**Inputs:** covered operations, required assurance and freshness, supported devices, existing enrollment, approved recovery routes, RP ID/origins for WebAuthn, and application step-up/session requirements.

Choose the actual authentication flow for each journey:

| Alternative | Tradeoff and deployment consequence |
| --- | --- |
| Password and enrolled TOTP | Compatible with the supplied known-factor and customer password/TOTP replacement journeys within their eligibility rules; TOTP is not phishing resistant |
| User-verifying passkey/security key | Requires deliberate WebAuthn configuration and enrollment; decide authenticator/device policy, RP domain and lost-device recovery before use |
| External credential owner | Centralizes enrollment and recovery with that owner; qualify federation, stable identity binding, outage behavior and revocation separately |

These choices are not an assertion that every option provides the assurance needed for every financial action. Amount/payee confirmation, consent, exemptions and other payment decisions belong to the payment service. Institutional-human authentication does not establish authority to represent an organization.

**Conservative default:** do not promote optional customer MFA from the sandbox into an approved production factor policy. Keep protected operations closed until required enrollment, challenge and step-up are enforced. Keep unsupported factor-recovery combinations unavailable. The customer credential-loss path does not recover passkeys or external credentials.

**Acceptance:** for each enabled journey, an enrolled user succeeds; missing/wrong factors, canceled enrollment and stale or insufficient assurance cannot complete the protected action. Verify fresh authentication separately from reused SSO, and exercise account enrollment and recovery on supported devices. Record permitted SSO reuse, step-up age, application idle limit and maximum session lifetime in seconds. Confirm independent application/payer activity tracking where required; token refresh is not human activity. See [authentication policies](authentication-policies.md) and [authenticator journeys](extended-flows.md).

## Workforce and administrators

**Owner:** workforce identity/HR and security for employees; the privileged-access owner for administrators.

**Inputs:** authoritative employment status, staff identifiers, tenant membership, role inventory, corporate IdP policy, privileged factor inventory, administrative networks and emergency-access custodians.

For workforce, choose local authentication or a corporate credential owner. The supplied workforce flow requires password/TOTP on fresh authentication and can reuse eligible SSO. It is not a phishing-resistant privileged flow. Decide which workforce actions require stronger factors or fresh step-up, and prove that the selected application checks enforce them.

The selected administrator baseline is named least-privileged accounts with a password and a pre-enrolled FIDO2/WebAuthn key with user verification required, through private access. Emergency access uses separate named accounts with the same factor requirement and independent custody. The institution still selects physical keys, attestation requirements, custodians and supervised enrollment/replacement procedures. A separate emergency account can reduce dependency on the ordinary administrator's factors but adds credential custody, monitoring and periodic exercise obligations. Preparing a configuration does not enroll hardware or activate this profile on real accounts.

Resolve those remaining choices in the [ordered administration activation procedure](workforce-administration.md#supervise-enrollment-and-transition): approve hardware and roles; fix the RP/private ingress boundary; appoint enrollment/recovery authorities and emergency custodians; enroll and exercise both account types; rehearse the retained configuration change and retirement of earlier authority; then accept the destination before reopening. Attach the device-policy record, account/role inventory, origin/network record, supervised enrollment receipts, emergency procedure, legacy-authority inventory and observed acceptance results. An unassigned owner or an unknown result keeps the relevant gate pending.

Keep exact-candidate import acceptance separate from retained-master transition acceptance. Import tests belong in an empty owned database. A production retained transition requires an approved settings-level update, a consistent retained-data checkpoint and evidence that identities, credentials, mappings and journals survive. Realm JSON is not a full backup, and an overriding import removes the existing realm; it is not the retained update procedure. Neither synthetic exercise approves the institution's devices, networks or real accounts.

**Conservative default:** keep public administration closed and deny privileged actions without the approved factor and current role. Do not retain bootstrap access as the emergency procedure. Establish and verify permanent and emergency access before removing temporary bootstrap accounts and secret injection.

**Acceptance:** fresh employee sign-in cannot finish without required factors; workforce APIs reject customer issuers. Ordinary staff cannot perform administrative actions. A privileged account without the required factor cannot enter its protected flow. Demonstrate the approved emergency procedure with attributed access and session closure. Read back the account/client/role inventory and prove former bootstrap credentials are refused. Record access-review frequency and a maximum revocation delay for employment/role changes. Follow [workforce and administration](workforce-administration.md).

## Authoritative identity and lifecycle

**Owner:** customer/party owner for customers, HR/workforce owner for employees, and the institutional mandate/tenant owner for representatives.

**Inputs:** exact issuer/subject namespace, protected party/staff/tenant attributes, provisioning service identity, link-change rules and current membership/hold sources. Preserve the distinction between an identity tenant namespace and a separately typed resource-tenant identifier.

Choose supported local provisioning or an authoritative federation/provisioning integration. Local provisioning gives explicit lifecycle control but needs an operating service; federation introduces an external lifecycle and availability dependency. Neither may join an existing person by email or display name alone.

**Conservative default:** refuse missing, ambiguous, caller-editable or stale links. Keep customer/employee/institutional populations separate and do not infer an organizational mandate from membership alone.

**Acceptance:** prove joiner, mover, leaver, suspension and tenant-transfer behavior in the real receivers. Changing email/name cannot relink an identity. Profile or token requests cannot overwrite protected attributes. A removed membership or newly applied hold stops the relevant operation within its approved revocation limit, including queued work. See [claims](provider-claim-profile.md) and [current authorization](#current-authorization-at-every-receiver).

## Recovery ownership

**Owner:** the credential owner and security/fraud; HR for workforce eligibility and privileged-access operations for administrators.

**Inputs:** supported credential types, native/Core/Domain installation, original lock and hold ownership, prior factor enrollment, authoritative links, help-channel identity, escalation contacts and recovery budgets.

| Situation | Available boundary and required decision |
| --- | --- |
| Local nonprivileged customer/employee retains password and previously enrolled TOTP | Optional native known-factor unlock can clear the eligible authentication lock through configured SCA owners; approve enrollment, support and outage procedures |
| Customer loses supported password/TOTP credentials | Separate opt-in customer replacement requires the independent assurance decision below, an existing-party resolver and notification operation |
| Employee loses factors | The employee's credential owner supplies the procedure; customer replacement does not cover workforce |
| Administrator loses factors | Use the approved privileged/emergency credential-owner procedure; native self-service excludes privileged and master identities |
| Passkey/external credential loss | Use the selected credential owner's separate procedure; customer replacement does not supply it |
| Fraud, administrative or employment hold | Refer to that hold's owner; authentication recovery cannot remove it |

Choose a credential-owner process that balances access restoration with proof strength and staffing availability. An attended procedure needs trained operators, approvals, attribution and service hours; an external owner needs an agreed escalation and outage contract. A documented manual route is not a new native recovery capability.

**Conservative default:** no credential-owner procedure means no lost-factor restoration for that population. Keep optional recovery disabled until its complete dependencies are accepted. Do not use generic re-enablement, password replacement, counter clearing or a new grant to repair a protected original operation.

**Acceptance:** eligible recovery returns the person to fresh ordinary sign-in; it grants no application token or business permission by itself. Test exclusions, new holds, changed links/credentials, expired operations and exhausted budgets. Restart/interruption exercises preserve original cases, generations, reservations, expiry, attempts and journals. Reconcile an uncertain execution against its exact journal; an unknown outcome remains unresolved. Include a timed escalation exercise for each population and a safe outcome when the approved operator or dependency is unavailable. See [recovery selection](access-recovery.md) and [retained data](retained-data.md).

## Keep KYC assurance separate

**Owner:** identity assurance/customer-data and compliance, with privacy and security.

The institution must separately select and accept an independent proofing adapter and evidence policy for customer credential replacement. The distribution supplies no real proofing provider. Existing KYC status, verified email, caller ID, a support PIN or a staff login is not replacement authority.

**Inputs and acceptance:** use the [assurance contract](assurance-provider-contract.md) to establish the authenticated provider evidence, existing-party resolution, freshness, current-policy decision and bounded original operation. Assess proofing-data ownership and privacy with the applicable institution procedures. This decision does not become accepted when other deployment decisions pass.

**Conservative default:** leave customer credential-loss recovery disabled until that separate assurance integration and the rest of its operating dependencies are accepted. Ordinary login, workforce/privileged access and eligible known-factor unlock have their own scopes; their acceptance does not approve KYC assurance.

## Public ingress and private infrastructure

**Owner:** platform/network operations, PKI and the database owner, with identity security.

**Inputs:** canonical public/admin DNS names, certificate chains, exact proxy CIDRs, approved public route list, private network paths, management probes, database role/CA, secret mounts and complete deployed configuration sources.

Choose the ingress and network layout, preserving verified HTTPS from ingress to Keycloak and verified database TLS. Separate administrative hostnames help routing but do not block public routes. Network isolation and route allowlisting must also cover direct-address access. Dedicated database roles reduce authority; the actual schema privileges need inspection rather than inference from the username.

**Conservative default:** allow only required public realm/protocol/account/resource routes. Deny `/admin/`, administrative-realm access, private recovery RPC, management and database access from public networks. Trust only owned proxy addresses and overwrite incoming forwarded headers. Do not expose a new route until its caller/authentication policy is accepted.

**Acceptance:** test from outside and inside each trust boundary. Approved public flows work; administrative/private paths and direct-service bypass fail. Spoofed forwarded headers do not change trusted request identity/origin. Invalid or mismatched certificates are refused for each connection. Inspect actual role privileges, mounts, runtime command/environment/keystore and health-probe trust. A supplied file passing the checker does not establish the process's effective configuration. Include source-abuse limits and alert thresholds for login/recovery without exposing account existence or remaining attempts. See [deployment setup](regulated-deployment.md) and [configuration checks](production-readiness.md).

## Availability, recovery points and recovery time

**Owner:** service operations and database/platform owners, with each recovery-service owner and the business continuity approver.

**Inputs:** traffic/concurrency model, capacity headroom, database topology, dependency inventory, backup/restore ownership, cluster behavior, maintenance windows and cross-service consistency checkpoints.

Choose a topology explicitly. A single instance is simpler but loses service during instance failure/maintenance. Multiple nodes can improve continuity but require supported clustering, shared-state consistency, routing and database failover. A second region adds transfer, key availability and reconciliation responsibilities. Node count alone does not establish HA or zero data loss.

Record numeric availability and latency targets, peak load, maximum outage duration, **RPO** (maximum acceptable data-loss interval) and **RTO** (maximum restoration time). Record whether the objectives differ for sign-in, privileged access, recovery and notifications. Include detection, operator response, dependency recovery, reconciliation and traffic switching in the measured restoration interval.

**Conservative default:** make no HA or recovery-time claim until the selected topology meets its objectives. Keep traffic on an unverified restore target closed. Restore rehearsals use isolated copies with real email, provider submissions and application traffic blocked; preserve the source and failed state.

**Acceptance:** exercise instance and database failure, dependency outage and restart under the recorded load. Restore a consistent checkpoint with matching historical keys and configuration. Measure actual loss and elapsed recovery against RPO/RTO. Verify retained credentials, links, holds, sessions, native/Core journals, budgets and pending notices across all owners; a green health endpoint is insufficient. Test migration and rollback using compatible database/image pairs, including pending operations and fenced notification leases. Do not reset counters, replace grants or repeat proof to repair inconsistent snapshots. See [operations](operations.md) and [retained restoration](retained-data.md).

## Keys and custody

**Owner:** security/PKI and secret-management custodians, with database, identity and recovery-service owners.

**Inputs:** purpose/version inventory, supported key-provider mechanism, active and historical versions, access identities, backups, expiry/overlap, compromise procedure and restoration dependency order.

| Material | Custody and rotation decision |
| --- | --- |
| Realm signing keys | Select the supported provider/custody mechanism; routine rotation retains the needed verification overlap and tests every consumer's JWKS refresh; compromise uses separate containment |
| Server/database trust and TLS keys | Assign certificate renewal, trust deployment and expiry monitoring; verify real hostname/peer checks after rotation |
| Workload/SMTP/database credentials | Use independent identities with least authority; define supported credential rotation and outage handling, without embedding secrets in images or review files |
| Support-PIN peppers | Keep separate from database and recovery encryption keys; versioned overlap uses explicit old-key verification deadlines and fresh authenticated PIN replacement |
| Recovery encryption keys | Keep independent exact 32-byte versions needed by pending enrollment and notice destinations; new encryption uses the active version while retained versions decrypt existing records |

Secret-manager delivery to supported mounts is an operational choice. HSM/KMS custody requires a compatible, separately qualified provider/integration; it is not implied by configuring a filename. Decide who can retrieve keys, who can restore them and whether independent approval is needed. Backups without their required historical keys may be unusable.

**Conservative default:** retain needed versions under their original names, restrict mounted files as required by their implementation and refuse missing/expired material. Never replace bytes under an existing version or share PIN/recovery keys. No automatic ciphertext migration is supplied.

**Acceptance:** rehearse routine rotation, rollback and loss/compromise response. Confirm unauthorized identities cannot read material, active services use the intended version, pending old records remain readable, expired PIN versions refuse and removed signing authority is handled by receivers according to the containment policy. Restore keys and retained records together without exposing plaintext in evidence. See [PIN keys](support-pin.md#install-and-protect-keys) and [recovery keys](credential-loss-recovery.md#protect-pending-enrollment-and-destinations).

## Notifications and customer communications

**Owner:** customer communications and messaging operations, with recovery, security and independent monitoring owners.

**Inputs:** approved SMTP service, realm mail settings, verified-destination handling, customer languages/accessibility, sender and monitor identities, worker durations, escalation contacts and observation/response targets.

Choose the real email channel, operating coverage and handling of delayed/duplicate/terminal messages. The managed worker uses separate dispatch and read-only monitoring identities. Manual dispatch has different operating coverage and does not establish worker supervision. Credential-replacement notices, applicable advance permanent-block warnings, incident/regulator notices and support correspondence are separate communications with separate owners; the recovery outbox does not implement all of them.

**Conservative default:** keep customer credential replacement closed until its channel, worker/supervision and terminal escalation are accepted. Keep private dispatch/monitoring outside public ingress. Never replace a queued destination, reset delivery attempts or replay recovery proof to fix a delivery failure.

**Acceptance:** demonstrate a real-channel test to an approved test destination, SMTP outage and recovery, missing-worker detection, stale observations, clock mismatch and terminal escalation. Record maximum observation age, queue delay, alert-detection delay and operator response time. Confirm sender/monitor credentials cannot assume each other's roles or invoke recovery-case authority. Verify notification attempts remain durable across restart. The native limit is eight attempts with a fenced lease; acceptance of a message is not proof of recipient reading, and ambiguous SMTP acknowledgement can produce duplicates. Use [notification operations](notification-operations.md) for exact settings and supplied private monitoring behavior.

## Current authorization at every receiver

**Owner:** each receiving application/service owner, with the authoritative policy/data owner and identity security. A gateway review does not cover its downstream receivers.

**Inputs:** enumerate browser applications, Experience, Domain, Core, workforce/admin APIs, background workers and other resource receivers. Record an entry per receiver and protected operation:

| Record | Required decision |
| --- | --- |
| Token/caller admission | Exact issuer, intended audience, approved algorithm, time checks, workload identity and independent human proof when required |
| Current policy | Authoritative party/staff link, membership, resource/tenant binding, holds, consent/mandate, assurance and obligations |
| Enforcement | Online current-state/introspection or accepted token-expiry window; policy evaluation and commit-time recheck for asynchronous operations |
| Timings | Maximum stale-authorization exposure in seconds, cache TTL/invalidation, request timeout and application-session revalidation/revocation |
| Outage behavior | Refusal for unavailable/indeterminate required current policy; no silent switch to weaker authority |
| Downstream calls | Receiver-specific authority/delegation and preserved original actor; an incoming token cannot be forwarded beyond its audience |
| Evidence | Owner, deployed version/configuration, acceptance exercise, measured delay and remaining restrictions |

Offline validation improves independence from the issuer but permits an already issued token to survive until the accepted expiry unless another control intervenes. Online current-state checks reduce that exposure but introduce latency and availability dependencies; caching affects the actual denial delay. Choose per operation, not just per service. General human token exchange is not configured by this distribution, and introspection alone does not establish business permission.

**Conservative default:** refuse a protected operation when its current-policy owner, delegation contract or required obligation cannot be enforced. Keep unintegrated downstream routes disabled. Do not claim immediate blocking from short token lifetimes, identity logout or a generic JWT decoder.

**Acceptance:** obtain valid sessions/tokens, then separately disable the account, retire the session, replace credentials, revoke employment/membership/mandate and change resource ownership/holds. Measure denial time at every receiver, including warm caches, independent application sessions and queued work at commit. Test wrong issuer/audience/tenant, stale policy and unavailable policy/introspection services. No receiver may exceed its approved exposure bound or accept an indeterminate authorization. See [receiver audiences](receiver-audiences.md) and [authorize every request](zero-trust.md).

## Support and BPO mandate

**Owner to appoint:** the service accountable for support cases and current authorizations, with outsourcing management, workforce security, privacy and the customer-service owner. The owner has not yet been selected.

**Inputs:** genuine staff/BPO operator, employer and current employment/delegation, customer, tenant, real case/call, purpose, action/resource, expiry, approvals, independent possession evidence and a private customer input channel.

The initial scope is consultation and support. Account changes, financial actions, impersonation and customer token handoff are outside that scope. Define the exact read operations and resources; a broad “support” role is not a permission model. In-house support and an outsourced BPO both need current authority; outsourcing adds provider personnel, revocation, contract and data-access responsibilities. An employee session or support PIN cannot establish that authority.

**Conservative default:** telephone/BPO PIN verification remains unavailable. The customer PIN lifecycle exists, but no production support authorization owner or public verification HTTP endpoint is supplied. A decision record cannot activate this missing integration. Do not impersonate the customer or give operators customer refresh tokens.

**Required decisions before activation:** name the case/authorization service and accountable team; define the consultation resources and tenant/delegation rules; select the private PIN input channel and independent possession evidence; assign audit custody and outage reconciliation. A support PIN is knowledge evidence alone, not MFA. Independent possession and private input are required parts of the proposed integration, not conclusions to infer from a PIN match.

Follow the [ordered BPO activation procedure](support-pin.md#activation-and-acceptance). First appoint the owner and approve exact consultation operations, then select the evidence/channel, implement and qualify the missing authorization factory and private caller integration, prepare reconciliation, and run complete acceptance. Record the owner/service protocol, issuers and tenant/delegation mappings, case/call sources, resource permissions, possession/freshness rule, channel/recording controls, one-time authorization lifetime, custody contacts and measured test results. Approve activation only for the listed deployment, providers, tenants and operations. Keep verification disabled while any required field or gate is unresolved; on a control failure, suspend new checks and preserve original proof, budget and audit state.

The [hosted native exercise](support-pin.md#scope-of-repository-checks) supplies a way to qualify concurrency, audit rollback, additive migration and same-database restart with synthetic authority. Inspect a complete passing receipt for the intended source before using it as supporting evidence. It cannot select the real case/authorization owner or protocol, precise consultation permissions and delegation, private PIN channel, independent possession, journal custody/retention or reconciliation team. Each receiving application still needs current authorization and destination acceptance. Application receipt loss in the fixture does not accept the real channel's network-failure behavior.

Keep the privileged-access decision separate: named least-privileged accounts, password plus a user-verifying hardware key, private ingress, supervised enrollment/recovery and independent emergency custody still require their own institution-owned implementation and acceptance. Neither support qualification nor its retained-data rehearsal approves those controls or creates a new production capability.

**Acceptance before enabling any future integration:** authenticate the actual operator and service, bind short-lived one-time authority to the exact case/customer/action and reject replay, expiry, wrong tenant/customer/action and revoked delegation. Preserve employee attribution at every hop and fulfill approvals before mutation. Prove that operators/recordings/logs cannot capture the PIN, and that PIN evidence does not clear locks or grant financial permission. See [support PIN](support-pin.md#native-evidence-boundary).

## Telemetry, privacy and retention

**Owner:** security operations and audit custody, with privacy/data owners, legal/compliance, service operations and supplier management.

**Inputs:** event/data inventory, purposes and access groups, data/backup/support locations, external collectors/processors, incident contacts and approved retention/hold schedules. Evaluate EU and US applicability through [the controls matrix](controls-matrix.md); do not substitute a universal retention period for that decision.

Choose a local or central operational collection arrangement and the required independent audit custody. Central collection improves correlation and resilience but creates additional access, transfer, retention and outage dependencies. A production immutable-audit collector is not supplied. If the institution requires one, qualify authenticated export, ordering/deduplication, bounded backpressure and collector failure handling before relying on it.

Record a separate retention rule for each category:

| Category | Decisions to record |
| --- | --- |
| Identity/admin/security events | Allowed fields, purpose, reader roles, retention start/duration, export, deletion and custody; sandbox seven-day expiry is not a production schedule |
| Metrics and service logs | Aggregate labels/correlation identifiers, collection interval, freshness, access and retention; avoid customer identifiers and unbounded labels |
| Recovery/PIN journals and notification records | Owner, integrity/reconciliation purpose, retained attempt/lease history, disposal approval and dependency on encryption versions |
| Backups and incident evidence | Snapshot age, access, location, legal/security holds, expiration, restore handling and destruction procedure |
| Proofing documents or biometrics | Separate evidence-owner scope and privacy decision; do not place raw artifacts in Keycloak attributes, application JWTs or shared telemetry |

For each schedule specify the unit and trigger, approved duration, accountable deletion owner, hold/exception handling, backup consequences and evidence of disposal. Decisions about residency must include remote support access and downstream processors. Document EU/US scope and the institution's applicable requirements without assuming that a hosting region or supplier claim resolves them.

**Conservative default:** emit minimal approved categories and aggregate metrics; exclude secrets, tokens, raw bodies, OTP/PIN material, SQL bind values, full admin representations and provider/mail payloads. Do not collect additional sensitive fields without purpose/access/retention approval, and do not delete protected retained state merely to shorten logs. Keep any journey whose required audit/privacy controls are unresolved closed.

**Acceptance:** exercise authentication failure, administrative change, receiver denial, recovery interruption and notification outage. Operators can correlate approved records and detect absence/staleness without access to secrets. Demonstrate alert routing within the approved detection/response limits, collector outage handling and authorized access refusal. Test retention expiry and hold handling on representative isolated data, including restored backups. Run an incident exercise that records awareness/classification/determination separately and reaches the actual incident/privacy/legal owners; routine recovery mail is not an incident filing. Follow [monitoring and incidents](observability-incidents.md).

## Open only the accepted scope

The deployment owner records which journeys, populations and receivers have passed their acceptance exercises. Attach the reviewed configuration, deployed checks, restoration/rotation exercises, unresolved restrictions and operating contacts. Keep exceptions bounded by scope and expiry. Rerun affected acceptance when a material input changes.

An accepted ordinary-login deployment can still have customer replacement, BPO verification or another optional journey unavailable. State those restrictions explicitly in operating and customer-facing procedures. Do not treat configuration-check success, a supplier statement or an isolated test as approval for an untested environment or receiver.
