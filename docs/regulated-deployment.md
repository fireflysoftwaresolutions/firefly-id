# Prepare a regulated deployment

Firefly Identity supplies engineering controls and exact-source qualification. A regulated deployment also needs an institution's applicability decisions, production topology, authoritative customer/employee links, approved authentication and recovery procedures, operating ownership and evidence from the actual environment. This page is an implementation path for that work; the repository intentionally does not generate production realms from guessed values.

Use the [EU/US controls matrix](controls-matrix.md) to determine which obligations apply to the entity and journey. EU payment services, DORA-covered entities, US banks, FTC-covered nonbanks and NYDFS-covered entities do not share one identical rulebook. NIST assurance levels are not automatically a private institution's legal certification. TOTP, a longer password or a Keycloak version number alone cannot establish compliance.

## Define the deployment contract

Before provisioning, approve a versioned record containing:

| Decision | Required evidence / owner |
| --- | --- |
| Entity, jurisdictions, regulators and processing roles | Legal/compliance applicability assessment, including US state overlays and cross-border data handling |
| Populations and institution boundaries | Customer, workforce, institution-human, service and administrative profiles; separate issuers/stores and stronger instance/database isolation where needed |
| Canonical URLs and trusted clients | Exact HTTPS public/admin/backchannel origins, redirect/logout allowlists, issuer/audience contracts and approved algorithms |
| Identity/business binding | Authoritative party/staff/tenant provisioner, lifecycle and delegation owners; no email/name auto-linking |
| Authentication assurance | Factor/enrollment and step-up policy per journey, privileged phishing resistance, session/inactivity behavior and equivalent-control decisions where legally available |
| Recovery and notification | Approved verifier/reference/assurance policy, permanent-block warnings/restoration, alternate evidence/escalation and real notification channel |
| Data and operations | Residency, retention, encryption, keys, immutable custody, backup/restore objectives, HA/failure modes, incident and supplier responsibilities |
| Acceptance and change control | Named approvers, evidence retention, rollback conditions, distribution artifacts and consumer adoption |

Customer and institutional base profiles do not require MFA. That is useful for bounded synthetic testing, not a blanket production banking recommendation. Select a strong profile for the applicable customer and high-risk journeys and qualify it. Workforce requires password/OTP, but TOTP does not satisfy a phishing-resistant requirement. Permanent privileged administration remains gated on its approved hardened flow.

## Build and review the exact distribution

Build the theme and, where selected, the optional native provider/gateway against pinned Keycloak 26.8.1. Use the [configuration reference](configuration-reference.md), [theme guide](themes.md) and [native guide](native-recovery.md). Pin the resulting immutable image/artifact hashes, retain notices and licenses, scan vulnerabilities and review upstream advisories. An OCI digest proves byte identity, not signature trust or an adequate security scan.

The two Containerfiles serve different selections: the ordinary theme distribution and the explicit native installation. Installing the native JAR registers additive JPA mappings even with recovery disabled. Rehearse migration on a restored, isolated copy before adding it to retained production state. Do not use an enable flag as a migration switch or assume an older image can read the migrated schema.

Production generation refuses until the actual contract is supplied. Do not remove that refusal, promote generated `.state` files or transplant synthetic clients/users to make a rollout work.

## Isolate public, administrative and management access

The public ingress should expose only the required realm/protocol/account/resource routes. Administrators use a separate private ingress and least-privilege roles; the master realm is administrative only. Configure and test route-level denial of `/admin/` and administrative realm access on the public host. A different `hostname-admin` alone does **not** restrict the Admin REST API. Verify that direct service addresses cannot bypass the ingress policy.

Use HTTPS for browser, interservice/backchannel and proxy-to-Keycloak connections; validate certificate chains and hostnames. The supplied production reference disables HTTP, fixes strict canonical hostnames and trusts forwarded headers only from approved proxy CIDRs. The ingress must overwrite, rather than append trust to, untrusted forwarded headers. Avoid a broad proxy allowlist that turns user-controlled headers into trusted client identity.

Management port 9000 belongs to an isolated monitoring network. The reference uses HTTP on that private management leg, so the network boundary must actually prevent public/untrusted reachability; add protected transport according to the approved topology. Health and metrics are not public application routes. No dashboard, database, debug console or SMTP sink belongs on public ingress.

These requirements are grounded in Keycloak's [production guide](https://www.keycloak.org/server/configuration-production), [reverse-proxy guidance](https://www.keycloak.org/server/reverseproxy) and [hostname configuration](https://www.keycloak.org/server/hostname). Qualify the exact installed version and proxy behavior rather than relying on a generic diagram.

## Protect storage, secrets and bootstrap

Operate a dedicated identity database and nonsuperuser application login. Review schema privileges, encrypted transport, backup access, restore roles and separation from business Core records. Treat database/backup administrators as privileged readers of sensitive identity state. Use approved at-rest encryption and key ownership; a local Compose volume is not an enterprise encryption/retention policy.

Inject database, client, SMTP and encryption secrets through the approved secret manager or supported configuration keystore. Use the pinned server's actual configuration mechanisms. There is no assumed generic `*_FILE` loader. Restrict mounts and permissions, prevent secrets in image layers, process arguments, CI artifacts, exception bodies and access logs, and rehearse rotations against retained consumers and encrypted records.

Temporary bootstrap access is only for establishing permanent administration. Provision named least-privileged administrators, required phishing-resistant factors, emergency access with review and an audit owner; then remove temporary bootstrap accounts and secret injection. Record proof of removal and test both privileged positive access and public/ordinary-user refusal. The catalogue's `mfaRequired` flag alone is not that proof.

## Enforce authorization in every layer

Experience, Domain and Core each validate their incoming principal, exact issuer, intended audience, lifetime, current applicable state and operation policy. Machine credentials identify the calling service; they do not invent a customer or employee. Human delegation must carry approved, bounded, attributable authority. Do not expose generic impersonation as a shortcut for a call-center or backoffice process.

Business policy, tenant/resource ownership, mandates, consent, risk and financial permissions remain with the authoritative application owners. A signed `party_id`, email verification, realm role, KYC status or login MFA does not confer payment authority. Read [zero trust](zero-trust.md) and the [integration contract](integration-contract.md) before issuing or forwarding tokens across service audiences.

Session removal and not-before changes do not make every previously issued self-contained JWT disappear. Prove the selected receiving-service current-state/revocation behavior, cache bounds, failure handling and application-session termination. A gateway-only check cannot substitute for every receiving layer's decision.

## Qualify recovery and customer communications

Keep known-password unlock distinct from lost credentials. The former requires genuine enrolled knowledge/possession under a purpose-bound one-time operation. The latter needs approved third-party proofing, trusted linkage to the existing party and fresh native eligibility before replacement factors. Unsupported populations or held accounts remain unavailable. A support PIN, email link or authenticated service is not substitute evidence.

Approve applicable advance notice for permanent blocking and the secure restoration procedure. Removing explanatory page copy does not implement a notice through another channel. Validate accessible EN/ES communications without account enumeration or remaining-attempt disclosure. Maintain fraud/admin holds and financial-authorization boundaries throughout.

The notification poller is implemented, but its real SMTP provider, channel, service-level objectives, alert receivers and operating procedure still need acceptance. Test sender/monitor separation, TLS, queue preservation, eight-attempt terminal escalation and at-least-once delivery. A process failure after SMTP acceptance may duplicate a notice; do not turn that into a second recovery. [Notification operations](notification-operations.md) provides the runbook.

## Rehearse and approve the retained environment

Use an isolated restored database with the corresponding keys/configuration and blocked external delivery. Rehearse migration, backup/restore, restart, clock/failure conditions, concurrent writers, multi-node operation and rollback. Validate actual provider and consumer integrations rather than replacing them with a success fixture. Preserve failed-run data and journals. Never reset counters or issue new grants to repair an ambiguous original execution.

The final acceptance packet should include the institution contract; exact source/image/theme/provider hashes; migration and restore results; ingress and bootstrap proof; factor/recovery/provider conformance; consumer current-state enforcement; real channel/alert evidence; privacy and incident procedures; residual risks and signed operational acceptance. The [evidence register](evidence.md) shows what the repository already proves and what this packet must add.
