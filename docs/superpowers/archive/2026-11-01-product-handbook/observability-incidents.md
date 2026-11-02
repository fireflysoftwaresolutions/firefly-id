# Observability and incident response

Observe whether the identity service is available, whether security decisions are working and whether a specific business/recovery operation has completed. These are different signals. A successful HTTP response or a healthy Keycloak process does not establish that an email arrived, a grant remains current or a receiving application rejects an old token.

## Signals and owners

| Signal | Owner / access | Interpretation and limit |
| --- | --- | --- |
| Server readiness/liveness | Private Keycloak management network, port 9000 | Process/dependency readiness; not authentication, authorization or recovery acceptance |
| Server metrics | Approved restricted monitoring system | Capacity, request/error and runtime signals; no public management exposure |
| Identity/admin events | Identity operations/security; controlled retention and access | Useful investigation records; ordinary Keycloak event tables/logs do not prove immutable custody |
| Native recovery journals/audit | Native identity owner, append-only controls at the qualified boundary | Exact lock/operation/execution history; not a permission to replay or grant another recovery |
| Core case/grant/execution state | Respective SCA or KYCB owner | Authoritative operation status and retained budgets; reconcile the original identifiers |
| Notification snapshot and metrics | Separate HTTPS monitor workload | Freshness and aggregate queue/retry/terminal state; contains no customer destination or case identifier |
| Consumer enforcement | Each Experience/Domain/Core resource receiver | Correct issuer/audience/policy/current-state decisions and their fail-closed behavior |

The repository does not ship an enterprise immutable-audit collector or SIEM integration. Before production, define authenticated export, ordering/deduplication, bounded backpressure, custody, retention, residency, access review, alert ownership and failure escalation. Logs or unit tests alone do not supply that infrastructure.

## Logging without leaking authority

The production reference selects JSON console logging. Keep diagnostic content bounded and structured. Prefer fixed event categories, approved correlation identifiers and result states. Restrict who can join identity, case and financial records. A correlation identifier can itself be personal or security-sensitive information; use the approved retention/access policy.

Never enable token/password/OTP/PIN logging, raw request bodies, browser trace/HAR capture, SQL bind values, full administrative representations, mail bodies or provider-document payloads in a shareable environment. URLs can contain authorization codes and action tokens. Sanitizing only the response body does not make the URL, exception stack or HTTP header safe.

Hosted qualification deliberately retains only safe fixed-stage JSON, source/artifact hashes and empty/masked/completion screenshots. `.state`, ownership files, raw Maven/service logs, TOTP material and synthetic credentials are excluded. Synthetic credentials are still secrets.

## Alert on failure and absence

Install and test normal platform alerts for service reachability, certificate/key expiry, capacity, abnormal authentication activity, administrative changes, federation/provider availability, database health and consumer enforcement. This requires actual operational baselines and owners; the repository does not invent production thresholds for an unknown institution.

The recovery notification worker supplies scoped rules for absent/stale observation, dependency/timeout/invalid responses, sustained retry/overdue work and terminal/invalid rows. Its private metrics are excluded from global Actuator export. The monitoring system must independently expect the worker: disabling a process cannot make it emit its own absence signal. [Notification operations](notification-operations.md) explains the exact endpoint, job and alert thresholds.

An alert should link to a named runbook and escalation owner, identify the observation time and avoid revealing customers. Test that alert transport works, its credentials cannot call recovery/case APIs, and acknowledgement does not mutate the protected recovery state.

## Triage authentication failure

First establish the affected issuer/population, client/journey, approximate time and approved correlation. Compare public-service availability with private dependency health. Check trusted TLS, canonical hostname/proxy behavior, client redirect/PKCE, token issuer/audience, clock synchronization, factor enrollment and current native hold/lock state.

Keep public failures generic. A support operator must not disclose whether a supplied account exists or how many attempts remain. Do not clear a failed-login counter, replace a password or issue a temporary enable to test a real user's access. A tracked permanent lock has its own approved unlock/reproofing procedure. Fraud/administrative/employment holds remain distinct.

If login succeeds but a business request is refused, inspect the receiving service's actual permission, tenant/resource, mandate/consent and current-state decision. Granting broader roles or forwarding an administrator token to silence a 403 is not incident repair.

## Triage interrupted recovery

Identify the authoritative original case, operation, reservation, grant and execution through the approved private owner interfaces. An ambiguous timeout is not evidence of failure or success. Read the exact committed journal and reconcile only that operation. Do not start another provider session, renew expiry, reset a budget or reconstruct human approval.

For unavailable provider evidence, verify authenticated connectivity and original session status. Do not convert an outage into a fabricated negative business check or approval. For a held or changed native account, preserve the hold and investigate its current owner; previous proofing does not override current eligibility.

For failed notification delivery, retain the original destination/attempt/lease evidence and follow the named channel runbook. A terminal row after eight attempts does not automatically requeue. At-least-once SMTP semantics can produce a duplicate notice after an ambiguous accepted send; a duplicate does not imply another credential replacement.

## Revoke and contain deliberately

Compromised signing keys, workload credentials, factors or privileged accounts require different containment actions. Define who can revoke/rotate each, how consumers observe the change, what remains valid during transition and how failure is detected. Preserve evidence before an approved mutation. Do not dump secrets into diagnostic output to compare them.

User disablement, session removal and not-before changes are important identity actions. Prove how every receiving service and application session observes current state; offline JWT signature validity alone can outlive the incident decision. Where the integration has no accepted live-state mechanism, record that limitation and use the approved compensating containment plan rather than claim immediate universal revocation.

## Apply the correct incident clock

Legal reporting triggers differ. DORA major-incident classification/awareness, GDPR personal-data-breach awareness, US bank notification-incident determination, FTC covered notification events and NYDFS cybersecurity/extortion events have different scopes, clocks and responsible parties. They can apply concurrently. Do not implement one generic timer as legal incident management.

The [EU/US controls matrix](controls-matrix.md) gives dated primary sources and the trigger distinctions. The institution must approve classification, legal/compliance contacts, regulator/individual/customer notifications, supplier escalation, evidentiary retention and contractual deadlines. A technical alert can start investigation; it cannot make the legal classification automatically.

## Close with evidence

Record what was affected, current status, authoritative decisions, protected evidence references, exact changes, consumer/channel recovery and unresolved risks. Confirm monitoring returned to the expected state and original recovery/case budgets were preserved. Capture lessons into the versioned runbook/configuration through review.

Neither an incident ticket closure nor a green synthetic workflow replaces actual provider, retained-data, HA or bank operating acceptance. [Evidence](evidence.md) and [retained data](retained-data.md) explain the remaining gates.
