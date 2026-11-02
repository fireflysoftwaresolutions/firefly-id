# Monitoring and incident response

Monitor service availability, security activity and recovery completion separately. A healthy process can still have an SMTP outage, a stalled recovery journal or an application that accepts a revoked identity.

## Connect the signals

| Signal | Where to collect it | What to watch |
| --- | --- | --- |
| Startup/readiness/liveness | Private HTTPS management interface, port 9000 | Startup progress, dependency readiness and process failure |
| Server metrics | Restricted monitoring system | Capacity, request/error rates, pools and runtime pressure |
| Identity/admin events | Controlled event storage/export | Authentication anomalies, administrative and credential changes |
| Native journals/audit | Native identity owner | Lock/operation/execution status and interrupted work |
| Core cases/grants | Respective SCA or KYCB service | Original operations, attempts, authorization and execution status |
| Notification status/metrics | Independent HTTPS monitor credential | Observation freshness, retry/backlog and terminal rows |
| Application decisions | Each resource receiver | Issuer/audience failures, authorization, current-state and tenant/resource refusals |

Set operational baselines and alert receivers for certificates/keys, capacity, database health, authentication anomalies, provider dependencies and consumer failures. Alerts should identify the observation time, link to a runbook and avoid customer data.

An enterprise immutable-audit collector is not supplied. Configure authenticated export, ordering/deduplication, bounded backpressure, custody, retention, residency and access review with the operating team.

## Monitor recovery notifications

Install the private worker scrape and external alert rules from [notification operations](notification-operations.md). Monitor both failure and absence: a stopped worker cannot report its own absence. The worker's private registry does not enter global Actuator metrics.

Check that monitor credentials cannot call recovery/case APIs and that acknowledging an alert does not change protected state. Cached counts must retain their observation time rather than look like a live healthy queue.

## Investigate a sign-in failure

1. Identify the affected issuer/population, application and approximate time using approved correlation data.
2. Compare public service reachability with private dependency health.
3. Check DNS, certificate/name verification, canonical hostname, proxy trust, callback/PKCE and clock synchronization.
4. Check factor enrollment and current lock/hold state through authorized private interfaces.
5. If sign-in succeeds but a business action fails, inspect that receiver's permission, tenant/resource binding, consent/mandate and current-state decision.

Keep public responses generic. Do not disclose account existence or remaining attempts, temporarily enable a real user for diagnosis, or broaden roles to silence a 403. A permanent lock and a fraud/admin/employment hold have different owners.

## Handle interrupted recovery

Locate the original case, operation, reservation, grant and execution. A timeout does not establish success or failure. Read the exact committed journal and reconcile only that operation. Keep original expiry and budgets; do not start another provider session, replay factors or create a replacement grant.

If provider evidence is unavailable, restore authenticated connectivity and inspect the original session. Do not fabricate approval or a business rejection from an outage. If account/contact/link/hold state changed, investigate the current owner before proceeding.

For SMTP failures, retain destination/attempt/lease state and follow the channel runbook. Eight exhausted attempts become terminal review work, not an automatic requeue. At-least-once delivery can produce a duplicate notice after an ambiguous accepted send; it does not imply another credential change.

## Contain a compromise

Identify whether the compromised material is a signing key, workload credential, user factor or administrator account. Each needs its own revocation/rotation procedure and consumer response. Preserve relevant records before an authorized mutation and keep secrets out of diagnostics.

Disablement, session retirement and not-before changes must be accompanied by current-state/revocation handling in applications that need immediate denial. Review cache bounds and independent application sessions. Use the institution's containment plan where an offline decoder would otherwise accept an unexpired JWT.

## Keep diagnostics private

The reference selects JSON console logs. Prefer fixed event categories, bounded result states and approved correlation identifiers. Restrict who can join identity, recovery and financial records.

Exclude raw HTTP bodies, authorization headers, passwords, PINs, OTP/setup keys, browser traces/HARs, SQL bind values, full admin representations and provider/mail payloads from shared diagnostics. URLs can contain codes and action tokens too. Store incident records and configuration exports in the controlled operating system, not the public repository.

## Apply the right reporting clock

DORA, GDPR, US bank-agency rules, FTC and NYDFS use different scopes, triggers and deadlines. Several may apply concurrently. Route technical alerts to the designated incident/privacy/legal owners so they can classify the event, record awareness/determination times and manage notifications. [EU/US controls](controls-matrix.md) lists the primary sources and timing distinctions.

Before closure, confirm service and consumer recovery, channel/monitoring health and preservation of original cases/budgets. Record affected systems, decisions, changes, unresolved risks and follow-up runbook improvements. Use [retained data](retained-data.md) when restoration is needed.
