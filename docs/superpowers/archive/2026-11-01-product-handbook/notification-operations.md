# Recovery notification operations

The native credential-replacement transaction records a notice to the customer's **previously verified destination** together with the canonical execution. Native owns the encrypted outbox, leases, send operation and eight-attempt budget. Core KYCB supplies an optional managed worker and private aggregate supervision. Neither the browser nor Domain can dispatch or monitor the queue.

The worker is implemented and tested against the actual synthetic SMTP sink. A bank's real channel, service-level targets, monitoring receiver and operating procedure remain separate acceptance. Do not enable customer recovery while those responsibilities are unassigned.

## Enable distinct workloads

Create a separate confidential, grant-disabled Native notification client and set realm attribute `firefly.reproofing.notification-workload-client-id` to its ID. Native verifies its current client state and credential. It may invoke only `dispatch` and `notification-status`; it cannot prepare, admit or journal a ceremony.

When that attribute is absent, older deployments retain the existing Core-only manual dispatcher, without fallback status authority. The new worker requires the dedicated identity. It always sends `{"limit":1}` to dispatch and `{}` to status under the exact trusted native RPC base `/firefly-recovery/lost-credentials/rpc`. Processing one row is not proof of delivery.

Core requires both `firefly.reproofing.enabled=true` and `firefly.reproofing.notifications.enabled=true`. The notification flag defaults false. Configuration changes follow normal application restart; no scheduler, notification client or worker metrics are created while disabled.

## Configure bounded operation

All fields below are under `firefly.reproofing.notifications`:

| Property | Default / requirement | Purpose |
| --- | --- | --- |
| `enabled` | `false` | Explicit worker opt-in in addition to global recovery |
| `client-id`, `secret-file` | Required dedicated Native notification workload | Dispatch and aggregate observation only |
| `monitor.client-id`, `monitor.secret-file` | Required independent monitor | Private read-only status/metrics only |
| `poll-interval` | `PT30S`; 1–300 seconds | Delay **after** a bounded cycle completes |
| `request-timeout` | `PT30S`; 1–60 seconds | Complete dispatch/status cycle and individual transport bound |
| `stale-after` | `PT90S`; greater than interval + timeout, at most 3,600 seconds | Maximum successful-observation age |
| `overdue-after` | `PT2M`; 1–3,600 seconds | Due-backlog degradation threshold |

Both secret files must be regular nonsymlink POSIX files with owner-only read/write permissions, containing 32–2,048 characters. IDs and secret values must differ from each other and receiver/native ceremony credentials, and evidence credentials when configured. Missing/reused/unsafe values refuse startup with generic diagnostics. Mount secrets; never place them in arguments, environment examples, logs or tickets.

The worker uses the existing exact `firefly.reproofing.native.base-url`, validated HTTPS and trusted certificates, with no redirects. Responses are bounded to 32 KiB, require exact JSON fields and reject malformed/duplicate/unknown values and invalid counts. Native timestamps more than 30 seconds ahead or 90 seconds behind Core are unavailable observations. Synchronize clocks; do not enlarge tolerance to hide a broken time service.

The managed lifecycle starts an immediate cycle, then fixed delay after completion. A local gate permits one active cycle; Native leases fence multiple Core instances and ambiguous responses. Shutdown cancels scheduled and active work. Core restart reobserves the same durable queue and never resets recovery cases, grants, attempts or terminal failures.

## Read private supervision

Only the independent monitor Basic credential over HTTPS GET may access:

| Endpoint | Response |
| --- | --- |
| `/internal/identity-recovery/notifications` | Safe immutable worker snapshot |
| `/internal/identity-recovery/notifications/metrics` | Worker-only Prometheus text |

All other methods/subpaths and ordinary/case/notification caller credentials are denied. The monitor cannot invoke case operations. Keep these endpoints outside browser ingress. Both are hidden from the original public producer API and add no SDK operation.

The snapshot contains exactly `state`, `activeCycle`, `lastAttemptAt`, `lastSuccessAt`, `consecutiveFailures`, `queue`. Queue is null before a valid observation; timestamps retain the corresponding original times. Its exact aggregate fields are `observedAt`, `pending`, `sending`, `retrying`, `delivered`, `failed`, `invalid`, `due`, `oldestDueDelaySeconds`. Counts are realm-scoped using Native database time. No subject, email/destination, case/execution ID, ciphertext, provider detail or raw exception is returned.

| State | Operational interpretation |
| --- | --- |
| `STARTING` | No successful queue observation yet |
| `HEALTHY` | Fresh validated observation without degradation conditions |
| `DEGRADED` | Failed/invalid/retrying rows or excessive due delay need attention |
| `UNAVAILABLE` | Latest cycle failed; cached queue information is not a fresh success |
| `STALE` | Last successful observation aged past the configured bound without a newer success |

Staleness is evaluated on reads even if scheduling silently stops. Preserve observation times when presenting a cached snapshot. Do not render old counts as a live healthy queue.

## Scrape and alert

The private registry exposes fixed-label `firefly.reproofing.notifications` metrics: cycles by success/failure, failures by timeout/invalid-response/dependency, processed, active, consecutive failures, last-success epoch, stale, observed and queue counts/due delay. Prometheus converts dots to underscores and counter names gain `_total`. Missing initial queue values are NaN, not fabricated zeros.

The registry is owned by a private wrapper: it is neither a Spring `MeterRegistry` bean nor a global-composite member. Worker series do not enter `/actuator/prometheus`; existing global metric configuration and security policy remain separately owned. The actual integration explicitly checks this isolation.

Install the [Core alert rules](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/blob/26c3b142c66d4d9ad3a0cc9619d476f2b9d24261/ops/reproofing-notifications/alerts.yml) in the independent monitoring system. Scrape the private HTTPS metrics path with the dedicated identity and a mounted `password_file`. The supplied absence selector expects job `identity-core-notifications`; adjust it to the approved target/instance topology and test missing-worker detection. Review the 90/120-second thresholds if changing configuration. An application cannot report its own absence after being disabled.

## Respond without changing authority

For unavailable/stale observations, inspect credential confinement, mount permissions, exact issuer/base URL, certificate trust, host connectivity, timeout and time synchronization. Keep diagnostics bounded; do not enable HTTP-body or SQL-bind logging. Restore the dependency and allow the next cycle to reobserve the retained queue.

For retries/overdue work, check the approved SMTP path and provider monitoring. Keep bounded connect/read/write deadlines; pinned Keycloak 26.8.1 defaults each to 10,000 ms. After restoring the channel, Native backoff and leases remain authoritative. Delivery is **at least once**: SMTP acceptance followed by a lost response can duplicate a notice, without another recovery execution.

An expired final sending lease becomes a retained failed row at attempt eight without a ninth send. Failed/invalid rows require named operational review. There is no supplied automatic replay/delete, address replacement or budget-reset endpoint. Preserve the exact row, lease/attempt and failure evidence and escalate under the approved procedure.

Before normal disabling, quiesce new recovery ingress, drain or review pending notifications, then disable/restart and adjust the external expected-worker alert deliberately. Emergency disabling preserves the Native queue and requires follow-up; it does not manufacture an empty successful status.

## Qualification

[Final actual integration 41332055134](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41332055134) passed automatic SMTP failure/retry/delivery without manual dispatch, Core restart retention, separate workload denial, private metrics/global isolation, actual database realm filtering/constraints and expired eighth-lease terminal supervision. See [evidence](evidence.md) for exact source/SDK hashes and limits. The [Core runbook](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/blob/26c3b142c66d4d9ad3a0cc9619d476f2b9d24261/ops/reproofing-notifications/README.md) is the implementation owner's reference.
