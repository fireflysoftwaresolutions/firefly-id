# Recovery Notification Poller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement the independent native/Core tasks, then integrate and review their actual runtime together. Preserve existing checkouts and evidence.

**Goal:** Complete the authorized Core-owned notification polling and private supervision without coupling Jafly to Identity.

**Architecture:** Native owns the durable outbox and bounded private status/dispatch RPC; Core owns an opt-in managed poller, independent monitor credential and Micrometer supervision. Domain/case SDK contracts remain unchanged.

**Tech Stack:** Java 21/Keycloak 26.8.1; Java 25/Spring WebFlux lifecycle/Spring Security/Micrometer; hosted PostgreSQL/browser qualification.

**Spec:** ../specs/2026-11-01-recovery-notification-poller-design.md

## Global Constraints

- Existing worktrees only. No local JVM/Maven/DB/clones/heavy downloads/deletions. Source-parent 6442bd51733ade4d5f4583e1afe812dd2c520b40 and published Jafly 26.10.23 remain qualification fixtures.
- Preserve all IDs, existing case producer/SDK, JPA schema and original notification budgets/leases. No ordinary token grants or new public approval path.
- Naming follows the role exemptions in the spec. No generated Java edits, handoff edits, merge/release/production activation.

## Review Focus

- A slow or cancelled network call must not permit unbounded overlapping poll cycles or silently retain the local in-flight gate.
- A dead poller must become stale without another cycle updating its status; old aggregate data cannot imply health.
- A notification-only or monitoring credential must not acquire ceremony or financial authority.
- SMTP acceptance followed by a lost response must retain at-least-once semantics and native lease fencing, without new recovery/grant/counter reset.
- Native aggregate reads must be realm-filtered, nonidentifying and consistent under concurrent sends; invalid rows must be visible to supervision.

### Task 1: Native outbox supervision and dedicated workload

**Files:** existing native `ReproofingContracts`, `impl/ReproofingResourceImpl`, `impl/ReproofingRpcImpl`, `impl/ReproofingDispatcherImpl`; new `impl/ReproofingNotificationStatusImpl`; tests in the same native module.

**Interfaces:** consumes existing native outbox and authenticated grant-disabled workload clients. Produces exact `dispatch` limit and `notification-status` wire/authorization in the spec.

- [x] Write failing tests for dedicated client confinement, bounded legacy/new batch bodies, aggregate redaction/unknown states and immutable native budgets.
- [x] Observe RED on a hosted native build, then implement the minimal wire/aggregate/authentication changes with no schema or existing purpose changes.
- [x] Run the full hosted native reactor and packaging; provide exact source pin, bounded result and added wire tests to root/Core.

### Task 2: Core managed poller and private supervision

**Files:** new notification port/records and technical implementations under Core reproofing; configuration/lifecycle/private monitoring controller/security in web; `ops/reproofing-notifications/` alert rules/runbook; source tests and naming-role inventory if required.

**Interfaces:** consumes Task 1 `dispatch(limit=1)` and `notification-status` exact JSON over dedicated private TLS client. Produces private GET monitoring snapshot and authenticated exact `/metrics` scrape using a worker-owned registry excluded from global Actuator export.

- [x] Write failing lifecycle/concurrency/cancellation/timeout/staleness/metrics and real HTTP receiving/authentication tests; verify RED remotely.
- [x] Implement the explicit default-off configuration, bounded client, local cycle fencing, safe snapshot and private monitor chain. Preserve all public case methods and original producer spec.
- [x] Qualify the full hosted Core reactor/actual PostgreSQL; verify original producer/SDK hash or explain any real API change. Provide exact source/fixtures and operating settings to root.

### Task 3: Actual automatic-delivery qualification and operations

**Files:** `tooling/reproofing_integration_fixture.py`, `tooling/reproofing-runtime.mjs`, exact-source workflow inputs and recovery/progress guides; Domain source pin fixture only after Task 2 qualifies.

**Interfaces:** consumes qualified native/Core/Domain producer pins and the installed poller. No manual dispatch may satisfy the automatic-delivery assertion.

- [x] Add dedicated native dispatch and Core monitoring fixture credentials; configure the real Core lifecycle and private supervision with owned TLS.
- [x] Stop SMTP before credential replacement, prove automatic persisted retry/degraded supervision, restart SMTP and await automatic delivery/healthy status; deny wrong/ordinary/case caller monitoring. Restart only owned Core and prove retention/no new recovery.
- [x] Run full new native/Core/Domain credential-loss and old known-password/PIN lanes at exact new pins, inspect bounded evidence and compare artifacts.
- [x] Independently review the changes and failure semantics; run local lightweight presubmit/relative-link checks; record configuration, alert handling and remaining real-provider/production gates in draft PRs and notify coordination when available.

## Qualification receipt

Native79:41331182922; Core170/19PG:41331774478 at26c3b142c66d4d9ad3a0cc9619d476f2b9d24261; Domain43/full102:41332030859/41332030842 at68fa0b7fc849dd3e4dab7756493e344a331bb478. Identity15fd1b7ffa045835f3d4c71fdcc33020d8f24ecf passed legacy48:41331177242 and final automatic/private-metrics25:41332055134. Root independently inspected bounded artifacts and matching native binaries. Reviews found no actionable issue; local26Python+11Node and41Markdown relative-target checks passed. Production/vendor acceptance remains outside these receipts. Draft PR metadata carries coordination receipts; no private handoff was edited.
