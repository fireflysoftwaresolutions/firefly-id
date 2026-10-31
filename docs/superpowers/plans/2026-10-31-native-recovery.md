# Native Recovery Implementation Plan

> **For agentic workers:** Use the explicitly authorized parallel workstreams below. Root integrates and reviews; no production action or release is authorized by this plan.

**Goal:** Complete provider-native two-factor unlock, owning Core/Domain integration and CIAM support credentials with real scoped qualification.

**Architecture:** Version-pinned native Keycloak extension; Core SCA durable reservation/proof/receipt ownership; genuine producer-generated SDK into Domain SCA; independent per-service authentication/current authorization. Jafly and terminal changes remain with the parent session.

**Tech Stack:** Keycloak 26.8.1/Java21, Spring Security/Jafly26.10.23/Java25, JPA/R2DBC/PostgreSQL, real OpenAPI producer/generator, native FreeMarker/CSS/Manrope, hosted browser tests.

**Spec:** [Native recovery design](../specs/2026-10-31-native-recovery-design.md).

## Global constraints

- No local JVM/Maven/PostgreSQL/Docker/dependency downloads below the 12GiB resource floor. Use hosted isolated fixtures and source checks locally.
- Preserve existing checkouts/state and source-parent fixture6442/Jafly23; never overwrite released GAVs, framework modules or the parent handoff.
- Native code contains no Jafly dependency. Public artifacts use American English; UI supports English/Spanish.
- Credentials stay native; server-derived authority and current authorization are mandatory at each boundary.
- Existing production generation remains fail closed until its real deployment contract is qualified.

## Review focus

- Interleaved native admin/credential writes and permanent lock/unlock commit ordering.
- Core reservation committed before any native factor verification; no attempt reset on cancellation/reissue.
- Actual generated SDK signatures/date types and concurrent caller token isolation.
- Opaque proof/receipt substitution, response loss and one-time execution reconciliation.
- PIN proof mistaken for possession, customer delegation or financial authority.

### Task 1: Core owning reservations, online authorization and durable audit

- [ ] Extend existing Core interfaces/service/controller with reserve/complete/verify-authorization operations and typed records.
- [ ] Add mapped immutable boundary-audit storage and separately reviewed installer privileges.
- [ ] Reuse existing reservation/completion transactions, enforce exact proof/receipt bindings and current admission, disable generic response idempotency caching.
- [ ] Extend meaningful service, real PostgreSQL, receiver and original-producer tests; run hosted qualification with no skipped required reports.

### Task 2: Native Keycloak owner

- [ ] Add `extensions/native-recovery` with explicit Keycloak26.8.1 dependencies, Java21, service registrations, entity indexing and native schema lifecycle.
- [ ] Implement durable permanent-lock capture, generic administrative bypass refusal, hold/revision invalidation and canonical population admission.
- [ ] Implement bounded restricted ceremony, native credential attestations, exact Core reservation contract, online receipt verification and generation-atomic journaled execution.
- [ ] Add separate hashed support-PIN credential lifecycle/verification capability with strong-auth gate and context-limited output.
- [ ] Test native API contracts, persistence, concurrency, rollback and secure failures on the real pinned provider.

### Task 3: Actual Domain orchestration and generated SDK

- [ ] Isolate current `domain-common-sca` source without modifying retained consumer checkouts.
- [ ] Add optional recovery-only receiver/current-policy and orchestration using actual generated `ScaRecoveryApi`; no new business persistence or credential DTOs.
- [ ] Build the actual Core producer/generator under distinct temporary candidate SDK coordinates and compile Domain against that artifact in hosted CI.
- [ ] Verify scoped bearer propagation without mutable singleton token state, native execution reconciliation and fail-closed capability/configuration.

### Task 4: Product adapters, branded journeys and full integration

- [ ] Implement actual product native admission/factor/journal adapters and recovery-only policy in separate product integration modules.
- [ ] Extend generator/build/runtime wiring for owned qualified native artifacts and separate customer/workforce configuration.
- [ ] Add native English/Spanish recovery/PIN pages using existing Manrope/light/dark theme and accessible generic state handling.
- [ ] Run fresh isolated HTTPS/native+Core+Domain/provider browser integration, including hostile substitutions, expiry, restart, concurrent execution, session retirement and support credential cases.

### Task 5: Review, operational documentation and evidence

- [ ] Independently review security boundaries and actual target-size UI captures; correct material findings.
- [ ] Expand installation, configuration, recovery/support operations, population policies, upgrade and failure documentation; verify repository metadata readback.
- [ ] Record exact source/artifacts/tests and external production/assisted-support/delegation gates without turning source proof into release or compliance claims.
