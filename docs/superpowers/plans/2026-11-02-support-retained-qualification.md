# BPO concurrency and retained migration implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development with independent review. Continue the approved support-evidence design and user-requested synthetic qualification.

**Goal:** Execute native BPO concurrency and additive migration over retained synthetic data, and document the remaining institution-owned activation decisions.

**Architecture:** An owned GitHub-hosted fixture uses the pinned Keycloak image and PostgreSQL. A separately packaged test-only adapter invokes the actual native support service with independent Keycloak sessions; production artifacts contain neither the adapter nor a support verification endpoint. Initialize the pre-support-evidence schema using its unchanged historical Liquibase changesets, seed representative records, then apply the current migration through native startup and preserve the original database through restart.

**Tech Stack:** Java 21, Keycloak 26.8.1, PostgreSQL, Python standard-library orchestration, GitHub Actions, MkDocs.

**Spec:** `docs/superpowers/specs/2026-11-01-support-privileged-design.md` and the user's request to complete BPO concurrency and retained-data migration tests without real accounts.

## Global constraints

- Existing isolated worktree; no Jafly changes, real accounts, production activation, merge or release.
- No local JVM/Maven, Docker/database/browser execution or dependency installation. Use owned hosted runners for native execution; local Python/Node presubmit is allowed.
- Preserve retained data and failed evidence. No counter resets, replacement grants or replay to repair uncertainty.
- Test-only authorization adapters must be absent from production artifacts and inaccessible outside the owned fixture.
- Publish bounded status/count evidence only; no credentials, PINs, raw logs, tokens, exports or keys.
- Prior commit/push, GitHub Actions and project Pages publication authorization persists. Root coordinates commits and pushes.
- Repository prose is American English. Institution-specific ownership, channels, evidence and acceptance cannot be invented.

## Review focus

- Concurrency must cross actual native service transactions and observe competing work, not merely assert SQL uniqueness or sequential mocked calls.
- Three reserved/failed slots must survive concurrency, interruption and restart; no automatic refund or new grant.
- Exactly one consumption may commit, and audit failure must roll back the same proof transition.
- Migration must apply the real additive changeset to existing rows without rewriting Liquibase history or dropping/recreating retained tables.
- A test authorization owner, endpoint or fixture credential must never enter the distributable image or accept an arbitrary external target.

### Task 1: Native concurrency and retained migration fixture

**Files:** existing `tooling/support_storage_qualification.py`, `tooling/native_integration_fixture.py`, `extensions/native-recovery` service/tests/resources as references; new isolated qualification-only Java fixture under `qualification/`, Python orchestration under `tooling/`, regression tests under `tests/`, and a dedicated `.github/workflows/support-retained.yml`.

**Interfaces:** use the unchanged `NativeSupportPinServiceImpl.verify(context, pin)` and `consume(context, reference)` entry points. Publish a bounded JSON receipt identifying source revision, scenarios, original/migrated state preservation and explicit scope. No production public API.

- [ ] Read existing native image, ownership, migration, phase and service patterns; choose the smallest test-only packaging that runs the real service with independent sessions and real PostgreSQL.
- [ ] Add failing offline regressions for owned-only admission, test-package exclusion and retained-migration provenance; retain evidence of the red result.
- [ ] Implement historical schema initialization without the final `firefly-native-support-evidence-2` changeset; seed prior proofs, PIN generation/counters/holds, audit and representative native recovery records. Apply current unchanged migration at startup, compare original-column values/identifiers and verify legacy proof refusal.
- [ ] Exercise same-nonce cross-customer contention, concurrent distinct-nonce budget exhaustion, concurrent consumption, audit-failure rollback, PIN generation/hold invalidation during a pending operation, and lost-response reconciliation across restart. Use barriers or observed database contention, bounded deadlines, exact invariant checks and fresh synthetic users per independent scenario.
- [ ] Prove the qualified adapter is absent from ordinary production packages and unusable outside the owned fixture; preserve failed state and bounded diagnostics.
- [ ] Run focused local regressions and `make check`; report changes, scope, tests and remaining uncertainty without claiming hosted acceptance.

### Task 2: Review and actual hosted acceptance

- [ ] Independently review Task 1 for spec compliance, actual-service transaction coverage, migration provenance, package isolation and safe ownership. Resolve material findings.
- [ ] Commit/push the reviewed implementation and run the owned workflow. Inspect bounded receipts, fix evidenced failures, and repeat required checks.
- [ ] Confirm exact-source hosted native build and all required CI results; distinguish each actual scenario from unqualified production behavior.

### Task 3: Activation documentation and delivery

**Files:** `docs/support-pin.md`, `docs/retained-data.md`, `docs/production-decisions.md` and draft PR #1.

- [ ] Update the existing handbook with the implemented exercise, observed limits, migration/reconciliation procedures and concrete institution-owned decisions. Keep internal run bookkeeping outside product navigation.
- [ ] Retain BPO owner/protocol, consultation permissions, private PIN channel, independent possession, custody, retention and receiver acceptance as production gates; retain privileged hardware/roles/private ingress/enrollment/recovery/emergency decisions.
- [ ] Review wording against exact evidence, publish MkDocs via existing CI, verify the served artifact and update the draft PR with source-specific receipts.

## Execution record

The existing design and this continuation are authorized by the user's request; no new production capability or institutional decision is inferred. Task 1 produces the receipt consumed by Tasks 2 and 3. Task 2 changes no product scope; Task 3 must not claim unexecuted scenarios. All tasks preserve the global constraints. Delivery receipts belong in draft PR #1 so recording the final run does not change the checked source.

Initial hosted run `41386933260` at `d2ad51ea820d1e0ecc83f59e44dfa6e43f0838ed` compiled both native service and fixture, passed 115 Java tests, verified production adapter exclusion, and seeded all eleven historical tables. It failed in `ADDITIVE_MIGRATION` before publishing route-admission results. The initial bounded diagnostics did not identify the failed substep; add specific safe failure stages and process/readiness evidence before attributing a root cause or changing behavior. Preserve that failed receipt. The other nine source workflows passed, including Pages publication and exact comparison of 81 public files and 32 unchanged reviewed SVGs; those results do not qualify the failed support runtime.

Diagnostic run `41388672887` at `863e3b502bed497a3a760839e0e678146be2363c` locates the failure at current-server `BOOT_READINESS`: health returned 503, then the identity process exited with code 1 without OOM while PostgreSQL remained running. It did not reach route-admission or concurrency checks. The startup exception is not yet identified; collect private verbose startup diagnostics and bounded read-only schema/history observations before selecting a behavioral fix. No migration, deadline, counter or authorization rule has been relaxed.

Run `41389726220` at `a3a0162440713cf3d496d96c22abbd373a52099d` establishes the cause: `CachedRealm.java:265` rejects a realm without a default role. The synthetic setup had disabled automatic role assignment when creating users but had not initialized the realm's required default role. Its postfailure read-only probe confirms that the additive changeset, nonce constraint and fifteen new binding columns were installed once, with unchanged prior provider history and all eleven original table projections. Initialize an empty synthetic default role before the initial checkpoint and verify a fresh cached-realm read; do not alter the production migration or relax BPO checks. Full startup, concurrency and restart acceptance still require the next complete run.
