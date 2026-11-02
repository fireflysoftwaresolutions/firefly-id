# Credential-loss Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Preserve worktrees and evidence.

**Goal:** Implement an independent customer identity-proofing authority and native credential-loss recovery without requiring old credentials or coupling Jafly to Identity.

**Architecture:** Core KYCB owns durable cases and one-time grants; customer Domain owns independently replaceable proofing adapters and genuine SDK orchestration. Native Keycloak replaces factors and retires old authority atomically. No approved real provider exists; successful proofing fixtures are test-classpath-only.

**Tech Stack:** Java 25/Spring WebFlux/Spring Security/R2DBC/PostgreSQL; Java 21/Keycloak 26.8.1 native SPI; hosted CI only for JVM/DB/browser runtime.

**Spec:** ../specs/2026-10-31-credential-loss-recovery-design.md and ../specs/2026-10-31-reproofing-wire-contract.md

## Global Constraints

- Jafly unchanged; DTO/provider-neutral application ports only, no Keycloak in customer/Core services.
- New implementation classes end `Impl` in `impl` subpackages. Preserve existing bean/provider IDs.
- Separate HUMAN/STAFF issuers; customer owner refuses STAFF/admin/foreign credentials.
- Feature disabled without explicit configuration; no implicit synthetic success; no real proofing/compliance claim.
- Preserve retained data/checkouts and released GAVs; no merge/release/deployment. Hosted JVM/DB only at current disk floor.
- Manrope, existing Firefly brand, English/Spanish, responsive light/dark, no reveal or account enumeration.

## Review Focus

- Restart/new case cannot reset subject-generation verified-grant budgets; authenticated negative evidence spends only its case's refusal budget.
- Valid proof for another reference/case/tenant/nonce never authorizes this account.
- Consumed receipt expiry and changed native hold/revision remain authoritative.
- Lost response after native commit resumes only the exact journal, never mutation.
- Forgotten credentials on an enabled user work without permitting administrative holds or old-factor survival.

### Task 1: Durable customer proofing authority (Core KYCB)

- [x] Create isolated candidate from current Core KYCB base, preserve retained checkout; inspect existing conventions and producer/OpenAPI build.
- [x] Write meaningful failing service/actual PostgreSQL tests for case binding, no-provider/forged evidence, strict receiver authorization, immutable expiry, case refusal limits and verified-grant budgets across new cases, parallel consume, replay/current holds and journal reconciliation.
- [x] Implement exact wire DTOs, default-off receiving/security configuration, provider-neutral native/evidence verifier ports, authenticated bounded remote adapters, database-authoritative case/grant/budget/audit and installer-owned SQL. No direct approval boolean endpoint.
- [x] Qualify full actual reactor and actual PostgreSQL scenarios in hosted CI using exact source-parent fixture; generate original producer OpenAPI/SDK, no manual SDK edits/modified released-parent installs.
- [x] Record exact candidate source/SDK artifact/API and evidence for Task 2/3; independent review.

### Task 2: Independent proofing adapters and Domain orchestration

- [x] Create isolated candidate from qualified explicit-sandbox KYB PR head; preserve that focused PR.
- [x] Write failing tests for missing adapter, wrong provider/session/reference/purpose/population, forged/replayed/expired evidence, idempotent provider begin and wrong workload/action.
- [x] Implement server-to-server proofing adapter port, default unavailable behavior, test-only provider, narrow security and native admission checks, orchestration through genuine Task 1 generated SDK. Domain owns no database.
- [x] Build against exact genuine Core producer/SDK in hosted CI; preserve published coordinates and candidate spec hashes; qualify synthetic provider separately from real proofing.
- [x] Record exact Domain source and interface evidence; independent review.

### Task 3: Native replacement and customer journeys

- [x] Write failing native tests for enabled/permanent-lock eligibility, generic unknown initiation, unsupported credentials/holds, complete credential revision, expired consumed receipt, CSRF/Origin, encrypted pending enrollment, factor replacement/retirement and canonical journal retries.
- [x] Implement separate purpose/cookie/ceremony/native RPC and Domain gateway per wire contract. New password follows actual realm policy/history; new TOTP is proved before activation; no old password required. Customer authority cannot recover STAFF/admin.
- [x] Perform atomic current-state checks, credential replacement, eligible lock transition, session retirement, PIN invalidation, revision/generation advancement, durable notification intent and journal. Keep external calls outside native transactions; preserve original expiry and execution on retry.
- [x] Build/test native Java 21 and run actual hosted Keycloak/Core/Domain synthetic-provider integration with real positive preconditions, fault/concurrency/expiry controls and no provider fixture in production packages.
- [x] Review English/Spanish desktop/mobile light/dark forms at target size and Manrope. Document provider setup, notifications, operations/failure/retry and remaining external acceptance precisely.

### Task 4: Independent end-to-end review and handoff

- [x] Independently inspect diffs, producer/SDK pins, default-off receiver chains, native mutation and actual bounded runtime evidence. Fix material findings, requalify only affected scopes.
- [x] Run repository check commands/relative links; report exact local vs hosted source vs synthetic runtime vs unqualified real-provider/production gates. Coordinate source ownership and evidence with parent without editing its handoff.
