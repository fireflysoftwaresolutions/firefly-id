# Support evidence and privileged administration implementation plan

> Use superpowers:subagent-driven-development for the independent implementation tasks and an independent final review. The user has approved the factor baseline and BPO scope; execute within that scope without another approval gate.

**Goal:** Complete local native support-evidence controls and qualify an opt-in phishing-resistant privileged sign-in profile.

**Architecture:** Keycloak native credential/state enforcement plus a separately owned support authorization SPI; no framework coupling or public support endpoint.

**Tech Stack:** Existing Java Keycloak SPI/JPA/Liquibase, Python standard-library configuration tools, Node/Playwright hosted qualification.

**Spec:** ../specs/2026-11-01-support-privileged-design.md

## Task 1 — Support evidence

- Read existing provider, entities, migration, invalidation and transaction patterns.
- Add meaningful regression tests before changing grant validation, replay identity or proof consumption.
- Implement bounded grant validation, durable nonce fencing and exact one-time proof consumption with attribution; preserve budgets and historical rows.
- Run source/native suites and actual owned database qualification; keep test-only owner code outside shipping artifacts.
- Update support PIN, recovery and production-decision guidance with concrete activation prerequisites and reconciliation behavior.

## Task 2 — Privileged administration

- Use pinned upstream authenticator behavior to specify the complete flow and pre-enrollment guard.
- Add offline profile/validation tests and native guard tests before implementation.
- Build the explicit opt-in profile, native guard and hosted virtual-key positive/refusal exercises. Do not activate real administrator accounts.
- Explain bootstrap transition, supervised enrollment, narrow roles, emergency access and physical-key acceptance in public guides.

## Task 3 — Qualification and delivery

- Obtain a fresh review across both boundaries, resolve important findings with regressions and run complete relevant checks.
- Verify actual hosted runtime, source/image packaging and documentation publication independently. Preserve failures and do not infer regulatory or third-party acceptance.
- Respect the latest instruction not to commit or push without explicit permission. Prepare a reviewable diff before requesting the publication needed for hosted qualification. No merge/release/production rollout.
