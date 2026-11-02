# Privileged master transition implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development with independent review. User authorized continued testing and documentation; existing commit/push/CI authorization persists.

**Goal:** Qualify exact offline-profile import and transition against a synthetic retained master, and explain institution-owned activation steps.

**Architecture:** A separate owned GitHub-hosted fixture runs the pinned native Keycloak image and PostgreSQL. Enroll synthetic named administrators and an emergency account, export actual master state, explicitly prepare prerequisites, run the existing generator, import its exact output offline into a separate empty owned database, and verify effective settings. Separately apply candidate settings through supported APIs to the original retained master, preserving identities and audit, then verify real authentication and retired authority. Realm replacement is not a retained-data migration. This is an isolated test, never a production transition tool.

**Tech stack:** Existing Python standard-library tooling, Node/Playwright, Keycloak 26.8.1, PostgreSQL, GitHub Actions, MkDocs.

**Spec:** User's request in this conversation: test profile import and transition on a test master without real accounts; document BPO and privileged administration activation decisions step by step.

## Global constraints

- Use the existing isolated worktree; preserve retained data and unrelated work.
- Runtime/JVM/database/browser execution only on owned hosted runners. No local installs or services.
- Fresh run-owned fixture identity, local Docker and ownership checks; never accept an arbitrary URL, realm, database, or state path.
- No credentials, exports, private keys, tokens, full API responses or raw service logs in published evidence.
- No merge, release, real-account activation or Jafly changes.
- The product handbook describes operation and decisions, not internal review bookkeeping.

## Review focus

- A stale/wrong ownership receipt must refuse destructive fixture operations.
- Imported server-normalized values must be compared semantically without silently dropping security controls.
- Retained identities, keys, role mappings and audit must survive the transition.
- Old bootstrap, sessions, refresh/access tokens and outstanding action authority need explicit acceptance or an honest unsupported boundary.
- Emergency access must keep the approved two-factor requirement, not become a bypass.

## Task 1: Actual master qualification

- [x] Inspect existing fixture ownership, TLS, browser helpers and profile validator patterns.
- [x] Add failing offline regressions for ownership and exact-candidate/readback boundaries.
- [x] Implement hosted fixture and workflow, with bounded diagnostics and private ephemeral state.
- [x] Exercise pre-enrolled ordinary/emergency accounts, exact generated candidate import into empty storage, settings-level retained-master transition, retained-state comparison, configuration readback, positive/refusal authentication and old-authority retirement.
- [x] Run local presubmit, independently review, commit/push and run actual hosted qualification; fix evidenced failures and rerun.

Hosted acceptance: run [41382681222](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41382681222), source `920004300411eeabc1f0ef0ec13a0a29909fff4d`, passes all 22 runtime controls and 115 native Java tests (zero failures, errors or skips). Original identities, credential hashes, component material, role mappings and nonempty audits survive. Prior ordinary/emergency/bootstrap access and refresh tokens refuse; fresh ordinary/emergency password plus UV succeeds. Previously opened password action refuses after restart; unexpired signed authority remains reachable and is closed only at its original expiry. This is single-process synthetic acceptance, not destination, hardware, least-privilege, HA or production approval.

## Task 2: Activation instructions

- [x] Extend existing support/admin/decision guides with ordered choices, responsible roles, artifacts to prepare, disabled defaults and measurable acceptance gates.
- [x] Separate agreed defaults from unassigned institutional decisions; distinguish synthetic qualification from destination-specific cutover.
- [ ] Run MkDocs/reading checks in hosted CI and verify exact public artifact after publication.

## Task 3: Delivery

- [ ] Review final diff and source-specific runtime receipts, preserve failure evidence, update draft PR and verify clean remote source.
- [ ] Report actual results and remaining institution decisions without claiming production or regulatory acceptance.

Ruling: pinned Keycloak ImportUtils removes the existing realm before an overriding import. Exact import compatibility and retained-master transition therefore use separate owned databases; the original is never replaced. This preserves the stated data-retention acceptance instead of treating a JSON export as backup.
