# Production activation proposal and client flow guard

> **For agentic workers:** Use superpowers:subagent-driven-development. This continues the authorized production closure; root owns commit, push and publication.

**Goal:** Refuse unreviewed per-client authentication-flow replacement in the offline production audit and provide concrete institutional BPO/privileged choices.

**Architecture:** Extend the existing conservative candidate audit, not a second runtime policy engine. Publish the proposal inside the existing institutional decision guide, linked from the two activation journeys.

**Tech Stack:** Python standard library, unittest, existing MkDocs handbook and hosted workflows.

**Spec:** `docs/superpowers/specs/2026-11-01-production-gates-design.md`; this plan narrows its client-check and institutional-decision deliverables in response to the current owner request.

## Global Constraints

- Existing isolated worktree only. No real accounts, external services, Jafly changes, deployment activation, merge or release.
- No local JVM, Maven, Docker, database, browser runtime or dependency installation. Python/Node presubmit is permitted; hosted CI supplies other proof.
- Preserve retained data, old evidence and other work. No counter reset, new grant, data replacement or cleanup.
- American English repository prose; no secrets, raw exports or sensitive diagnostics.
- Institution choices are proposals until explicitly selected and destination acceptance is recorded. Previous approval covers consultation/support and named password + UV FIDO2 administrative accounts with separate audited emergency access.

## Review Focus

- Built-in client names cannot bypass the new guard.
- Absent/empty override representations must be distinct from malformed false-like values.
- Disabled clients remain inactive, but re-enabling requires a new check.
- A binding guard does not qualify the realm flow, client-policy executors, federation or actual factors.
- Proposed owners, time bounds and hardware selections must not be represented as implemented or legally universal.

### Task 1: Guard client bindings and write the activation proposal

**Files:** `scripts/check_production.py`, `tests/test_production.py`, `docs/production-readiness.md`, `docs/production-decisions.md`, `docs/support-pin.md`, `docs/workforce-administration.md`.

**Interfaces:** Existing `audit(server, realms, catalogue)` fixed-code JSON report remains unchanged. Enabled clients with a nonempty or malformed `authenticationFlowBindingOverrides` emit `REALM_CLIENT`; absent or an empty object are accepted. Explicitly disabled clients retain current behavior.

- [x] Read existing code/doc sections before edits. Add tests covering all populations and six built-in names plus an application; nonempty browser/direct-grant/unknown bindings; null/list/string/boolean/numeric false-like values; absent/empty object acceptance; disabled then re-enabled behavior. Include CLI refusal with a sensitive marker in the offending value and assert no marker in stdout/stderr.
- [x] Run `python3 -m unittest discover -s tests -p test_production.py -v` and capture expected failures before changing code.
- [x] Add the minimal typed-empty-map guard before built-in early return. Do not broaden the checker into factor-flow acceptance or change real configuration.
- [x] Explain the finding and conservative no-override policy in production-readiness. Link the pinned upstream resolver: https://github.com/keycloak/keycloak/blob/26.8.1/server-spi-private/src/main/java/org/keycloak/models/utils/AuthenticationFlowResolver.java . Explicitly retain the need to review client policies/requested flows, federation, the realm flow and real factor enforcement.
- [x] Add a concrete recommended first activation proposal near the beginning of production-decisions, before the detailed existing register. Use two readable tables with recommendation, alternative/tradeoff, and exact institutional decision. Include stable BPO and ADMIN choice identifiers. Link this section from both existing journey activation sections.
- [x] BPO proposal: accountable internal customer-service owner with security approval and a named case/authorization service; initial masked case/customer/status reads and support-case assistance only (exact receiver actions to approve); no financial/account changes, impersonation or customer tokens. Recommend existing authenticated first-party app with independently proven enrolled possession and explicit case/call binding, plus private PIN entry excluding operator/recordings/analytics; fallback private IVR requires independently accepted channel and separate possession, otherwise unavailable. No invented integration. Recommend 60-second grant TTL within existing native 120-second ceiling, one operation, no renewal to repair ambiguity; native three-attempt hold stays. Propose current delegation checks at each protected operation, no positive caching for initial high-risk access, refusal on outage, reconciled original proof/journal. Assign operational/audit ownership and propose response/review targets clearly as unimplemented acceptance objectives. Keep owner unassigned until institution selects a person/service.
- [x] Privileged proposal: retain approved named password + UV key and separate named emergency accounts. Recommend two institution-issued device-bound hardware keys per ordinary admin in separate custody, approved AAGUID/attestation policy qualified on real devices; explain alternative platform/synced factors require separate risk/assurance approval and are outside proposed initial profile. Define task-specific minimum roles, no shared daily superadmin, exact role matrix remains to approve. Recommend fixed RP/origins/private ingress with backend/management isolation. Recommend supervised enrollment/replacement by distinct verifier/approver with HR/current employment proof, no support-PIN or customer recovery fallback. Recommend named emergency custodians and two-person authorization/custody procedure, explicitly not a native dual-control capability; emergency still same factors, monitored, rehearsed, access closed after use without destructive account deletion. State existing administrator session limits from actual catalogue; propose numeric monitoring/review/exercise targets labeled recommendations. Controlled transition requires original-state preservation, valid ordinary/emergency access, retired authority including signed-action-link expiry, and removal of bootstrap injection.
- [x] Source recommendation rationale briefly from NIST https://pages.nist.gov/800-63-4/sp800-63b.html (phishing resistance and key properties; no AAL certification claim) and Keycloak https://www.keycloak.org/server/reverseproxy (private admin origin alone is not ingress denial). Limit source-derived prose; institution targets are engineering proposals, not regulatory mandates.
- [x] End proposal with an actionable approval record checklist: names/services, allowed actions/resources, private/possession channel, hardware/roles/origins, enrollment/emergency authorities, measurable operations/custody and scoped acceptance. State what remains implemented/tested versus destination integration and institutional selection; link existing evidence scope rather than duplicate internal commit history.
- [x] Run targeted tests then `make check`; report commands, failures-before/final counts and limitations in the ignored task report. Do not commit; root handles review and delivery.

## Delivery

Root independently reviews the diff and evidence, commits/pushes the authorized current branch, waits for applicable hosted CI and Pages, and verifies served documentation against the source artifact. No production activation follows from a proposal or a passing offline audit.
