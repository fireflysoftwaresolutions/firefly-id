# Independent Production Controls Implementation Plan

> Use superpowers:executing-plans for implementation; independent configuration reviewer checks findings. The owner's request supplies scope and authorization, without another permission gate.

**Goal:** Ship tested offline security controls and the canonical public repository handbook on GitHub Pages.

**Architecture:** Existing MkDocs/Actions qualification feeds a narrowly authorized Pages deploy job. A standalone standard-library Python audit checks candidate server and exported realm configuration without network or mutations; institution acceptance stays separate.

**Tech Stack:** Python standard library, existing pinned MkDocs/Material/Playwright, official SHA-pinned Pages actions; no new runtime framework.

**Spec:** ../specs/2026-11-01-production-gates-design.md

## Constraints and review focus

- Preserve checkouts/data/failures, public repository visibility, independent Jafly and all KYC owners.
- No local heavy runtime/dependency work; no merge/release or CIAM rollout.
- Catch unsafe override assumptions: audit accepts resolved file values, refuses ambiguous syntax, and explicitly does not model environment/CLI/keystore precedence.
- No secret-bearing values or exception strings in audit output, including malformed JSON/property/URL inputs.
- Pages uses the project subpath; PRs cannot deploy, stale source cannot overwrite current publishing-ref output, artifacts remain exact-source.

## Task 1 — Independent candidate audit

Files: `scripts/check_production.py`, `tests/test_production.py`, `deploy/keycloak.production.conf.example`, public production/decision guides.

- [x] Write and observe failing behavior tests for secure candidates, unsafe server/realm/client input, parser ambiguity and diagnostic secrecy.
- [x] Implement pure `audit(server, realms, catalogue)` and literal config parser; CLI reads bounded files, outputs fixed findings, refuses malformed/unsupported input and never grants production approval.
- [x] Harden supported reference options, document complete invocation, limitations and owner decision register; run full `make check`.

## Task 2 — Canonical GitHub Pages

Files: `mkdocs.yml`, `.github/workflows/documentation.yml`, `tooling/documentation-runtime.mjs`, `README.md`, `docs/documentation.md`, affected public links.

- [x] Configure public project URL, correct browser test base path, tested build/output/Pages artifact flow and restricted deploy job.
- [x] Enable Pages Actions and exact publishing branch/environment policy without merging draft work; update homepage metadata.
- [x] Push focused source under existing authorization; independently inspect hosted exact-source summaries/screenshots, deploy and verify actual public pages/provenance.
- [x] Review final source, update draft PR and evidence with distinct candidate/audit/runtime/publication and external acceptance results.

## Completion receipt — November 1, 2026

Qualified and published source: `59c40ed6b9259cc6c17592d2b28ff23722322a10`. This later excluded plan completion changes no published guide, checker or runtime input.

- Local/hosted presubmit: 56 Python + 11 Node tests, syntax and diff checks. Twenty candidate-audit tests include positive confidential-machine behavior and mutation refusals. A separate actual-output regression reproduces the Pages-prefixed 404 mapping failure.
- [Production reference 41343858431](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41343858431), artifact `13098437894`: actual digest-pinned Keycloak 26.8.1 `show-config all` accepts all nine expected settings; no database or network. Reference SHA-256 `28aff4c20473ad338bbedee9ddaea10c262e0febb385e5ab2867facf01766f98`.
- [Documentation/Pages 41343858432](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41343858432), artifact `13097918419`: 47 HTML pages including 404, 4,355 local references, 184 actual desktop/mobile light/dark surfaces under `/firefly-id/`, four search/four navigation checks, theme persistence, canonical Manrope/colors/logo, zero external runtime requests/failures. Static tar SHA-256 `288c5671f61f0ff0986c53bfeae708c44a2f8483e22e98fc8489b0d8b62d03fa`; evidence ZIP SHA-256 `dbeba2e33d65e0be47ccdc03bcb4833aa28fa1f00de4a0e7ecf80c743925ec2d`.
- Public [GitHub Pages handbook](https://fireflysoftwaresolutions.github.io/firefly-id/) deployment `7478209994` succeeded from that exact source. Unauthenticated homepage, nested production/configuration guides, search index, provenance and canonical font bytes match the qualified artifact; an unknown route returns the exact custom404 with HTTP404. Actual hosted screenshots were inspected at target sizes. PR Documentation lane passed and its Pages job was skipped as required.
- Independent complete-delta review identified trust-disabling SPI input, temporary-lock budget, JWT grant/logout returns, JDBC mapper substring collisions, health placement and non-OIDC shape gaps. Meaningful tests were observed RED then fixes passed; narrow server-option refusal covers unsupported raw/SPI/public-health overrides. Root additionally reproduced/refused public service-account candidates while accepting confidential machines.
- The initial source6ee3f0b retained two failed receipts: project-prefix output validation and unsupported `show-config --all`. Corrected path resolution keeps escape checks; pinned upstream source established positional `show-config all`. Original artifacts are retained, not relabeled as passes.
- Repository remains public with Pages Actions, explicit publishing-ref variable and literal main/feature environment rules. Default Actions token is read; PR review auto-approval is disabled; secret scanning and push protection are enabled, with validity checks disabled. API readbacks were retained without credential values. The old private Sites preview/history remains preserved and superseded; its inactive manifest is archived under excluded internal receipts.
- Existing draft PR1 has exact new control/build/publication receipts and the separate old native/Core/Domain runtime tuple. Jafly, native Java/JPA/SPI, themes, ordinary generator and KYC adapters are unchanged. The production reference and offline checker have their own new evidence; no actual TLS handshake, database privilege, factor flow, retained restore/HA or institutional acceptance is inferred.

Owner decisions remain in the public production-readiness register. The explicit candidate branch publishes the handbook without a runtime merge; switching publication to main is part of approved integration. No CIAM production rollout, provider selection, release, data deletion or retained-state reset occurred.
