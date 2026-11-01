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
- [ ] Push focused source under existing authorization; independently inspect hosted exact-source summaries/screenshots, deploy and verify actual public pages/provenance.
- [ ] Review final source, update draft PR and evidence with distinct candidate/audit/runtime/publication and external acceptance results.
