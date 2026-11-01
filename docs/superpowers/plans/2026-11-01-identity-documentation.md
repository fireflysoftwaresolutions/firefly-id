# Firefly Identity Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development for independent research/content/review; root integrates the site and validation. Preserve retained checkouts and evidence.

**Goal:** Deliver a complete source-backed MkDocs handbook and reviewed Firefly reading experience, including EU/US applicability and exact implementation/acceptance boundaries.

**Architecture:** Canonical Markdown remains in the Identity repository. MkDocs/Material builds a static site; a small hook supplies original brand/font files, generated catalogue/version references and correct source links. Hosted CI builds/tests; private Sites publication is separate from CIAM deployment.

**Tech Stack:** MkDocs1.6.1, Material9.8.0 (verified official PyPI metadata November1), Python3.12 hosted, existing pinned Playwright1.64.1, canonical Manrope/Firefly SVG. No application runtime or framework upgrade.

**Spec:** ../specs/2026-11-01-identity-documentation-design.md

## Global Constraints

- English repository/site content; owner communication Spanish; actual identity journeys EN/ES.
- Exact canonical colors/font/logo from PRODUCT.md/DESIGN.md; familiar MkDocs Read navigation, responsive light/dark, no tracking or external runtime font/script/CDN fetch.
- EU/USA applicability must distinguish regulation, supervisory guidance and technical standards. Never claim certified/universal compliance or all customer login already SCA.
- Source authority: Core26c3b142c66d4d9ad3a0cc9619d476f2b9d24261, Domain68fa0b7fc849dd3e4dab7756493e344a331bb478, Identity runtime15fd1b7; docs successor0ae3c776. Existing parent/Jafly fixtures unchanged.
- Local lightweight Python/Node only; no local JVM/Maven/DB/Docker/clones/dependency installs or deletion. Hosted build/browser dependencies only.
- No retained-state/credential/raw-log output, CIAM production activation, merge/release, private handoff edit or generated-output commit. Site access private by default; canonical source preserved.

## Review Focus

- A source-file link outside docs must resolve to the exact repository revision rather than break or accidentally publish local secrets.
- Generated policy reference must derive actual values and clearly distinguish optional customer MFA, required workforce OTP, admin gates and sandbox scope.
- Search/navigation, responsive tables/code and actual Manrope must work at390/1440px in both themes, with no external asset requests.
- EU/US control mappings must preserve applicability and implementation gaps; stale historical pages cannot contradict current evidence.
- Documentation publication must package source-matching output and exclude private state, internal plans and logs without changing any CIAM service.

### Task1: Source and applicability audit; substantive handbook

**Files:** create docs/why-keycloak.md, solution-overview.md, getting-started.md, configuration-reference.md, regulated-deployment.md, controls-matrix.md, customer-journeys.md, workforce-administration.md, notification-operations.md, assurance-provider-contract.md, documentation.md, glossary.md, faq.md; update stale statements in existing public guides only with current receipts.

**Interfaces:** consumes live source, existing guides and authoritative cited primary sources; produces linked task-oriented Markdown with exact commands/defaults/limits. Independent writers own disjoint files; root owns shared existing-page edits.

- [x] Read/audit actual policy/generator/deploy/theme/provider settings and latest25/48 receipts; collect primary EU/US scope-aware sources.
- [x] Write the substantive pages above, including safe start/troubleshooting, setup/build/configuration, journey paths, enforcement owners and pending operational decisions; root reviews each before integration.
- [x] Correct stale current qualification claims without rewriting historic failures; build a source/control/page inventory and independent factual review.

### Task2: MkDocs brand, generated reference and strict build

**Files:** create mkdocs.yml, requirements-docs.txt, tooling/documentation_support.py, tooling/mkdocs_hooks.py, docs/index.md, docs/stylesheets/extra.css, docs/overrides/partials/copyright.html, docs/assets/diagrams/solution.svg, tests/test_documentation.py; extend Makefile/.gitignore; add .github/workflows/documentation.yml. Canonical assets consumed from existing paths, never redrawn/copied into authored assets.

**Interfaces:** consumes Task1 pages + existing public docs, config/authentication-policies.json, deploy/images.lock.json and source revision; emits ignored .work/documentation/site with searchable native Material nav, generated reference/effective-defaults.md and reference/versions.md, self-hosted assets and provenance JSON.

- [x] Add meaningful failing local tests for catalogue-derived reference, source-link rewriting/path escape/fragment handling, publication exclusions and asset-byte fidelity; observe RED, then implement the smallest helpers/hook.
- [x] Implement restrained Firefly styles and accessible static architecture diagram; use fonts locally, original mark/header, light/dark preferences and copyright/upstream attribution. Preserve upstream Material navigation/search affordances.
- [x] Configure strict Markdown link/anchor/nav handling, pinned dependencies, original-source links, exclusion of internal plans and private files, and generated references/provenance. Local checks must remain dependency-free.
- [x] Hosted workflow installs docs/browser dependencies, builds strictly, checks output links/anchors/source references/exclusions and uses actual Playwright for desktop/mobile light/dark, search, nav, theme persistence, canonical font hash, local-only requests and overflow. Retain bounded summaries/PNG/static bundle, never logs/state.

### Task3: Integration review and private documentation publication

**Files:** complete shared navigation/README/developer instructions/progress receipts and ignored source-matching static staging; persist supported .openai/hosting.json metadata only after Site creation. No runtime configuration edits unless independently evidenced and tested.

**Interfaces:** consumes qualified source revision/static artifact and review feedback; produces exact private Site version/deployment, complete canonical source/draft PR and transparent acceptance report.

- [x] Run makecheck, strict hosted build/output/browser checks; inspect actual output and paired desktop/mobile screenshots; one batched visual correction/confirmation if needed.
- [x] Independently review code/content and final Read UI; resolve material findings. Confirm source/policy/theme/provider/JPA/SPI runtime bytes unchanged.
- [x] Publish the matching canonical repository source + ignored built output through supported Sites helper/native tools, preserving access and credentials. Persist one returned SiteID; don't re-create or silently change audience. If blocked, keep source/artifacts and report exact blocker.
- [x] Update draftPR/evidence docs with exact build/source/test/publication status and residual legal/provider/production gates. No CIAM deployment, merge, release or cleanup.

## Design check

Fresh builder review: nothing important left. The user supplied the platform (MkDocs), complete-solution scope, established branding and EU/USA coverage; remaining implementation choices are explicitly assigned above. Their execution request remains the authorization; no repeated approval gate is introduced.

## Completion receipt — November 1, 2026

The published handbook is built from `a1997dce729738881da42882500fab1736e400fb`, not from this later internal-plan completion record. [Hosted documentation run 41341035791](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41341035791) passed source presubmit (35 Python + 11 Node), strict MkDocs/output checks and 180 actual desktop/mobile light/dark content surfaces, four real-keyboard searches, four navigation journeys, palette persistence and zero external runtime requests/failures. Artifact `13096854904` contains 46 HTML pages including 404, 4,205 validated local references, exact provenance/dependencies, twelve safe screenshots and the static tar. Root independently inspected summaries, source/catalogue/font provenance, copied bytes and paired screenshots.

Source/factual and scoped visual reviews were integrated. The resulting public handbook has 43 authored guides plus two generated references, including a central customization catalog and scope-aware EU/US controls matrix. Runtime policy/generator/deployment/theme/native JPA/SPI and integration fixture inputs remain unchanged from Identity `15fd1b7`; no new runtime qualification is inferred from documentation checks. Jafly is untouched.

The first publishing attempt found an unsupported static root in the hosting manifest. The final source uses supported `dist/`, staged byte-for-byte from the qualified artifact; the failed attempt and earlier qualified outputs are preserved. The portable archive uses `COPYFILE_DISABLE=1` to exclude macOS AppleDouble sidecars. Final deployment archive SHA-256: `cc4ef8c66f55ebb8f24bb91f46a73a5bd2ac37fe4e048c48bdff1a58f3f1cc97`; hosted static tar SHA-256: `cdcf55d1a7f6cbcd7c7720172d6c5aec22f00786ee82a158629779534f7fb3f6`.

[Private handbook](https://firefly-identity-handbook.me-1867.chatgpt.site) publication succeeded with unchanged owner-only access. Project `appgprj_6ae77d7eb52c8191bc7edb112ffe0933`; saved version `appgprj_6ae77d7eb52c8191bc7edb112ffe0933~appgver_0a21c13cab708191aacf26b8675d6cd2`; final deployment `appgdep_6ae7918586708191bd7918709be5da23`. The integrated-browser handoff is unavailable because its native pipe is absent; native publication succeeded and the exact hosted artifact passed actual browser checks. The existing draft Identity PR was updated with source/build/publication and separate runtime receipts.

The real verifier/reference/assurance policy, institution-specific legal/factor/recovery procedure, permanent administration, workforce/admin lost factors, BPO authority, receiving-wide current-state enforcement, real notification channel, retained-DB/HA acceptance, release and CIAM production rollout remain explicit external gates. This completes the documentation task without asserting those gates were fulfilled. Existing checkouts, origins and retained data were preserved.
