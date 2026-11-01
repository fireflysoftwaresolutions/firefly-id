# Product Handbook Editorial and Diagram Plan

The owner rejects internal integration/contract reviews, commit/run/PR reports and provider evaluation in the product handbook. Execution is authorized: explain use, installation, architecture, flows, configuration and operations with diagrams; investigate actual technical pending items rather than merely rewording them. Preserve engineering history internally and real prerequisites honestly. This is a clarification of the existing documentation objective, not a request for another design approval.

## Constraints

English source; existing Manrope/Firefly/light-dark/MkDocs/Pages; no local dependency installs, browser, JVM, Maven, DB, Docker or destructive cleanup. Existing public repository and qualified runtime inputs remain intact. No provider, bank procedure or infrastructure acceptance may be fabricated. Existing feature-branch publishing and draft PR policy remain.

## Work

- [x] Archive committed original guides under excluded `docs/superpowers/archive/2026-11-01-product-handbook/`.
- [x] Independent writers rewrite disjoint integration, operations/configuration and recovery pages as product guides. Root rewrites overview/customization/glossary/FAQ/navigation and publishing support.
- [x] Remove provider evaluation, progress and evidence reports from publication/search/navigation; preserve internal source/history. Remove development-review/receipt fragments and repeated negative qualification copy across public guides. Retain concrete installation dependencies and unsupported operations.
- [x] Render authored Mermaid architecture/sequence/state diagrams to local static SVGs at build time. Use the existing hosted Playwright browser, pinned Mermaid12.2.0, canonical font and paired Firefly light/dark styles. No runtime CDN or JavaScript diagram dependency. Build fails on syntax/font/diagram failure.
- [ ] Test editorial exclusions and diagram extraction/rewriting before implementation, then full presubmit; hosted strict build, every-page actual desktop/mobile/light-dark checks, diagram visibility/font/overflow/search exclusions.
- [ ] Review rewritten content against implementation; inventory technical 'pending' claims, implement safe independent defects found with meaningful tests, and explain unavoidable external configuration plainly. Publish only qualified exact source to GitHub Pages and verify public bytes. No runtime enablement inferred from prose.

- [ ] Close genuine signed verification-link expiry and passkey enrollment/assertion with an owned hosted RP, plus first-administration access under a restrictive build umask. Preserve real-device/RP/privileged and institution acceptance separately.

## Delegation

Root: index, solution overview, why Keycloak, customizations, themes/brand/tokens/artwork/locales, glossary, FAQ, documentation maintenance, navigation, generated references, diagram tooling/build/QA/publication. `docs_builder_check`: seven architecture/integration guides. `configuration_docs_audit`: thirteen configuration/operation/security guides. `reproofing_native`: eight recovery/notification/provider-connection guides. No overlapping file ownership and no subagent commits/pushes.
