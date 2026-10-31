# Firefly Identity implementation plan

> Execute the explicitly authorized independent workstreams in parallel; root integrates and reviews. No additional generic approval is required by the delegated request.

**Goal:** Deliver a public, Firefly-branded Keycloak distribution with reproducible setup and evidence-backed OpenPlatform integration.

**Architecture:** Supported Keycloak theme inheritance; dedicated PostgreSQL identity storage; CIAM behind generic Jafly boundaries. Business persistence and policy remain in their owning services.

**Tech stack:** Keycloak 26.8.1, PostgreSQL, Compose, Python standard library, SVG/CSS/FreeMarker.

**Spec:** [Design](../specs/2026-10-31-firefly-id-design.md).

## Constraints

- American English public artifacts; Firefly Identity identity with lowercase visual wordmark.
- Public repository, authorized focused commits/pushes; no destructive cleanup or production deployment.
- Dedicated new checkout; parent handoff is read-only.
- No new heavy test stack until 12 GiB initial/8 GiB ongoing disk floors and parent coordination permit it.
- Pin actual supported versions and digests; never weaken issuer, audience, PKCE or trust boundaries for demonstrations.
- Preserve alternate CIAM adapters and one exact coordinated Jafly version, currently published 26.10.23.

## Tasks

- [ ] Inspect actual remotes and source contracts. Produce integration matrix with immutable refs and explicit gaps. Verify claims against source, distinguish legacy contracts from signed-proof design.
- [ ] Discover canonical brand sources; implement original vector identity, tokens, font licensing, banner and provenance. Review target-size light/dark/tiny assets.
- [ ] Implement deployment generator, isolated sandbox, pinned images, secret injection and production-oriented settings. Write failure tests for dangerous redirect/grant/attribute configurations; run stdlib tests and Compose validation.
- [ ] Implement real inherited login/account/admin/email theme. Write package/resource tests first; package a deterministic theme JAR and verify entries. Keep upstream protocol templates inherited, with a branded footer/email layout and CSS.
- [ ] Write architecture, setup, integration, security, operations, troubleshooting and theme flow guides; publish coherent README and CI source/runtime lanes.
- [ ] Review whole repository and run source checks, package checks and hosted CI. Publish qualified closed source blocks. Coordinate exact artifacts with parent.
- [ ] Once admitted, run actual Keycloak/PostgreSQL, browser/OIDC positive/negative flows, recovery using synthetic mail, restart/logout/rotation and genuine Jafly integration. Preserve explicit pending status until actual evidence exists.

## Review focus

Redirect/logout allowlist bypasses; editable identity linkage; wrong container/browser issuer; public client secrets; inherited UI regressions; unintended private source publication; roles treated as financial authority; deployment scripts affecting unrelated resources.
