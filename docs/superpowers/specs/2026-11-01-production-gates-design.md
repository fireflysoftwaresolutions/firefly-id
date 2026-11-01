# Independent production controls and GitHub Pages

The owner explicitly requests execution: close independent security/production gaps with tests, retain institution decisions, and publish canonical MkDocs from this public GitHub repository through its GitHub Pages project. The existing ChatGPT Sites publication is superseded; preserve its history and do not delete it or change its access.

Use the existing isolated checkout and Python/Node conventions. No local JVM, Maven, database, Docker, dependency install, clone or cleanup. No KYC selection, framework coupling, production CIAM activation, merge or release. American English artifacts; Spanish owner communication.

## Deliverables

1. Canonical `site_url` and README point to the repository's Pages project. The Documentation workflow uploads Pages only after strict/output/browser checks. Deployment has minimal job-scoped permissions, a protected `github-pages` environment and a single explicit publishing ref. Pull requests cannot publish. While the draft remains unmerged, the owner-authorized feature branch may be selected explicitly; main becomes the publishing ref after integration. Preserve GitHub source and evidence, never commit built HTML.
2. Harden the production server reference: management inherits HTTPS, modern TLS protocols and outgoing hostname verification are explicit, legacy observability remains disabled. PostgreSQL must use peer/hostname verification in its full URL; adding ignored URL properties cannot repair an unsafe full URL.
3. A dependency-free, read-only candidate audit checks fully resolved literal Keycloak configuration plus explicit customer/workforce/admin realm exports. Reject ambiguous/duplicate input, unresolved values, insecure transport/trust, bootstrap/static secrets, unsafe client grants/redirects, weak catalogue settings and population collisions. Output only fixed control IDs, never values, paths, usernames or secrets. Pass means candidate checks only, never production/legal approval. It does not emulate all Keycloak configuration precedence or validate deployed network/DB privileges/factor flows.
4. A maintained decision register separates implementable controls, actual evidence and owner decisions (factor profiles, privileged recovery/BPO, real channels, KYC assurance/reference, topology/custody/legal scope). No approved boolean can turn these into implemented controls.

## Verification

Observe meaningful tests fail before adding the audit, then run the complete source presubmit. Add refusal cases for secret-bearing malformed inputs, insecure DB URL properties/duplicates, wildcard proxies/redirects, unsafe client grants and missing/colliding populations. Audit is offline and cannot connect/mutate state. Hosted MkDocs validates every page under the real Pages base path in desktop/mobile light/dark. Verify the actual Pages deployment and public canonical/provenance URLs, not merely an upload receipt.
