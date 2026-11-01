# Maintain this handbook

The handbook lives with the implementation. Markdown is the authored source; MkDocs/Material produces a static reading site. Configuration references derive from the actual policy/image catalogues, original branding/font assets are packaged without redrawing them, and source-file links point to the exact documentation revision.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `mkdocs.yml` | Public navigation, theme/search, strict validation and generated reference entries |
| `requirements-docs.txt` | Pinned direct documentation dependencies: MkDocs 1.6.1 and Material 9.8.0 |
| `docs/*.md` | Public maintained guides, control mappings and evidence |
| `docs/stylesheets/extra.css` | Read-surface styles using canonical Firefly tokens and self-hosted Manrope |
| `docs/overrides/partials/copyright.html` | Foundation copyright, Keycloak recognition and documentation-tool credit |
| `docs/overrides/partials/source.html` | Plain repository link without automatic third-party repository-statistics requests |
| `docs/overrides/partials/path.html` | Accessible handbook/section/page trail, including a homepage grouped under Overview |
| `tooling/documentation_support.py` | Dependency-free source-link, publication-scope and generated-policy helpers |
| `tooling/mkdocs_hooks.py` | Generated references, original asset inclusion and build provenance |
| `.github/workflows/documentation.yml` | Hosted strict build/output/browser qualification |
| `.work/documentation/` | Ignored generated output, safe evidence and source-matching publication bundle |

Internal `docs/superpowers` planning and theme override templates are excluded from the published handbook. A public guide may link an internal design as a versioned repository source reference; that does not copy the internal tree into the site. `.state`, credentials, owner manifests, raw logs, private-source index examples and generated dependency/runtime directories must never enter the public static bundle.

## Build in an approved environment

The following commands are for a development/CI environment with permission and capacity to install documentation dependencies. They do not start Keycloak, Docker, Maven, a database or a proofing provider:

```sh
python3 -m venv .work/docs-venv
.work/docs-venv/bin/python -m pip install -r requirements-docs.txt
.work/docs-venv/bin/python -m mkdocs build --strict
```

Expected output is `.work/documentation/site`, including the generated policy/version pages, original local font/brand assets, search index and `documentation-provenance.json`. The direct dependency versions are pinned; hosted evidence also records the resolved transitive package set. Review dependency security/maintenance before updates rather than silently installing whatever a future latest release becomes.

Material's maintainers [support critical fixes and security updates through May 5, 2027](https://github.com/squidfunk/mkdocs-material/issues/8523). This handbook honors the requested MkDocs platform and currently pins Material 9.8.0. Review a supported theme or compatible generator transition before that date, testing navigation, hooks, search and asset packaging; do not silently change the platform or keep an unsupported theme indefinitely.

Uncommitted local builds are visibly marked as previews and carry `source_dirty=true`, `publication_ready=false`. Their repository links refer to the committed baseline. Output validation rejects them for publication; an environment-provided source SHA must also match the actual checkout. Publish the clean hosted artifact for the recorded revision rather than relabel a dirty preview as an exact-source build.

For a local reading preview, after an approved install:

```sh
.work/docs-venv/bin/python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

Serve locally; do not bind an unauthenticated development server to a public interface. The canonical public site is the repository GitHub Pages project at `https://fireflysoftwaresolutions.github.io/firefly-id/`. A local build or an expected URL is not proof of publication.

## Make a source-backed change

Read the implementation before editing a control description. Record the exact property, enforcement owner, application mechanism and observable result. Distinguish a new-realm default, an explicit post-bootstrap setting and a retained-realm migration. Keep upstream feature availability separate from Firefly configuration and from actual qualification.

Do not duplicate catalogue values in a new generated table. Change `config/authentication-policies.json` only through an authorized policy change with relevant runtime evidence; the generated reference will follow. For new source links outside `docs`, use the real relative file path: the build maps it to the exact repository revision. Reader-to-reader links remain local and are validated strictly.

Add a page to an appropriate navigation section and give it one clear task. Explain imports/inputs/outputs, context and expected results around code examples. Use synthetic nonsecret placeholders; never include a real issuer/client/customer/credential from an environment. Long reference tables and code may scroll inside their own area, while the page and navigation remain usable on mobile.

## Verify prose, build and behavior

Run `make check` for source helpers and the repository presubmit. `make docs` performs the strict MkDocs build in an environment with the documentation dependencies installed. Hosted qualification additionally validates produced internal links/anchors, publication exclusions, provenance and local font bytes, then exercises actual browser search/navigation/theme behavior at desktop/mobile widths in light/dark.

Inspect the paired screenshots at their real target sizes. Check the title/navigation/footer, long code/table overflow, body measure, focus and the canonical Manrope load. A static HTML preview cannot establish identity-journey security; keep documentation checks distinct from the native/provider integration suites.

When a build fails, preserve its bounded failure and fix the actual source/reference rather than weakening strict mode or hiding the broken page. Do not upload dependency logs, raw browser traces, `.state` or real provider content. A resolved dependency list and safe fixed-stage summary are sufficient build evidence.

## Update qualification claims correctly

[Evidence](evidence.md) is the concise current register; [progress](progress.md) retains the chronological record. An old failure may remain true about that checkpoint while a newer exact-source receipt supersedes its then-pending status. Correct current wording without deleting the history.

Record source revisions, executed build artifact hashes, actual test counts and external acceptance separately. A documentation-only successor does not require pretending the older runtime workflow ran on the new documentation commit. State that its executable/theme inputs are unchanged. Source qualification, package installation, real-provider conformance, consumer adoption, publication and production acceptance are distinct results.

## Regulatory maintenance

The [EU/US matrix](controls-matrix.md) is a dated applicability aid, not a legal certificate. Verify primary legal/regulator sources and effective/application dates before changing it. Preserve the distinctions between banks and FTC-covered nonbanks, federal and state scope, statutory requirements, supervisory guidance and technical standards.

Adding a legal requirement to prose does not implement it. Where the source lacks an owner, factor, trust resolver, incident procedure or real acceptance, identify that gap explicitly and link its decision gate. Do not convert a vendor assurance label, KYC flag, TOTP success or compliance-framework name into a blanket product promise.

## Publication and licensing

The canonical source is this public repository's `docs/` directory and `mkdocs.yml`. GitHub Pages serves the built handbook at [fireflysoftwaresolutions.github.io/firefly-id](https://fireflysoftwaresolutions.github.io/firefly-id/). The earlier private ChatGPT Sites preview is superseded and is not the project documentation destination. Its history/access is preserved; no new publication is sent there.

The Documentation workflow runs source presubmit, pinned strict MkDocs build, actual output validation and real desktop/mobile light/dark browser checks under the **`/firefly-id/` project prefix**. Only a successful push from the selected publishing ref can upload the official Pages artifact; pull requests and workflow dispatch qualification cannot deploy. A separate `pages` job needs the successful handbook job, uses SHA-pinned official actions and has only `contents: read`, `pages: write`, and `id-token: write`. It deploys through the restricted `github-pages` environment and refuses when the remote branch has advanced beyond its source SHA. Build output remains ignored and is not committed to a `gh-pages` source branch.

The repository must have Pages enabled with build type **GitHub Actions**. `DOCS_PUBLISH_BRANCH` is an explicit repository variable; when absent it defaults to `main`. While the implementation remains a draft PR, the owner-authorized `codex/identity-credential-recovery-20261031` branch may be selected so the requested handbook can be published without merging runtime work. The Pages environment allows `main` and that exact temporary branch; the workflow permits only the single selected publishing ref. After integration, set the variable to `main` and replace the temporary environment branch rule with `main`; the next qualified main push publishes it. Do not grant fork/PR refs, broad branch patterns, reusable long-lived publishing credentials or `pull_request_target` execution.

Changing the publishing ref, Pages environment rules or repository visibility is a repository-owner administration operation. Preserve the public repository and desired audience, audit the selected source and maintain normal review/protection on the integration branch. The live handbook's `documentation-provenance.json` identifies its actual source, including when that source is an unmerged candidate. Documentation publication does not merge a PR, release a provider or activate CIAM production.

Preserve exact source, workflow run, bounded build/browser summaries, artifact hashes and actual Pages deployment receipt. Check the public homepage, a nested guide, search assets, canonical project URLs and provenance after deployment. An uploaded artifact or successful strict build alone is not a published Pages site. See GitHub's [custom Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

Footer recognition of Keycloak and the documentation tools is a deliberate open-source acknowledgement. Preserve the actual applicable LICENSE/NOTICE and font OFL files independently; a “Powered by” line is not a substitute for those notices and is not described as a universal license obligation. Trademark permissions remain separate. See [brand](brand.md) and [themes](themes.md).

## Static product diagrams

Author Mermaid fences in product guides. The hosted Documentation workflow installs Mermaid 12.2.0 as a build dependency, uses its existing Playwright browser to render paired SVGs with canonical embedded Manrope, and packages only static SVG output. Run `node tooling/documentation-diagrams.mjs` before MkDocs after installing the pinned builder in `.work/docs-diagrams`. No Mermaid/CDN code runs in the reader. Internal history, contract reviews, provider evaluation and this maintainer guide are excluded from the product navigation, publication and search.
