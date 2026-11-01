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

Uncommitted local builds are visibly marked as previews and carry `source_dirty=true`, `publication_ready=false`. Their repository links refer to the committed baseline. Output validation rejects them for publication; an environment-provided source SHA must also match the actual checkout. Publish the clean hosted artifact for the recorded revision rather than relabel a dirty preview as an exact-source build.

For a local reading preview, after an approved install:

```sh
.work/docs-venv/bin/python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

Serve locally; do not bind an unauthenticated development server to a public interface. The separately hosted documentation Site is private unless its owner explicitly changes access. A static build or an expected hosting URL is not proof of publication.

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

Publish only output built from the recorded source. Preserve the Site ID and audience, keep any source credential in memory/stdin and package only the validated static output plus hosting manifest. Generated output remains ignored rather than committed as authored source. Keep the canonical repository and retained checkouts/remotes intact.

Footer recognition of Keycloak and the documentation tools is a deliberate open-source acknowledgement. Preserve the actual applicable LICENSE/NOTICE and font OFL files independently; a “Powered by” line is not a substitute for those notices and is not described as a universal license obligation. Trademark permissions remain separate. See [brand](brand.md) and [themes](themes.md).
