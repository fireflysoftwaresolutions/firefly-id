# Authentication security artwork

The Firefly Identity authentication artwork is a complete architectural security campus, drawn with the actual canonical Firefly isometric system used by the [live website](https://fireflysoftware.io/openplatform/architecture/). It preserves the true 30-degree projection, upper-left lighting, shaded faces, studded foundations, restrained palette and depth-aware vector construction. The approved product signature and tagline remain unchanged.

## Scene and meaning

One amber credential vault and its perspective-correct identity badge anchor a raised trust zone. An olive perimeter and controlled amber entry enclose that identity. Customer and employee access points sit outside the perimeter, while a policy engine, audit store and application adapter make authorization, evidence and connection visible. Four intentional thin routes connect the relevant zones.

The desktop composition has 24 purposeful pieces. It is one coherent architectural object with layered foundations and a clear central focus, rather than isolated decorative blocks. The smaller composition retains the complete 12-piece security enclosure and credential core. Neither scene contains labels, user data, third-party vendor logos or asserted deployment claims.

| Asset | Use |
| --- | --- |
| `assets/identity-backgrounds/authentication-light.svg` | Complete 24-piece campus on paper or white |
| `assets/identity-backgrounds/authentication-dark.svg` | Same campus on charcoal, using the canonical dark product foundation |
| `assets/identity-backgrounds/authentication-mobile-light.svg` | Complete 12-piece security enclosure for narrow layouts |
| `assets/identity-backgrounds/authentication-mobile-dark.svg` | Same reduced enclosure for dark narrow layouts |
| `assets/identity-backgrounds/composition.json` | Original editable layout, dimensions, materials, connections and variant definitions |
| `assets/identity-backgrounds/validation.json` | Four canonical reproduction and full scene-check matrices |
| `assets/identity-backgrounds/index.html` | Desktop and mobile composition reference |
| `assets/identity-backgrounds/provenance.json` | Exact sources, rights, hashes and qualification scope |

All artwork is editable SVG, with grouped canonical pieces, reusable vector studs, transparent canvases and no raster or remote image dependency. The desktop viewBox is 916.34 × 565.6, composed for a 624 × 400 authentication illustration region. Use `contain`, preserve its aspect ratio and retain its built-in clear margin.

At narrow widths, use the reduced 455.628 × 381.3 scene as a crisp contained illustration around 168–200 px wide. Its identity core and complete perimeter remain visible at full vector quality. Keep artwork separate from the opaque form surface; avoid fading a busy campus into a texture behind form controls. This shared artwork supports customer and employee identity journeys without replacing upstream authentication behavior.

## Source evidence

Sources were inspected on October 31, 2026:

- Live [Firefly homepage](https://fireflysoftware.io/) and [OpenPlatform architecture](https://fireflysoftware.io/openplatform/architecture/), including the rendered seven-layer isometric assembly and connected service example.
- `fireflysoftwaresolutions/firefly-software-website` current remote `795a80c1b11250630bd0e399a3c5c8763f3c9864`: `scripts/brand/system/pieces.mjs`, `tokens.json`, `pieces.json`, `architecture.json`, `colour.mjs` and `scene-check.mjs`. All six local source blobs were independently matched against the current remote before use. The renderer blob is `b0f94355dcdf96b4ebb4f18fa6d11af2daf40e49`; the canonical website system version is 1.4.0.
- Private `fireflysoftwaresolutions/brand-kit` current remote `eb8f3fae894c517c5d39c3d4ffc07547f8e17a1b`: `data/diagram-system.json`, `data/design-system/tokens.json`, `docs/graphic-language.md` and `NOTICE.md`. The kit defines projection, material meanings, one light source and single-focus composition rules. Its 1.3.1 tokens retain the same core palette and face recipes; the current website renderer supplies the 1.4.0 geometry.

Copyright 2026 Firefly Software Foundation Inc. for the original composition. The private brand kit identifies Firefly Software Solutions Inc. as the owner of its canonical marks and graphic systems; the new-composition copyright does not alter those source rights. Only necessary rendered artwork and the original declarative composition are included. Private generators, their source code and unrelated brand-library assets are not redistributed. Software licensing does not grant trademark or private-kit rights. The preview references the existing Manrope font under SIL OFL 1.1 in `assets/brand/fonts/OFL.txt`.

## Depth order and pipe topology

SVG painter order comes from canonical `build()` → `depthOrder()`. Projected-volume overlap constraints compare x/y separation and resting z planes before a deterministic topological ordering. Faces, studs, cylinders, elbows and conduit segments participate before SVG emission. CSS `z-index` does not repair internal artwork order.

All four light/dark desktop/mobile cases reproduce canonically and return no findings from structural rules or full `checkScene()`. These checks cover support, interpenetration, occlusion, pipe intersection/clearance, excessive covering and bounds. They supplement direct enlarged review; they do not certify visually plausible mating by themselves.

Four 0.1-radius routes approach their actual visible entry faces perpendicularly. Customer and employee access meet separate perimeter controls; the application connection enters the raised foundation; policy and audit have a separate path. No redundant endpoint caps or sockets are drawn. Unused built-in ports on the application adapter and employee channel remain disabled. All exact endpoint coordinates and approach directions are recorded in `validation.json`.

## Visual qualification

The complete light/dark artwork was inspected at the actual 624 × 400 target, in a 1440 px authentication composition and a 390 px mobile composition. Enlarged topology review covers the controlled entry, perimeter overlap, credential badge perspective, visible pipe entry faces and elbows. The mobile variant preserves the complete enclosure without busy peripheral routes. All referenced images and Manrope loaded; the 390 px reference has no horizontal overflow.

This evidence covers the artwork and composition reference. Actual Keycloak login, logout, recovery, consent, MFA and customer/employee journey behavior require separate integration validation.
