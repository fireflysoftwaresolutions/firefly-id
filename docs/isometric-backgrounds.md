# Authentication isometric artwork

The Firefly Identity authentication artwork extends the actual canonical Firefly isometric system. It uses the same rendered pieces as the current [Firefly website](https://fireflysoftware.io/openplatform/architecture/): a true 30-degree projection, upper-left lighting, precisely shaded faces, studded foundations, amber Firefly modules, ivory channels, steel adapters and orthogonal connection pipes.

## Scene and meaning

One amber access gateway anchors the composition. A person tile sits within its foundation. Two deliberate connections link that protected identity to an application channel and a service behind an adapter. It is an identity/access composition, rather than a decorative enlargement of the logo. It contains no labels, user data, vendor logos or invented technical claims.

| Asset | Use |
| --- | --- |
| `assets/identity-backgrounds/authentication-light.svg` | Complete desktop scene on paper or white |
| `assets/identity-backgrounds/authentication-dark.svg` | Complete desktop scene on charcoal, with the canonical dark product foundation |
| `assets/identity-backgrounds/authentication-mobile-light.svg` | Quiet central gateway and person for narrow layouts |
| `assets/identity-backgrounds/authentication-mobile-dark.svg` | Same reduced composition for dark narrow layouts |
| `assets/identity-backgrounds/composition.json` | Original editable composition: piece identities, locations, dimensions, materials and connections |
| `assets/identity-backgrounds/index.html` | Light/dark desktop and mobile composition reference |
| `assets/identity-backgrounds/provenance.json` | Exact sources, rights, hashes and qualification scope |

All artwork is editable SVG with grouped canonical pieces, reusable vector studs and no raster or remote dependency. The SVGs have transparent canvases. The full scene has a wide aspect ratio suited to a large left-hand illustration region. Use `contain`, preserve its aspect ratio and retain the built-in clear margin. Do not stretch it into a full-screen texture.

On a desktop, place the approved signature and tagline above the illustration, with the focused authentication form on the right. At 900 px or below, use the reduced mobile scene as a quiet contained or lightly cropped background, at reduced visual emphasis, separated from the opaque form surface. It must never reduce form contrast or compete with recovery, logout, error, consent, MFA or employee identity tasks. The artwork is shared presentation; it does not replace upstream journey behavior.

## Source evidence

Sources were inspected on October 31, 2026:

- Live [Firefly homepage](https://fireflysoftware.io/) and [OpenPlatform architecture](https://fireflysoftware.io/openplatform/architecture/), including the rendered seven-layer isometric assembly and the connected service example.
- `fireflysoftwaresolutions/firefly-software-website` current remote `795a80c1b11250630bd0e399a3c5c8763f3c9864`: `scripts/brand/system/pieces.mjs`, `tokens.json`, `pieces.json`, `architecture.json`, `colour.mjs` and `scene-check.mjs`. The local renderer's Git blob `b0f94355dcdf96b4ebb4f18fa6d11af2daf40e49` was verified against the current remote before rendering. The canonical website system version is 1.4.0.
- Private `fireflysoftwaresolutions/brand-kit` current remote `eb8f3fae894c517c5d39c3d4ffc07547f8e17a1b`: `data/diagram-system.json`, `data/design-system/tokens.json`, `docs/graphic-language.md` and `NOTICE.md`. The kit defines the 30-degree projection, material meanings, one light source and single-focus composition rules. The kit's 1.3.1 design tokens retain the same core palette and Firefly face recipes; the current website renderer supplies the 1.4.0 geometry.

The composition is original work for Firefly Identity. Only the necessary rendered artwork and original declarative composition are included here. Private generators, their source code and unrelated brand-library assets are not redistributed. The rendered brand artwork remains reserved Firefly identity material; the repository's software license does not grant trademark or private-kit rights. The approved product logo and tagline are referenced in the composition preview, unchanged. Manrope is used only in that preview and retains its existing font license in `assets/brand/fonts/OFL.txt`.

## Validation scope

Canonical structural rules and the full scene checker returned no findings for the desktop composition, including support, intersection, occlusion, conduit routing and canvas bounds. The light and dark artwork and its responsive composition reference were directly rendered and inspected. This verifies vector artwork and composition behavior; actual Keycloak login, logout, recovery and employee/customer journeys require separate integration validation.

## Depth order and pipe topology

SVG order comes from the canonical renderer's `build()` → `depthOrder()` pipeline. It compares projected volume overlaps, constructs behind/in-front constraints from x/y separation and resting z planes, then performs a deterministic topological ordering. Studs, faces, cylinders, elbows and conduit segments participate before SVG emission. CSS `z-index` is not used to repair internal artwork order.

`validation.json` records four successful canonical reproduction and full scene-check cases: desktop light/dark and reduced mobile light/dark. These cover support, interpenetration, occlusion, pipe intersection/clearance, excessive covering and bounds. Direct enlarged reviews additionally checked visible endpoints and elbows; the automated checker does not certify that a decorative connector is visually mated to its intended port.

Both routes use the canonical 0.1-radius event tap, with no duplicate endpoint caps or sockets. Routes approach their entry faces perpendicularly. The left steel adapter uses `port:false` intentionally: its tap meets the actual inset +x face at `[1.96, 10, 0.85]`, rather than leaving an unused built-in connector visible while a route passes behind it. The other visible contacts are the gateway's y face at `4.96`, its x face at `7.96`, and the channel's x face at `11.96`. The original composition expresses these contacts without changing or redistributing the private renderer.
