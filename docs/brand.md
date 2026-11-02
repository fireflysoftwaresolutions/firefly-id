# Firefly Identity brand

Firefly Identity uses the established Firefly palette and Manrope typography, with an original protected-identity symbol and product composition. The normal visual wordmark is lowercase **firefly identity**. The family signature preserves the actual parent Firefly artwork, its spark and chevron, then adds a divider, the chosen protection emblem and lowercase `identity`. The emblem sits directly beside the product name at a matching scale.

![Firefly Identity](../assets/brand/repository-banner.svg)

## Assets

All brand artwork is editable vector SVG; no raster image or external font service is required.

| Asset | Purpose |
| --- | --- |
| `assets/brand/firefly-id-light.svg` | Primary signature for white or paper |
| `assets/brand/firefly-id-dark.svg` | Reversed signature for charcoal |
| `assets/brand/firefly-id-mono-black.svg` | One-color black signature |
| `assets/brand/firefly-id-mono-white.svg` | One-color white signature |
| `assets/brand/firefly-id-symbol-{light,dark,mono-black,mono-white}.svg` | Independent product identity at 16 px and above |
| `assets/brand/favicon.svg` | Identity mark on a charcoal app tile |
| `assets/brand/repository-banner.svg` | 1280 × 400 repository banner |
| `assets/brand/tokens.json` | Canonical palette and product interface roles |
| `assets/brand/fonts/manrope-latin-wght-normal.woff2` | Self-hosted variable Manrope |
| `assets/brand/index.html` | Responsive light/dark/mono identity reference |

Open the reference locally with a static server, for example `python3 -m http.server 8766`, then visit `http://localhost:8766/assets/brand/`.

The emblem makes protected identity visible: a structural arch and broad geometric cradle enclose a single amber identity. Its balanced silhouette keeps the protection meaning clear at small sizes. The repository banner contains only the family signature with its adjacent protection emblem and **Identity at the heart of every connection.**.

## Use

Use the family signature at 160 px wide or more. Keep at least the parent wordmark's x-height clear on every side. At smaller sizes use the independent product symbol; its structural arch and geometric cradle protect a central amber identity. The favicon is designed for browser tabs and app icons. Preserve aspect ratio and supplied colors. Do not retype the Firefly parent wordmark, redraw its geometry, add effects or rearrange its components.

The canonical palette is charcoal `#10110f`, paper `#f3f1eb` and amber `#ffb34a`, with ink `#272820`, muted `#62645b`, gold `#855414`, stone `#bfb8ab`, line `#d8d4ca` and graphite `#474a42`. Use charcoal text on amber actions and gold for amber-family text on light surfaces. See [DESIGN.md](../DESIGN.md) for semantic roles and typography.

## Licensing

Software licensing does not grant trademark rights in the Firefly parent or product marks. Preserve the [brand notice](../assets/brand/NOTICE.md), supplied artwork and included [Manrope SIL OFL license](../assets/brand/fonts/OFL.txt). Private brand-kit generators and unrelated source assets are not part of this distribution.
