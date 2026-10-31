---
name: Firefly Identity
description: Firefly customer identity and access management, built on Keycloak
colors:
  charcoal: "#10110f"
  paper: "#f3f1eb"
  amber: "#ffb34a"
  ink: "#272820"
  muted: "#62645b"
  gold: "#855414"
  white: "#ffffff"
  stone: "#bfb8ab"
  line: "#d8d4ca"
  graphite: "#474a42"
typography:
  title:
    fontFamily: "Manrope, sans-serif"
    fontSize: "27px"
    fontWeight: 450
    lineHeight: 1.2
    letterSpacing: "-0.035em"
  body:
    fontFamily: "Manrope, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.65
  label:
    fontFamily: "Manrope, sans-serif"
    fontSize: "13px"
    fontWeight: 650
    lineHeight: 1.4
rounded:
  control: "8px"
  panel: "12px"
  dialog: "16px"
spacing:
  unit: "4px"
  small: "8px"
  field: "16px"
  group: "24px"
  section: "32px"
  large: "48px"
components:
  button-primary:
    backgroundColor: "{colors.amber}"
    textColor: "{colors.charcoal}"
    rounded: "{rounded.control}"
    height: "44px"
---

# Design System: Firefly Identity

## Overview

**Creative North Star: Protected identity.**

Firefly Identity is a CIAM product in the established Firefly family. A structural arch joins a broad geometric protective cradle. A single amber identity is held within the protected space. The enclosure makes protection visible and carries the Firefly spark. The mark is restrained, balanced and legible at small sizes, without a literal letter puzzle or generic keyhole. Meaningful abstraction serves the product's identity and access purpose.

The family signature preserves the official outlined Firefly wordmark, amber spark and solid chevron, then adds a thin divider, the chosen protection emblem and lowercase `identity` in outlined Manrope 500. The emblem is scaled to the lettering and placed directly beside `identity`, as requested. It is also used independently for favicon. The solid chevron is an official small-size variant. Parent geometry is rendered by the canonical private generator; that generator is not redistributed.

The visual authority is the current private Firefly brand kit. Actual koinon and liquidOS source confirms the same family. Exact revisions and paths are recorded in `assets/brand/provenance.json`. Rejected studies are retained only in internal `.work/brand/` evidence, outside the public brand assets.

## Colors

`assets/brand/tokens.json` is the canonical machine-readable palette. Exact values come from private brand-kit `data/palette.json` at `eb8f3fae894c517c5d39c3d4ffc07547f8e17a1b`. Charcoal `#10110f`, paper `#f3f1eb` and amber `#ffb34a` establish the family. Ink `#272820` and muted `#62645b` serve light text roles; gold `#855414` supplies amber-family text on light. Stone `#bfb8ab` serves dark secondary text; line `#d8d4ca` and graphite `#474a42` supply rules.

Amber actions use charcoal text. Gold, rather than amber, is suitable for ordinary accent text on paper or white. Semantic roles in `tokens.json` include light surface `#ffffff`, light canvas `#f3f1eb`, dark surface `#272820` and dark canvas `#10110f`. Supporting family tones steel `#b4bdb8`, slate `#6b8795` and olive `#7a8460` are reserved in the token file.

The private parent-logo generator contains an older paper constant; rendering explicitly receives the current palette's `#f3f1eb`.

## Typography

Use **Manrope everywhere**, including layouts, forms, labels and all interface states. The self-hosted variable font lives in `assets/brand/fonts/` with its SIL OFL 1.1 license. Body: 16 px / 1.65 at 400. Labels: 13 px / 1.4 at 650 with .025em tracking. Titles: 27 px / 1.2 at 450 with -.035em tracking. These values follow the canonical `data/type.json` and apply to the live login title. Brand lettering is independently approved outlined SVG; interface text remains live text.

## Layout

Use a 4 px spacing unit and the 4/8/12/16/24/32/48/64/96 scale. Authentication is an operational task: use a balanced two-column desktop composition with the approved signature and canonical isometric identity scene on the left, and a 480 px focused form on the right. At 900 px and below, use a single column and a reduced, quiet isometric background behind the opaque form. Labels, recovery paths, keyboard focus and primary actions remain clear in every journey. The repository banner is a deliberate 1280 × 400 composition with the approved family signature and its adjacent protection emblem. It contains no subtitle or upstream attribution. Its tagline connects identity to the ecosystem: “Identity at the heart of every connection.”

Account and administration are operational workspaces. Keep the native navigation, forms and safety warnings. Use a continuous charcoal masthead, the shared semantic palettes and clear action hierarchy. On narrow screens, the masthead reflows into two rows; welcome text spans the content grid, and secondary actions wrap without clipping. The administrative welcome retains a 65ch maximum description width and removes its extra desktop indentation on phones. Review actual packaged consoles at 320, 390, 768 and 1440 pixels in light and dark modes.

## Elevation & Depth

Brand assets are flat vector artwork without shadows, texture or gradients. Login surfaces may use the implemented soft, offset elevation; do not add decorative glow to the mark.

## Shapes

The approved mark uses a 96-unit construction grid. A 10-unit arched contour rises above a broad cradle with 13-unit walls and a curved lower enclosure. A central 12 × 15 unit amber identity sits within the protected space. The chosen geometry is preserved exactly across color variants. Mono variants use one ink for arch, enclosure and identity. The symbol retains its clear silhouette at 16 px.

Family radii are 8 px controls, 12 px panels and 16 px dialogs. The production SVG signature uses viewBox `0 0 580 96`; the independent mark uses `4 4 88 88`; favicon uses `0 0 96 96`.

## Components

Use `firefly-id-light.svg` on white/paper, `firefly-id-dark.svg` on charcoal, and the corresponding mono-black/mono-white variants for one-color reproduction. At 160 px wide or more, use the full family signature; below that use the independent symbol. `favicon.svg` provides a charcoal app tile. Preserve at least the parent wordmark's x-height of clear space around a placed signature.

The brand reference at `assets/brand/index.html` was directly inspected at 1440 px and 390 px wide, including light/dark/mono variants and symbols at 16/24/32/64 px. The final repository banner was separately inspected at 1280 × 400. This evidence covers brand assets and their reference composition; integrated Keycloak flows require separate validation.

## Do's and Don'ts

- Preserve the official parent artwork, all proportions and exact canonical colors.
- Keep protected-identity meaning intelligible; product meaning takes priority over decorative abstraction.
- Use Manrope across every layout, form and interface.
- State CIAM purpose directly; avoid generic experience slogans in the banner.
- Do not retype the parent wordmark, stretch, rotate, add effects or rearrange the signature.
- Keep trademark rights distinct from software licensing and font licensing.
