# Interface tokens and functional icons

`themes/tokens.css` is the shared interface token layer. Load it after Keycloak's inherited styles and before the surface stylesheet. Package the same file for login, account, administration and welcome; avoid independent copies of its values in each surface stylesheet. Font declarations remain beside the packaged font so their relative URLs stay valid.

## Authority

The following private Firefly brand-kit files were inspected directly at revision `eb8f3fae894c517c5d39c3d4ffc07547f8e17a1b` on October 31, 2026:

| Source | Applied rule |
| --- | --- |
| `data/palette.json` | Exact charcoal, paper, amber, ink, muted, gold, white, stone, line and graphite values |
| `data/type.json` | Manrope family and web fallback stack; body 16 px / 1.65 at 400; title 27 px / 1.2 at 450 with −.035 em tracking; label 13 px / 1.4 at 650 with .025 em tracking |
| `docs/icons.md` | 24-unit outline icon grid, 1.5 px screen stroke, round caps and joins, `currentColor`, no fill, 2 px live-area padding and optical size calculation |
| `icons/icons.json` | Catalogue 1.0.0 IDs and their pinned Lucide geometry |
| `icons/LICENSE` | Lucide ISC and inherited Feather MIT attribution requirements |

The palette and type values are canonical brand rules. The 4 px spacing scale, 8/12/16 px radii, 44 px minimum control size and focus dimensions are existing Firefly Identity interface decisions, recorded in `DESIGN.md` and `assets/brand/tokens.json`; they are not represented as private-kit mandates.

The existing machine-readable product token file records rounded title/label weights of 500/600. The shared interface CSS uses the directly inspected canonical variable-font weights of 450/650. Outlined logo lettering is an independent approved asset and remains unchanged.

## Layers

`--ffid-color-*` holds immutable palette values. Semantic roles select those values for the current surface:

| Role | Light | Dark |
| --- | --- | --- |
| `--ffid-canvas` | Paper | Charcoal |
| `--ffid-surface`, `--ffid-surface-raised` | White | Ink |
| `--ffid-text` | Ink | Paper |
| `--ffid-text-muted` | Muted | Stone |
| `--ffid-border` | Line | Graphite |
| `--ffid-border-control` | Muted | Stone |
| `--ffid-link`, `--ffid-focus` | Gold | Amber |
| `--ffid-action` / `--ffid-action-text` | Amber / charcoal | Amber / charcoal |

Dark roles activate with Keycloak's `.pf-v5-theme-dark` or an explicitly applied `data-ffid-theme="dark"`. The consuming welcome surface owns its system-color-scheme behavior. The Identity dark card stays ink `#272820`, matching its current surface styling. The `#1d1f1a` role in the older product JSON came from Koinon; it is not a private-kit palette color and is not introduced into Identity's runtime by this layer.

Use quiet `--ffid-border` for separators. Use the stronger `--ffid-border-control` when an input boundary must remain identifiable. Use charcoal text on amber actions and gold for links on light surfaces. Preserve functional error, warning and success meaning; the token layer does not recolor all status states amber.

The `--pf-v5-global-*` bridge uses names checked against `@patternfly/patternfly` 5.4.2, the declared baseline of Keycloak 26.8.1. It covers live text and heading families, variable-font aliases, body size/line height, base surfaces, text, borders and links. Component layout, status colors, code typography and icon geometry stay outside that bridge. Rebinding it on the dark theme also supports nested theme containers.

## Functional icon subset

`assets/icons/` contains only the catalogue concepts needed by inherited authentication controls: `check`, `error`, `copy`, `chevron-right`, `chevron-down`, `success`, `warning`, `info`, `sync`, `access-management`, `mobile-app`, `security` and `list`. It contains no new logo, vendor mark, sign-out extension or decoration. Keep its unmodified upstream `LICENSE` with distributed copies. `assets/icons/provenance.json` records each source URL, source SHA-256 and every output SHA-256.

Geometry is taken from the exact catalogue source package, `lucide-static` 1.52.0, one individual SVG at a time. The 24 px masters retain geometry and change only the stroke from Lucide's 2 to Firefly's 1.5. The `16/` and `20/` files use the prescribed 2.25 and 1.8 viewBox-unit strokes, respectively, so every size renders a 1.5 px screen stroke. Use each variant at its named physical size; do not stretch a 16 px mask to 24 px. An inline master can alternatively use `vector-effect: non-scaling-stroke` on its shapes.

## Integration contract

Copy the icon tree into each consuming theme's `resources/img/icons/`, with the licence and provenance retained. Dedicated `.ffid-icon` and `.ffid-icon--<catalogue-id>` hooks can use a `currentColor` mask from `../img/icons/16/<catalogue-id>.svg` in the surface stylesheet. A mask must have explicit 16 × 16 px dimensions and must not retain a Font Awesome `::before` glyph. Set 20/24 px dimensions and the matching file only on an explicit larger-icon hook. Keep decorative icons `aria-hidden="true"`; their existing control labels supply the accessible name.

These keys were checked against the actual [`keycloak.v2/login/theme.properties` at Keycloak 26.8.1](https://github.com/keycloak/keycloak/blob/26.8.1/themes/src/main/resources/theme/keycloak.v2/login/theme.properties). Overrides may set their class value to `ffid-icon ffid-icon--<icon>`:

| Parent property | Catalogue icon |
| --- | --- |
| `kcInputErrorIconClass`, `kcFeedbackErrorIcon` | `error` |
| `kcFeedbackWarningIcon` | `warning` |
| `kcFeedbackSuccessIcon` | `success` |
| `kcFeedbackInfoIcon` | `info` |
| `kcResetFlowIcon` | `sync` |
| `kcSelectAuthListItemArrowIconClass`, `kcAngleRightIconClass` | `chevron-right` |
| `kcAngleDownIconClass` | `chevron-down` |
| `kcAuthenticatorDefaultClass`, `kcAuthenticatorRecoveryAuthnCodesClass` | `list` |
| `kcAuthenticatorPasswordClass` | `security` |
| `kcAuthenticatorOTPClass`, `kcLoginOTPListItemIconClass` | `mobile-app` |
| `kcAuthenticatorWebAuthnClass`, `kcAuthenticatorWebAuthnPasswordlessClass` | `access-management` |
| `kcCopyIconClass` | `copy` |
| `kcCheckIconClass` | `check` |

The local restart-login template also contains a literal `fa-sync-alt` element. It requires an explicit dedicated icon hook; changing `kcResetFlowIcon` alone does not reach it. The footer's native language select needs no decorative globe. Native account/admin React SVGs are not covered by these FreeMarker properties; do not globally replace or mask arbitrary `<svg>` elements. A changed React icon needs a separately verified component integration.

## Verification boundary

The distribution packages the shared token stylesheet for login, account, administration and welcome. Login functional icons use dedicated property/class hooks and optical 16/24 px masters; the restart control is explicitly updated. Native account/admin SVG components retain their own semantics while inheriting the shared palette and typography. The theme archive carries Apache LICENSE/NOTICE, Lucide ISC/MIT attribution and the font's OFL notice. Public footer attribution does not replace those distribution files.

The icon sources, XML shape attributes, optical stroke values, licences and recorded output hashes can be checked without running Keycloak. Token source comparison and stylesheet structure can also be checked independently. These checks establish asset and source integrity. Integrated icon visibility, state transitions, keyboard focus, contrast in context and small-screen composition still require review of the packaged theme in the actual Keycloak flows. They are not proved by the asset checks alone.
