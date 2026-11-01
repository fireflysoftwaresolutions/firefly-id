# Interface tokens and functional icons

The [handbook stylesheet](stylesheets/extra.css) extends this family for a Read surface without changing authentication tokens. It keeps canonical Manrope and color roles, with 16 px body text, a 74ch prose measure, 42/35 px desktop/mobile document titles, 25/23 px section headings and 13.6 px navigation/reference text. Code uses a system monospace stack for aligned technical content. The larger document-title hierarchy and bounded scrolling tables are scoped to documentation; the 27 px authentication title remains unchanged.

`themes/tokens.css` is the shared interface token layer. Load it after Keycloak's inherited styles and before the surface stylesheet. Package the same file for login, account, administration and welcome; avoid independent copies of its values in each surface stylesheet. Font declarations remain beside the packaged font so their relative URLs stay valid.

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

Dark roles activate with Keycloak's `.pf-v5-theme-dark` or an explicitly applied `data-ffid-theme="dark"`. The consuming welcome surface owns its system-color-scheme behavior. The Identity dark card uses canonical ink `#272820` in both the product JSON and live interface.

Use quiet `--ffid-border` for separators. Use the stronger `--ffid-border-control` when an input boundary must remain identifiable. Use charcoal text on amber actions and gold for links on light surfaces. Preserve functional error, warning and success meaning; the token layer does not recolor all status states amber.

The `--pf-v5-global-*` bridge uses names checked against `@patternfly/patternfly` 5.4.2, the declared baseline of Keycloak 26.8.1. It covers live text and heading families, variable-font aliases, body size/line height, base surfaces, text, borders and links. Component layout, status colors, code typography and icon geometry stay outside that bridge. Rebinding it on the dark theme also supports nested theme containers.

## Functional icon subset

`assets/icons/` contains only the catalogue concepts needed by inherited authentication controls: `check`, `error`, `copy`, `chevron-right`, `chevron-down`, `success`, `warning`, `info`, `sync`, `access-management`, `mobile-app`, `security` and `list`. It contains no new logo, vendor mark, sign-out extension or decoration. Keep its unmodified upstream `LICENSE` with distributed copies. `assets/icons/provenance.json` records each source URL, source SHA-256 and every output SHA-256.

Geometry is taken from the exact catalogue source package, `lucide-static` 1.52.0, one individual SVG at a time. The 24 px masters retain geometry and change only the stroke from Lucide's 2 to Firefly's 1.5. The `16/` and `20/` files use the prescribed 2.25 and 1.8 viewBox-unit strokes, respectively, so every size renders a 1.5 px screen stroke. Use each variant at its named physical size; do not stretch a 16 px mask to 24 px. An inline master can alternatively use `vector-effect: non-scaling-stroke` on its shapes.

## Apply icons to a theme

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

## Review the installed theme

Keep palette values in the shared token layer and test semantic roles in both appearances. PatternFly aliases describe theme roles rather than fixed physical colors; do not force a light-panel alias to white while rendering paper text. Preserve the inherited warning/success semantics and native console SVGs.

After rebuilding, check real headings, labels, editable fields, dialogs, keyboard focus, icons at their physical size and narrow-screen layout. Include the software, icon and font notices with distribution. See [themes](themes.md) for installation and [brand](brand.md) for product artwork.
