# Why Keycloak

Firefly Identity builds on Keycloak to provide standards-based authentication with a consistent Firefly experience. Keycloak manages the security-sensitive mechanics of credentials, authentication flows, action tokens and sessions; Firefly supplies the visual identity, population policies and optional native recovery behavior.

## Standards-based application integration

Applications use OpenID Connect discovery, authorization code with PKCE S256, refresh and logout. They can use their existing OIDC client libraries rather than implementing password handling. APIs validate the issuer and intended audience and keep business authorization at the receiving service.

This division lets several applications share a sign-in experience without sharing passwords. It also keeps Jafly independent: its generic Spring Security configuration can connect to Firefly Identity or another compatible provider.

## Separate identity populations

Keycloak realms provide separate identity configuration, issuers and user stores. Firefly uses this capability to distinguish customers, workforce and privileged administration. Each population can have its own factor, password, session and recovery rules.

Realms are logical boundaries. An institution that requires separate operational ownership or infrastructure isolation should also separate the relevant instances, databases and administrative access. See [architecture](architecture.md) and [workforce administration](workforce-administration.md).

## Supported customization

Keycloak exposes theme inheritance and provider APIs. Firefly uses inherited forms and consoles to keep protocol-generated actions, CSRF protections, enrollment and session handling intact while changing typography, layout, illustrations, icons and copy.

The distribution brands login/logout, required actions, account management, administration, email and welcome surfaces. The [theme guide](themes.md) shows installation and customization points. The native module handles operations that presentation cannot enforce, such as checking existing factors while an account is locked or replacing lost credentials after independent verification.

## Responsibilities you operate

Operating the server means owning patching, certificates, secrets, availability, database access, monitoring, incident response and backup restoration. Native providers also need compatibility checks when the Keycloak version changes. Business identity linking, customer consent, mandates and financial permissions remain in the relevant application services.

For recovery after credential loss, deploy a trusted verification adapter and configure the authoritative customer binding. A local password reset, an email address or a KYC flag alone is insufficient. See [recovery flows](access-recovery.md).

## Version and licensing

The distribution uses Keycloak 26.8.1 with immutable image references. Consult [supported versions](reference/versions.md) and [deployment operations](operations.md) when building or upgrading.

Keycloak uses the [Apache 2.0 license](https://github.com/keycloak/keycloak/blob/26.8.1/LICENSE.txt). Preserve the software LICENSE/NOTICE and asset licenses when redistributing. Firefly trademarks and Manrope font licensing are separate; see [brand usage](brand.md).

Continue with [getting started](getting-started.md) to run an evaluation environment or [application integration](integration-contract.md) to connect a client.
