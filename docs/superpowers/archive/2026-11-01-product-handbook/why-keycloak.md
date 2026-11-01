# Why Keycloak

Firefly Identity uses Keycloak as the authentication server and keeps business authorization with the application owners. The choice provides standard application protocols, server-owned credential and session mechanisms, and supported presentation extension points. Firefly adds the identity experience, explicit population policies, reproducible packaging and optional native recovery protocols around that server.

This is the rationale for the implementation in this repository, not a scored procurement exercise. No benchmark, support contract or exhaustive comparison with commercial identity services is claimed.

## What the choice solves

| Requirement | Upstream capability | Firefly implementation and boundary |
| --- | --- | --- |
| Applications need a common sign-in protocol | OpenID Connect discovery, authorization, token, public-key and logout endpoints | Browser examples use authorization code with PKCE S256; every receiver still validates its exact issuer and audience |
| Customers and employees need different identity policies | Realm-specific identity configuration and authentication flows | Separate synthetic customer, workforce and institution realms; the master realm stays administrative |
| Customers need familiar account and credential screens | Login forms, Account Console, required actions and email flows | Inherited server forms and consoles with the `firefly-id` theme; enabled journeys need their own qualification |
| The experience must match Firefly | Supported themes for login, account, admin, email and welcome | Canonical assets, self-hosted Manrope and English/Spanish presentation without replacing protocol authority with browser code |
| Recovery must check native credential state | Optional providers installed into an optimized server image | Version-specific native extensions check local credentials, lock generations and execution state; separate Core/Domain owners authorize recovery |

The protocol capabilities are documented in the official [OpenID Connect endpoint guide](https://www.keycloak.org/securing-apps/oidc-layers). Theme types and inheritance are documented in [Working with themes](https://www.keycloak.org/ui-customization/themes). Provider placement and image augmentation follow the [upstream container guide](https://www.keycloak.org/server/containers). The Firefly-specific entries above are grounded in the [generator](../scripts/generate.py), [theme guide](themes.md) and [native installation contract](native-recovery.md).

## Why extend rather than implement an authentication server

An application should redirect a person to the issuer, receive a bounded authorization result and validate the resulting token at its own boundary. It should not acquire the user's password to manufacture a session. Using Keycloak preserves the server's action tokens, CSRF protections, authenticator enrollment and session model across applications.

Presentation changes remain deliberately narrow. The Firefly theme inherits upstream forms; supported resources supply the logo, typography, color, messages and layouts. Exact-version macro adaptations remove password-reveal controls and normalize public login errors. These adaptations create an upgrade obligation: inherited behavior and copied template fragments must be rechecked together. [Theme architecture](themes.md) identifies those files and checks.

The optional native package addresses operations that a theme cannot enforce: checking an enrolled password/TOTP while ordinary authentication is locked, binding recovery to current native state, replacing lost local customer factors after independent proofing, and retaining a canonical execution journal. These are product protocols with explicit owners. Installing Keycloak alone does not supply them; installing their JARs does not approve their production use.

## Tradeoffs accepted by the design

| Decision | Benefit | Cost or remaining obligation |
| --- | --- | --- |
| Operate a packaged identity server | Control of identity deployment, presentation and integration | Own patching, infrastructure, secrets, availability, incident response and restore rehearsal |
| Keep realms and privileged administration separate | Distinct issuers, profiles and policies | Realm isolation is logical; stronger institutional isolation can require separately operated instances/databases |
| Use native extension APIs only where needed | Credential checks and mutation stay at their authoritative owner | Native JARs target Keycloak 26.8.1 exactly and require requalification on upgrades |
| Keep business records outside identity | Authentication data does not become the customer or employment ledger | Provisioning, identity linking, consent and business authorization need real owner APIs |
| Keep Jafly provider neutral | Applications may integrate another identity provider | Each provider/receiver combination needs its own claim, audience and current-state acceptance |

The official [production guide](https://www.keycloak.org/server/configuration-production) assigns deployment configuration to the operator, including TLS, administrative exposure and database choices. The [high-availability overview](https://www.keycloak.org/high-availability/introduction) explicitly makes end-to-end topology validation an operator responsibility. Those upstream capabilities do not qualify this distribution's retained-database migration, recovery failover or multi-node behavior.

An organization that requires an outsourced operational service should evaluate that operating model before accepting this responsibility. A deployment whose workforce credentials are owned by a corporate provider must preserve that provider's recovery authority; local customer recovery is not a workforce bypass. A deployment needing documentary or biometric assurance must approve a real provider and its evidence contract separately.

## Version, licensing and evidence

**Reviewed November 1, 2026:** the official [26.8.1 release](https://github.com/keycloak/keycloak/releases/tag/26.8.1) was marked latest. This repository pins 26.8.1 and an image digest in [images.lock.json](../deploy/images.lock.json). The version is a qualified input, not an instruction to track a floating `latest` image. Current online upstream guides may evolve; exact installed behavior is checked against the pinned source and runtime receipts.

Keycloak's [Apache 2.0 license at the selected tag](https://github.com/keycloak/keycloak/blob/26.8.1/LICENSE.txt) is separate from Firefly branding and the licenses/notices of distributed assets. Preserve the repository [LICENSE](../LICENSE), [NOTICE](../NOTICE) and [brand guidance](brand.md). The visible Keycloak acknowledgement is the chosen product attribution; do not infer that every footer phrase is a license requirement.

The [latest evidence](progress.md) records the actual normal-distribution, 48-control known-password/PIN and 25-control credential-loss results. These establish bounded synthetic integration behavior. They do not establish banking SCA for every login, regulatory certification, a real proofing-provider approval or a production deployment.

Continue with the [solution overview](solution-overview.md) for component ownership, or [customer journeys](customer-journeys.md) to see how the boundaries affect a person using the service.
