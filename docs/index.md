# Firefly Identity handbook

<p class="handbook-lead">Understand the identity service, configure it deliberately, integrate each trust boundary and operate it with evidence.</p>

Firefly Identity is the Firefly-branded Keycloak distribution for customer identity and access management, with separate workforce and administrative security profiles. This handbook explains the complete solution: the upstream capabilities we use, the configuration we select, the extensions we add and the responsibilities that remain with applications and operating institutions.

<figure class="solution-figure" markdown>
<picture>
  <source media="(max-width: 600px)" srcset="assets/diagrams/solution-mobile.svg">
  <img src="assets/diagrams/solution.svg" width="1040" height="460" alt="Customers and workforce authenticate through Firefly Identity. Experience, Domain and Core independently authorize their operations; KYC records have a separate owner.">
</picture>
<figcaption>Authentication establishes identity. Each receiving application still authorizes its own operation; Core retains business records and recovery authority.</figcaption>
</figure>

!!! note "Read the implementation boundary first"
    The repository supplies a qualified synthetic distribution and optional recovery candidates. Production realm generation remains closed. Customer MFA is optional in the base synthetic profile; workforce password and OTP are mandatory. No real identity-proofing provider or bank procedure is approved. [Qualification and acceptance](evidence.md) identifies the exact passing source revisions and the remaining gates.

## Start with your task

| Your task | Read first | What you should be able to decide |
| --- | --- | --- |
| Evaluate the solution | [Why Keycloak](why-keycloak.md), [solution inventory](solution-overview.md), [architecture](architecture.md) | What the platform owns, what Firefly adds and the cost of operating it |
| Run an isolated evaluation | [Start safely](getting-started.md), [sandbox](sandbox.md), [configuration reference](configuration-reference.md) | How to create a fresh synthetic environment without touching retained state |
| Integrate an application | [Application contract](integration-contract.md), [Jafly](jafly.md), [zero trust](zero-trust.md) | How to authenticate and authorize every receiving boundary without framework coupling |
| Design customer and employee journeys | [Journey map](customer-journeys.md), [workforce and administration](workforce-administration.md), [recovery choices](access-recovery.md) | Which factor, enrollment, recovery and account-management paths apply to each population |
| Prepare a regulated deployment | [EU and US controls](controls-matrix.md), [regulated deployment](regulated-deployment.md), [evidence](evidence.md) | Which obligations apply, who enforces them and what still needs institutional acceptance |
| Operate or investigate an incident | [Operations](operations.md), [retained data](retained-data.md), [observability and incidents](observability-incidents.md) | How to preserve evidence, restore service and avoid manufacturing a new authorization |

## Follow the actual configuration

The [generated policy catalogue](reference/effective-defaults.md) is derived from the same JSON the generator consumes. The [configuration reference](configuration-reference.md) explains the rest of the realm, client, server and extension settings. The [version reference](reference/versions.md) identifies the pinned images and documentation source.

Defaults are a reviewed starting point. They are not a universal password law, an approved payment SCA policy, a production tenant contract or a compliance certificate. The [controls matrix](controls-matrix.md) distinguishes EU legislation, US regulatory requirements, supervisory guidance and technical benchmarks.

## Understand recovery before enabling it

Known-password two-factor unlock and recovery after losing credentials are different purposes. The first requires existing knowledge and enrolled possession. The second requires independently verified identity evidence before a new password and authenticator can be installed. An email link, support PIN, KYC `VERIFIED` flag or employee login cannot replace that authority.

Read [native unlock](native-recovery.md), [lost-credential recovery](credential-loss-recovery.md), [the provider contract](assurance-provider-contract.md) and [notification operations](notification-operations.md) together. KYC/KYB is the system of record; Domain integrates a future third-party verifier. Jafly remains an independent framework.

## Keep the experience coherent

The product uses the approved protected-identity symbol, self-hosted Manrope, canonical Firefly tokens, English/Spanish journeys, light/dark presentation and the established isometric authentication backgrounds. [Themes](themes.md), [localization](localization.md), [design tokens](design-tokens.md) and [brand](brand.md) explain how those resources are built and tested across login, logout, recovery, account and administration.

Presentation preserves the upstream protocol, CSRF and authenticator boundaries. A hidden password-reveal control is a presentation choice; server-side factor, policy, authorization and recovery checks carry the security decision.

## Evidence and maintenance

The latest customer credential-loss lane passed [25 controls](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41332055134); the shared native binary separately passed [48 known-password/PIN controls](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331177242). These are exact-source synthetic-provider receipts. They do not approve a real provider, retained-data rollout or production deployment.

[Qualification and acceptance](evidence.md) gives the concise current record. [Implementation history](progress.md) retains the original failed and successful checkpoints. [Maintain this handbook](documentation.md) explains strict builds, source-linked references and the checks that keep the manual aligned with the implementation.
