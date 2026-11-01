![firefly identity](assets/brand/repository-banner.svg)

# Firefly Identity

Firefly Identity is the Firefly distribution of Keycloak for customer identity and access management. It provides consistent sign-in, account management and recovery, with separate customer, employee and administrative security profiles. Applications use OpenID Connect; business identity records and authorization remain with their owning services.

The distribution uses Keycloak 26.8.1, self-hosted Manrope, English/Spanish text and responsive light/dark themes across authentication, account, administration, welcome and email surfaces.

## Documentation

Read the [Firefly Identity manual](https://fireflysoftwaresolutions.github.io/firefly-id/) for installation, configuration, architecture, integration and operating procedures with diagrams. Its Markdown source is maintained in [docs](docs/index.md) and published with [MkDocs](mkdocs.yml).

| Task | Guide |
| --- | --- |
| Run an evaluation | [Getting started](docs/getting-started.md) and [local environment](docs/sandbox.md) |
| Understand responsibilities and flows | [Architecture](docs/architecture.md), [components](docs/solution-overview.md) and [customer journeys](docs/customer-journeys.md) |
| Connect an application | [OIDC integration](docs/integration-contract.md), [claims](docs/provider-claim-profile.md), [audiences](docs/receiver-audiences.md) |
| Configure security | [Policies](docs/authentication-policies.md), [workforce/admin](docs/workforce-administration.md) and [production checks](docs/production-readiness.md) |
| Recover access | [Journey selection](docs/access-recovery.md), [native unlock](docs/native-recovery.md) and [credential loss](docs/credential-loss-recovery.md) |
| Customize the experience | [Themes](docs/themes.md), [languages](docs/localization.md), [tokens](docs/design-tokens.md) and [brand](docs/brand.md) |
| Operate the service | [Deployment](docs/operations.md), [backup/restore](docs/retained-data.md), [monitoring](docs/observability-incidents.md) and [notifications](docs/notification-operations.md) |

## Start locally

Use Python 3.11+, Node.js 22, Docker Compose v2 and a local Unix-socket Docker engine. Allow at least 12 GiB free disk. Configure `id.firefly.test` to resolve to `127.0.0.1`, then run from the repository root:

```sh
make check
make theme
python3 scripts/generate.py --mode sandbox --output .state/evaluation
python3 scripts/sandbox.py preflight --state .state/evaluation
python3 scripts/sandbox.py pull --state .state/evaluation
python3 scripts/sandbox.py up --state .state/evaluation
```

Generation creates separate synthetic populations and random local credentials and refuses to overwrite existing state. Use the same state path to inspect, stop or resume the environment. Read [getting started](docs/getting-started.md) for addresses, credentials, application callbacks and safe lifecycle steps.

## Select the modules you need

The ordinary distribution provides the Firefly themes, identity policies and application integration. Native recovery is optional and adds local existing-factor unlock, customer support-PIN lifecycle and password/TOTP replacement after independent identity verification.

Existing-factor unlock uses the native provider/gateway and separate Domain/Core SCA services. Credential-loss recovery uses Core KYCB as the system of record and a customer Domain adapter for the selected third-party verifier. Configure those backend services before selecting the native theme. Telephone/BPO PIN verification also requires an authorized case/call integration. [Components](docs/solution-overview.md) and [recovery](docs/access-recovery.md) explain the setup.

## Security and deployment

Customer and workforce realms have distinct issuers, managed party/staff links and policies; privileged administration uses its own plane. The selected policy permanently blocks ordinary authentication after three failures, with a distinct secure recovery transition. Every receiving Experience, Domain and Core service must validate its own caller and current action/resource permission.

For real users, configure production domains, HTTPS, private administration, database TLS/privileges, secret management, factor policies, application registrations and operating procedures. Use [regulated deployment](docs/regulated-deployment.md), [production configuration checks](docs/production-readiness.md) and the [EU/US controls guide](docs/controls-matrix.md). Keep local users, HTTP endpoints and the mail sink in the evaluation environment.

## Build and contribute

`make check` runs the repository presubmit. `make theme` builds `dist/firefly-id-theme.jar` and unpacked themes. The ordinary and native Containerfiles consume their respective packages; see [operations](docs/operations.md) for build and installation steps.

Keep credentials, tokens, database dumps and generated state out of issues, commits and artifacts. Software licensing and protected brand rights are described in [LICENSE](LICENSE), [NOTICE](NOTICE) and [brand usage](docs/brand.md).
