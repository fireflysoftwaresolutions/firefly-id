# Start safely

Create a local evaluation with synthetic identities, a dedicated database and a local mail viewer. If you already have a generated state directory, resume it through its recorded lifecycle; a new directory creates a separate environment.

## Choose your installation

| Installation | Use it for | What you need |
| --- | --- | --- |
| Theme distribution | Branded login, account, administration, email and welcome screens | Built Firefly theme and pinned Keycloak |
| Synthetic sandbox | Explore sign-in, account management and population policies locally | Local Docker/Compose, new state directory and free capacity |
| Optional native extension | Known-password unlock, customer PIN and credential-loss recovery | Native JARs, schema review and the services required by the selected journey |
| Institution deployment | Operate the identity service for real users | [Deployment setup](regulated-deployment.md), application registrations and an operating team |

Create production realms and clients through the Admin Console or authorized Admin API using the settings in this manual. Keep the sandbox's HTTP endpoints, users and SMTP sink local.

## Prepare the host

Use Python 3.11+, Node.js 22 and a running local Unix-socket Docker engine with Compose v2. Allow at least **12 GiB free disk** and about 2 GiB of service memory plus engine overhead. Remote/TCP Docker contexts are refused.

Run from the repository root:

```sh
make check
python3 tooling/build_theme.py
```

The theme builder writes `dist/firefly-id-theme.jar` and `dist/themes/firefly-id`, including the local font and assets. It does not start a service. Native extension builds require Java 21 and Maven; their installation is covered in [native recovery](native-recovery.md).

## Create the evaluation

Choose a path that does not exist:

```sh
python3 scripts/generate.py --mode sandbox --output .state/evaluation
```

The result contains `ownership.json`, `compose.json`, realm imports and random credentials. There is no shared default password. If the path exists, resume that environment or choose a different path; do not remove retained state to make generation succeed.

Arrange local DNS or a hosts entry so `id.firefly.test` resolves to `127.0.0.1`. The generator does not change host DNS.

## Start the services

Use the same state path for every lifecycle action:

```sh
python3 scripts/sandbox.py preflight --state .state/evaluation
python3 scripts/sandbox.py pull --state .state/evaluation
python3 scripts/sandbox.py up --state .state/evaluation
python3 scripts/sandbox.py status --state .state/evaluation
```

`preflight` checks capacity, the theme, ownership, the Compose hash and the local engine. `pull` downloads the pinned images explicitly. `up` uses `--pull never` and waits for readiness. If a step fails, preserve the directory and follow [troubleshooting](troubleshooting.md).

| Purpose | Address |
| --- | --- |
| Identity service | `http://id.firefly.test:8180` |
| Customer Account Console | `http://id.firefly.test:8180/realms/sandbox-customers/account/` |
| Workforce Account Console | `http://id.firefly.test:8180/realms/sandbox-workforce/account/` |
| Customer discovery | `http://id.firefly.test:8180/realms/sandbox-customers/.well-known/openid-configuration` |
| Temporary administration | `http://id.firefly.test:8180/admin/master/console/` |
| Synthetic mail viewer | `http://127.0.0.1:8025` |
| Readiness | `http://127.0.0.1:9000/health/ready` |

The administrator username is `sandbox-bootstrap`; its random password is in `.state/evaluation/secrets/admin-password`. Application usernames/passwords are in `.state/evaluation/credentials.json`. Read these locally and keep them out of logs, tickets and commits.

## Sign in and explore

Open the customer Account Console and sign in with the customer username/password recorded in `.state/evaluation/credentials.json`. This built-in application lets you explore profile, credentials and sessions immediately. Use the workforce Account Console with its separate recorded workforce credentials to try employee enrollment and sign-in.

The environment has separate customer, workforce and institutional-human realms. Workforce users enroll an authenticator before finishing their first fresh sign-in. Customer MFA is optional in the base sandbox. English and Spanish follow native locale selection and the optional footer control.

The registered clients expect an application at `http://localhost:3000/oidc/callback` or a confidential backend at `http://localhost:8081/oidc/callback`. This repository does not start those applications. Register your client using [the integration guide](integration-contract.md), or use the supplied runtime tooling in a prepared test environment. A client must validate its response, and its API must validate the access token.

Explore [customer journeys](customer-journeys.md), profile editing, email verification and logout. Messages go to Mailpit using synthetic `example.invalid` addresses. Use a separate disposable user when trying permanent blocking; three applicable failures do not expire automatically. [Authentication policies](authentication-policies.md) explains the recovery choices.

## Stop and resume

```sh
python3 scripts/sandbox.py stop --state .state/evaluation
```

Stopping preserves the database volume, generated state and credentials. Mailpit messages disappear when its process stops. Resume with `up` against the same path. The helper deliberately has no reset/delete/prune command.

Read [sandbox details](sandbox.md) for networking and alternate paths, [configuration](configuration-reference.md) for defaults, and [regulated deployment](regulated-deployment.md) when preparing an institution environment.
