# Local sandbox

The sandbox runs Keycloak, dedicated PostgreSQL and Mailpit with synthetic data. It creates `sandbox-customers`, `sandbox-workforce` and `sandbox-institutions`, plus Keycloak's administrative `master` realm. Institutional users represent people; a party link does not give them authority to act for a company.

## Requirements and ownership

Use Docker Compose v2 with a local Unix Docker socket, at least **12 GiB free disk** and approximately 2 GiB of service memory plus engine overhead. The lifecycle helper refuses remote/TCP engines and insufficient disk before pulling or starting services.

Every generated directory has a unique Compose project and `ownership.json`. The helper verifies the ownership marker and exact Compose hash before acting. Keep that directory with its database and credentials. Editing the marker to adopt another service defeats this protection.

## Generate and start

Run from the repository root:

```sh
python3 tooling/build_theme.py
python3 scripts/generate.py --mode sandbox
```

This creates `.state/sandbox` with realm imports, `compose.json` and random secrets. Generation refuses an existing output. For another independent environment, supply a new `--output` and pass its path through `--state` on every lifecycle command.

Configure local DNS or a hosts entry:

```text
127.0.0.1 id.firefly.test
```

Then start the owned project:

```sh
python3 scripts/sandbox.py preflight
python3 scripts/sandbox.py pull
python3 scripts/sandbox.py up
python3 scripts/sandbox.py status
```

`up` uses `--pull never` and waits up to 180 seconds for readiness. Image pulls have a ten-minute command deadline. A refusal or failed start leaves state in place for diagnosis; see [troubleshooting](troubleshooting.md).

## Find the services and credentials

| Surface | Address |
| --- | --- |
| Browser and canonical issuer base | `http://id.firefly.test:8180` |
| Customer discovery | `http://id.firefly.test:8180/realms/sandbox-customers/.well-known/openid-configuration` |
| Internal discovery transport | `http://keycloak:8180/realms/sandbox-customers/.well-known/openid-configuration` |
| Administrative console | `http://id.firefly.test:8180/admin/master/console/` |
| Mail viewer | `http://127.0.0.1:8025` |
| Readiness | `http://127.0.0.1:9000/health/ready` |

Use `sandbox-bootstrap` with the random password in `.state/sandbox/secrets/admin-password`. Synthetic application credentials and confidential-client secrets are in `.state/sandbox/credentials.json`. Keep both files private. The addresses use `example.invalid` and registration is disabled.

`sandbox-web` uses `http://localhost:3000/oidc/callback` and `http://localhost:3000/signed-out`. `sandbox-backend` uses the equivalent paths on port 8081 and a separate client secret. Both use authorization code and S256 PKCE. Password, implicit, device, CIBA and service-account grants are disabled for these interactive clients. The [Configuration lookup client](configuration-service-client.md) is an explicit optional machine profile.

## Understand the network

The browser hostname is also an alias on the internal `identity` network. Backend containers attached to that network can use the canonical hostname directly. Discovery through `keycloak:8180` may advertise internal backchannel endpoints, but the token issuer remains the canonical browser URL. Validate that exact issuer rather than substituting the Docker service name.

PostgreSQL uses only the internal network and has no host port. Keycloak and Mailpit also use an ingress bridge for loopback port publication. SMTP is unpublished and Mailpit has no external relay. The ingress bridge is not an outbound firewall. Check Docker Desktop publication and local DNS behavior on your host before using the environment.

## Try the main tasks

1. Read discovery and JWKS, then complete application sign-in with code/PKCE.
2. Open account management, edit an allowed profile field and sign out. Verify that tenant/party/staff links remain protected.
3. Enroll the workforce authenticator and use a fresh browser session to observe the OTP challenge.
4. Trigger email verification or password reset and read the new message in Mailpit. Treat action links as secrets.
5. Check both languages and appearances at desktop and mobile widths.
6. With a separate disposable user, try the permanent-block policy and the intended recovery route.

Do not connect the sandbox to real customer mail or a shared database. Use [authentication policies](authentication-policies.md) and [customer journeys](customer-journeys.md) to understand each task's prerequisites.

## Stop without losing data

```sh
python3 scripts/sandbox.py stop
```

The database and secrets remain; Mailpit messages are ephemeral. Resume with the same directory/project. Realm import skips existing realms, and PostgreSQL initialization runs only for a new data directory. Editing an import or secret file does not update retained identities or rotate a database password. Follow [retained data](retained-data.md) for migration and backup procedures.
