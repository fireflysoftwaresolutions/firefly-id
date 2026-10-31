# Synthetic local sandbox

This sandbox is a provisional example, not an OpenPlatform integration contract. It contains separate `sandbox-customers`, `sandbox-workforce`, and `sandbox-institutions` realms, plus Keycloak's administrative `master` realm. Each application realm has example clients `sandbox-web` and `sandbox-backend`. The institution realm currently demonstrates a synthetic human institutional user; its party reference does not grant organizational authority. No institution machine/service actor or business authorization is inferred. No production realm, callback, role, scope, tenant, or identifier is implied. See [the integration contract](integration-contract.md) before choosing production settings.

## Capacity and ownership

A run requires at least **12 GiB free disk**, a running Docker engine with Compose v2, and enough available memory for approximately 2 GiB of bounded service allocations plus engine overhead. Do not run on an already pressured host. The measured development host had about 11 GiB free on 2026-10-31; image pulls and runtime qualification were deferred. Registry manifests were fetched without image layers. No package install, image pull, container start, or cleanup is needed for offline checks.

Every generation creates a unique Compose project recorded in `.state/sandbox/ownership.json`. The lifecycle helper checks this marker and the exact generated Compose hash, and requires a local Unix Docker socket; remote contexts and TCP endpoints are refused. Never change the marker to adopt an existing service. `stop` affects only this project's services and preserves its database volume and generated secrets. Mailpit messages are ephemeral and disappear when its process stops. There is deliberately no delete, reset, prune, or global cleanup command. Obtain explicit approval and identify exact owned resources before any later deletion.

## Prepare

Run from the repository root:

```sh
python3 tooling/build_theme.py
python3 scripts/generate.py --mode sandbox
```

Generation creates protected `.state/sandbox`, fresh random bootstrap/database/client/user credentials, realm imports, and `compose.json`. It never overwrites an existing output, rotates a retained password, or resets a database. Reusing retained data means reusing the same state directory and Compose project. A new path creates a separate sandbox, not a migration.

On the host, ensure this name resolves to loopback before opening the browser:

```text
127.0.0.1 id.firefly.test
```

This requires an operator-managed hosts entry or local DNS. The same DNS name is a Docker network alias on port 8180, so backend containers attached to this project's `identity` network can fetch the canonical issuer. No service uses another container's `localhost` as an issuer. The source tree is never mounted as a built theme; the build creates `dist/themes/firefly-id`, and generation fails if it is absent.

When a safe capacity window is available, explicitly perform:

```sh
python3 scripts/sandbox.py preflight
python3 scripts/sandbox.py pull
python3 scripts/sandbox.py up
python3 scripts/sandbox.py status
```

`preflight`, `pull`, and `up` stop before Docker if the disk gate fails. `up` uses `--pull never`, waits at most 180 seconds for readiness, and cannot trigger an unexpected image download. Pulls have a ten-minute command deadline. A failure preserves all state; inspect the project's bounded logs and stop services if needed. No helper modifies host DNS or other projects.

## Addresses and credentials

| Surface | Address |
| --- | --- |
| Browser and canonical issuer base | `http://id.firefly.test:8180` |
| Customer discovery | `http://id.firefly.test:8180/realms/sandbox-customers/.well-known/openid-configuration` |
| Backend transport discovery on identity network | `http://keycloak:8180/realms/sandbox-customers/.well-known/openid-configuration` |
| Administrative console | `http://id.firefly.test:8180/admin/master/console/` |
| Mail viewer, host only | `http://127.0.0.1:8025` |
| Readiness, host only | `http://127.0.0.1:9000/health/ready` |

The internal discovery transport may return internal token/JWKS endpoints with dynamic backchannel enabled; the token `iss` remains the canonical browser URL. Validate that exact issuer string. Do not substitute a transport URL for the issuer. A backend requiring discovery through its issuer can use `id.firefly.test:8180` directly through the network alias. The `identity` network is internal: SMTP is unpublished and cannot relay externally. Keycloak, Mailpit UI, and management ports bind only to host loopback. Docker Desktop host publication and local DNS behavior still require actual runtime verification on the target machine.

Bootstrap username is `sandbox-bootstrap`; its random password is `.state/sandbox/secrets/admin-password`. Synthetic application usernames and their random passwords are in `.state/sandbox/credentials.json`. Never paste these into issue reports or commit the generated state. Synthetic addresses use `example.invalid`; they are intentionally non-deliverable. The users are preverified solely to exercise the local login and recovery experience. Registration is disabled; a user cannot self-assign a realm, tenant, party, or staff identifier.

Clients require authorization code with PKCE S256. The only browser callback is `http://localhost:3000/oidc/callback`, and its only post-logout return is `http://localhost:3000/signed-out`. The confidential backend example uses `http://localhost:8081/oidc/callback` and `http://localhost:8081/signed-out`. These endpoints are contracts for a test application; this repository does not start that application. Password grants, implicit flow, device grants, CIBA, and service accounts are disabled. No redirect contains a wildcard.

## Runtime acceptance still required

Offline tests inspect generated boundaries; they do not prove Keycloak imported them or enforced them. Before claiming qualification, record each of these against the pinned stack:

1. Check `/health/ready` and `/health/live`, discovery issuer, and advertised JWKS from both the host browser path and an attached backend container.
2. Execute code + PKCE S256 for public and confidential examples. Reject missing/incorrect PKCE, a changed callback, password grants, implicit grants, and a wrong client secret. Validate signature, issuer, audience, expiry, and realm isolation at the backend.
3. Log in, use account self-service, perform logout with the exact return URI, and prove the old session is invalid. Review English at narrow and desktop widths. Spanish and other localization remain unqualified until translated custom copy is reviewed.
4. Trigger reset-password and verify-email messages to Mailpit. Inspect both HTML and text, message links, and the expiry/reuse rejection of action links. Do not send real mail.
5. Attempt tenant/party/staff edits through account/profile and registration/broker paths; verify protected attributes and resulting access-token claims remain unchanged. An admin-controlled mapper alone is insufficient proof.
6. Prove failed-login throttling, separate user stores, database persistence across stop/start, and backup/restore into a distinct disposable database. Verify no default credential and no externally published database or SMTP port.
7. Review actual startup warnings, the imported user profile component, scope/audience mappings, theme assets, and available metrics. Capture redacted evidence without tokens, secrets, or synthetic passwords.

```sh
python3 scripts/sandbox.py stop
```

Stopping preserves the database. Realm `--import-realm` runs on first creation and skips an existing realm; editing a generated import is not an update strategy. Use reviewed administrative changes or a migration against retained data.
