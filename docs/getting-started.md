# Start safely

This walkthrough creates a **new synthetic evaluation environment**. It is not a production deployment or an instruction to modify a shared identity service. If you already have a generated state directory, use its recorded lifecycle; generating another directory creates a separate environment and does not repair or migrate the first one.

## Choose the installation you need

| Installation | What it provides | Prerequisites and boundary |
| --- | --- | --- |
| Theme distribution | Login, account, administration, email and welcome branding on pinned Keycloak | Build the canonical theme; ordinary Keycloak protocol and action-token behavior remains upstream |
| Synthetic sandbox | Three application populations, temporary bootstrap administration, dedicated PostgreSQL and local Mailpit | New generated ownership/state, local Docker/Compose and at least 12 GiB free disk |
| Optional native recovery candidate | Permanent-lock tracking, existing-factor unlock, customer PIN and separate customer credential replacement | Exact native/gateway JARs, reviewed database installation and qualified owning Core/Domain services; enabling a theme alone is insufficient |
| Regulated production deployment | Institution-approved identity topology and application integration | Requires the [deployment and acceptance plan](regulated-deployment.md); production generation deliberately refuses incomplete contracts |

Read [why Keycloak](why-keycloak.md) and the [solution inventory](solution-overview.md) before adding custom authenticators or adapting account ownership. The repository already has separate extension points; a new login theme or callback must not become a second authorization service.

## Check prerequisites

The lightweight source checks use Python 3 and Node.js with standard libraries. The sandbox additionally needs a running **local Unix-socket Docker engine**, Docker Compose v2, sufficient memory for its bounded services and at least **12 GiB of available disk**. Remote/TCP Docker contexts are refused. Do not bypass the ownership or capacity check to use an existing cluster.

Native provider builds use Java 21 and Maven. The separate platform-service qualification fixtures use Java 25. The documentation build uses Python 3.12 in hosted qualification; it does not require starting Keycloak. [Versions and provenance](reference/versions.md) records the exact images.

Run source checks from the repository root:

```sh
make check
python3 tooling/build_theme.py
```

`make check` runs the configured Python/Node suites and syntax checks. The theme builder assembles the approved source, artwork and locally served Manrope into `dist/firefly-id-theme.jar` and `dist/themes/firefly-id`; it does not start a service. Keep the original repository path and editable files. The build output is ignored and must not replace the source tree.

## Generate one new evaluation

Choose a new output path that does not exist. The following name is illustrative; if it is already present, select another name rather than deleting or overwriting it:

```sh
python3 scripts/generate.py --mode sandbox --output .state/evaluation-20261101
```

Expected result: a new protected directory with `ownership.json`, `compose.json`, realm imports and random credentials. There is no shared default password. Generation validates the policy catalogue and refuses an existing output, a symlink or an unselected production contract. It neither enrolls real customers nor modifies a running provider.

The [configuration reference](configuration-reference.md) explains the four population profiles, source-managed attributes, disabled grants, session values and opt-in machine-client exception. Inspect configuration through an approved local tool; never paste generated credentials, imports or ownership files into tickets or documentation.

## Start only the owned environment

Arrange local DNS or an operator-managed hosts entry for `id.firefly.test` to resolve to loopback. The script does not modify your hosts file. Use the same explicit state path for every lifecycle operation:

```sh
python3 scripts/sandbox.py preflight --state .state/evaluation-20261101
python3 scripts/sandbox.py pull --state .state/evaluation-20261101
python3 scripts/sandbox.py up --state .state/evaluation-20261101
python3 scripts/sandbox.py status --state .state/evaluation-20261101
```

`preflight` validates capacity, the built theme, the ownership marker, immutable Compose hash, local engine and Compose syntax. `pull` explicitly retrieves the pinned images. `up` uses `--pull never` and waits for bounded readiness; it cannot silently fetch a different image. If a step fails, preserve its state and use [troubleshooting](troubleshooting.md). Do not alter an ownership marker to adopt somebody else's database or service.

The sandbox is deliberately local HTTP with synthetic mail. Its addresses are:

| Purpose | Address |
| --- | --- |
| Identity base | `http://id.firefly.test:8180` |
| Customer discovery | `http://id.firefly.test:8180/realms/sandbox-customers/.well-known/openid-configuration` |
| Temporary administrative console | `http://id.firefly.test:8180/admin/master/console/` |
| Synthetic mail viewer | `http://127.0.0.1:8025` |
| Host-loopback readiness | `http://127.0.0.1:9000/health/ready` |

The hostname in the verified token issuer is canonical. A container transport name is not a substitute issuer. [Sandbox networking](sandbox.md) explains browser, backend and dynamic backchannel behavior, dedicated database networking and the limits of loopback publication.

## Exercise the intended journey

The examples expect applications at the exact callback and signed-out addresses in the generated clients. This repository does not start those application frontends. Use the supplied hosted runtime fixtures for reproducible protocol qualification, or implement a client against the [application contract](integration-contract.md).

For an evaluation, confirm discovery/JWKS, actual code plus PKCE, signature/issuer/audience validation, account access, logout and refresh refusal. Test customer and employee profiles independently. Workforce users must complete native TOTP enrollment before the application receives a code. Browser language matching and the optional footer selector support English/Spanish; check both light and dark presentation at desktop and narrow widths.

Use only generated synthetic identities. Email verification and password-reset messages go to the local sink. A permanently blocked account must stay disabled after an ordinary reset; follow [recovery choices](access-recovery.md) instead of manually enabling it. Reusing an action, authenticator enrollment or successful recovery does not qualify another fresh operation.

## Stop and retain

```sh
python3 scripts/sandbox.py stop --state .state/evaluation-20261101
```

Stopping preserves the database volume, generated state and credentials. Mailpit messages are ephemeral. There is deliberately no reset/delete/prune helper. A later `up` must use the same state and project; changing a generated realm import does not update an existing realm.

Before moving beyond evaluation, read [regulated deployment](regulated-deployment.md), [retained data](retained-data.md), [EU/US applicability](controls-matrix.md) and [qualification evidence](evidence.md). None of the steps above approves real identity proofing, a bank's recovery procedure or a production migration.
