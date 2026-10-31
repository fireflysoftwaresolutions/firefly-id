# Deployment and operations

The repository supplies a pinned Keycloak theme distribution, an isolated synthetic Compose sandbox, and production reference configuration. Production realm/client/provisioning generation intentionally fails closed until the actual platform contract is approved. A successful source test, theme package build, or registry metadata check does not qualify a running identity deployment.

## Supported baseline and provenance

| Component | Pinned release | Purpose |
| --- | --- | --- |
| Keycloak | 26.8.1 | Public upstream identity distribution |
| PostgreSQL | 17.11, Debian bookworm image | Dedicated identity database |
| Mailpit | 1.31.3 | Synthetic local SMTP sink only |

Exact OCI manifest digests and registry endpoints are in [deploy/images.lock.json](../deploy/images.lock.json). On 2026-10-31 each registry manifest response was fetched and its SHA-256 compared with `Docker-Content-Digest`; no image layers were downloaded. Digest pinning provides byte identity, not a signature or vulnerability assessment. Verify upstream advisories and rescan the built image before each deployment. Use the same pinned version for theme compatibility review and runtime acceptance; changing a tag alone does not constitute an upgrade.

Keycloak's [download page](https://www.keycloak.org/downloads) and [26.8.1 database guide](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/db.adoc) define the baseline; its [database support template](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/templates/databases.adoc) includes PostgreSQL 17. PostgreSQL 17 remains supported through November 2029 under the [official versioning policy](https://www.postgresql.org/support/versioning/). Mailpit publishes exact release tags in its [official Docker instructions](https://mailpit.axllent.org/docs/install/docker/) and [release history](https://github.com/axllent/mailpit/releases/tag/v1.31.3).

## Local and production artifacts

Follow [sandbox.md](sandbox.md) for the synthetic local lifecycle. Offline validation uses Python's standard library and does not require Docker or package installation:

```sh
python3 -m unittest discover -s tests -v
python3 tooling/build_theme.py
bash -n deploy/keycloak-entrypoint.sh deploy/postgres/init.sh
```

[deploy/Containerfile](../deploy/Containerfile) builds an optimized production image from the pinned upstream digest and the built theme JAR. Its build requires the approved capacity window, access to the pinned image, and the previously built `dist/firefly-id-theme.jar`. It does not copy realm exports, credentials, or local state. Build-time options are PostgreSQL, health, and metrics; runtime starts with `start --optimized`. The sandbox uses upstream `start --import-realm` without `--optimized` so the same build-time options can be applied on local startup; it does not use `start-dev` or the development database.

[deploy/keycloak.production.conf.example](../deploy/keycloak.production.conf.example) is an unrendered reference for TLS re-encryption. It requires the operator to choose the public and private administration URLs, exact proxy CIDRs, database endpoint/user, mounted TLS files, and runtime secrets. It is not a deployable production environment and does not provision production clients. Run the production image with the reference mounted as its Keycloak configuration only after all required values and policy are reviewed.

Use one dedicated PostgreSQL database owned by the Keycloak login, separate from all application databases. The sandbox initializer creates `firefly_id` with no superuser, role/database creation, or replication privilege; it revokes public database access and public schema creation. Keycloak retains DDL rights within its own database/schema because schema migration needs them. The database bootstrap superuser is not the runtime application login and its secret is not accessible to the Keycloak container. Production can use a managed PostgreSQL service with the same isolation, backups, encryption, restricted network access, and a JDBC URL requiring certificate/hostname verification (`sslmode=verify-full` with the appropriate trusted CA). Never point sandbox initialization at a shared or existing production database.

Inject the database password through `KCRAW_DB_PASSWORD` or a supported PKCS12 Keycloak configuration keystore. Inject the keystore's password through the secret manager if that path is used. Do not invent generic Keycloak `*_FILE` variables. See [pinned configuration guidance](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/configuration.adoc). Run temporary bootstrap administration only during initial setup, remove it after permanent least-privileged MFA administration is established, and remove bootstrap credentials from subsequent deployments. Runtime secret rotation requires explicit database/client/admin operations; editing a mounted secret alone does not update a retained database identity.

## Network and health

Production browser and backend consumers must agree on the exact public issuer URL per approved realm. Prefer the same HTTPS issuer reachable from both networks through appropriate DNS/routing. If a private backchannel transport is needed, explicitly configure and test hostname/backchannel behavior; do not change token issuer validation to accept an internal service URL. The sample keeps dynamic backchannel disabled in production. See [the pinned hostname guide](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/hostname.adoc).

Terminate browser TLS at a controlled ingress and re-encrypt traffic to Keycloak. Restrict service access to that ingress and private operations networks. Overwrite incoming `X-Forwarded-*` headers and configure exact trusted proxy CIDRs. The sample's HTTP listener is disabled; certificates and private keys are runtime mounts. A separate administration hostname does not restrict the Admin REST API by itself: enforce private-only `/admin/` and administrative-realm routes at ingress. Never expose a database, SMTP sink, health, or metrics listener to the public internet. These requirements follow [Keycloak 26.8.1 reverse-proxy guidance](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/reverseproxy.adoc).

Enable health and metrics in the optimized image. Probe the private management port 9000: `/health/started` for startup, `/health/ready` for traffic admission, and `/health/live` for process liveness. Readiness may include the database pool when metrics are enabled; a failed readiness check must not itself cause a restart loop. Scrape `/metrics` only from authenticated/restricted monitoring infrastructure. The reference uses HTTP on a private management network; use the platform's mTLS/network controls where needed. Keycloak's slim image has no curl; use an external probe or the documented bash TCP readiness check. See [official health guidance](https://www.keycloak.org/observability/health).

Bound CPU/memory and logs according to load tests. The sandbox bounds service memory and log rotation, stores at most 100 messages with 24-hour mail retention, and keeps the mail sink's default in-memory storage. Production needs database pool sizing, connection budget, cache/cluster topology, load-balanced routing, and HA/failure testing based on the actual workload; the single-node sandbox proves none of those.

## Backup, restore, and upgrade

Back up the database with the platform's supported PostgreSQL physical/PITR process or a consistent logical dump, along with encrypted secrets, signing material, deployment manifests, theme artifact checksum, and exact image digests. Protect backups as credential-bearing personal data. A realm export is a configuration aid, not a complete database/session backup. Do not print passwords on command lines or place backup files in the public checkout.

For a logical sandbox rehearsal, an operator can run `pg_dump -Fc` inside only the owned PostgreSQL service with its local application login and redirect the resulting bytes into a protected backup directory. Verify the exit status and dump with `pg_restore --list`. Identify the project from `ownership.json`; never substitute an unreviewed global container selector. The lifecycle helper deliberately does not offer a backup deletion or database reset command.

Restore into a new, explicitly disposable dedicated PostgreSQL instance/database, never over retained or production data. Apply the approved database ownership and privileges first, restore with the supported PostgreSQL tools, then start the matching old Keycloak version against that restored copy. Verify discovery/JWKS and signing continuity, users/credentials, clients, protected attributes, sessions, roles, recovery emails, and a real code/PKCE application login. Record restore time and data loss window. A backup is unqualified until this restore rehearsal succeeds.

Before an upgrade:

1. Review Keycloak and PostgreSQL release/migration notes and security advisories. Choose supported exact versions and refresh registry digests by metadata inspection. Do not change major PostgreSQL versions by swapping an image over the same data directory.
2. Build the theme and optimized image against the new Keycloak version; review inherited template/API changes. Scan the result and keep the previous package and image digests.
3. Back up and restore the current database into an isolated rehearsal environment. Do not replay real external mail or client traffic.
4. Run the target Keycloak migration only on the rehearsal database, then execute all protocol, profile-forgery, population-isolation, visual, recovery, and restore acceptance checks in [sandbox.md](sandbox.md).
5. Schedule a controlled maintenance/rollout plan appropriate to the approved cluster topology. Record pre-change backups and checkpoints, deployment identity, new image/theme hashes, and acceptance evidence.

If an upgrade changes the schema, restarting an older image against the migrated database is not a rollback plan. Stop writers and restore the pre-upgrade backup into a separate reviewed target with the matching previous image, keys, and configuration, then verify it before switching traffic. Preserve failed-upgrade data/evidence. Never run automatic broad cleanup, migrations against unknown endpoints, or destructive restore flags without explicit approval.

## Current acceptance boundary

The source generator, policy-output tests, shell syntax, and theme build are lightweight checks. Actual container import/startup, PostgreSQL privilege enforcement, host/container issuer reachability, code/PKCE, mail recovery, logout, forged-attribute rejection, visual review, persistence, backup restore, production ingress/TLS, and actual OpenPlatform consumer acceptance require separate recorded runtime evidence. Do not label them passed because source CI is green.
