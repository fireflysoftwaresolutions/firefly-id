# Deployment and operations

Operate Firefly Identity as a dedicated identity service: pinned server image, protected database, private administration and monitored communications. Use [local sandbox](sandbox.md) for evaluation and [deployment setup](regulated-deployment.md) for the institution's topology.

## Build the distribution

| Component | Pinned release | Purpose |
| --- | --- | --- |
| Keycloak | 26.8.1 | Identity server |
| PostgreSQL | 17.11, Debian bookworm image | Dedicated identity storage |
| Mailpit | 1.31.3 | Local sandbox SMTP sink |

Exact OCI references are in [images.lock.json](../deploy/images.lock.json). Keep digest pins, scan the built image and review upstream advisories before deployment. Native providers target Keycloak 26.8.1 and Java 21; the separate Core/Domain services use Java 25.

Build and check the theme from the repository root:

```sh
make check
python3 tooling/build_theme.py
docker build --file deploy/Containerfile --tag firefly-id:local .
```

Use Python 3.11+, Node.js 22 and a container engine on the build host. The image build retrieves the pinned upstream image and runs Keycloak's optimized build inside the container; the ordinary theme build does not require a host JDK. Replace the local tag with your deployment's unique image tag and retain the resulting digest.

[Containerfile](../deploy/Containerfile) consumes `dist/firefly-id-theme.jar` and the password blocklist, enables PostgreSQL/health/metrics at build time, and starts with `start --optimized`. [Containerfile.native](../deploy/Containerfile.native) also consumes the packaged native providers. Follow [native installation](native-recovery.md) before using it: the JARs add database mappings, and the selected recovery journey needs its own service configuration.

In the deployment workload, mount the rendered server configuration read-only at `/opt/keycloak/conf/keycloak.conf`, mount the certificate/key/database CA at the paths it declares, and supply the database secret through the supported secret mechanism below. Keep the image's default startup command, including its native provider selection when applicable. Configure the dedicated database and private/public ingress before starting the workload; building the image alone does not start or configure those services.

Prepare production realm/client registrations through the Admin Console or authorized Admin API and render the server configuration through your deployment process; do not copy synthetic users or generated sandbox state.

## Configure storage and secrets

Use a dedicated PostgreSQL database and a nonsuperuser runtime login, separate from application databases. Keycloak needs schema migration rights in its own schema. Restrict database networking, encrypt backups and review actual role privileges. The sandbox initializer creates a dedicated `firefly_id` login and is intended only for a new sandbox database.

The [production reference](../deploy/keycloak.production.conf.example) uses `db-tls-mode=verify-server` and `/run/secrets/database-ca.pem`. Supply a plain PostgreSQL JDBC URL without competing driver/TLS parameters. Check the real database certificate chain and hostname; use [the configuration checker](production-readiness.md) to catch unsupported input combinations before rollout.

Inject `KCRAW_DB_PASSWORD` or a supported PKCS12 Keycloak configuration keystore through the secret manager. There is no generic `KC_DB_PASSWORD_FILE` loader. Restrict ownership of TLS private keys, workload credentials and encryption/PIN keys. Keep all secrets out of image layers, build arguments, tickets and diagnostic output. [Keycloak configuration mechanisms](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/configuration.adoc).

Changing an initialization secret does not rotate the password stored in PostgreSQL. Coordinate a database credential change with the runtime secret and restart/reconnect behavior. For clients, update the registered client credential and its consumers together. Test old-credential refusal and new-credential access.

## Expose only the intended interfaces

Use the same canonical HTTPS issuer from browser and backend networks where possible. The production reference disables dynamic backchannel hostnames. A private transport address must not become another accepted token issuer.

Re-encrypt traffic from ingress to Keycloak. The ingress must overwrite forwarded headers, and Keycloak must trust only its exact proxy addresses. Restrict `/admin/` and administrative-realm routes to private administration; `hostname-admin` alone does not enforce that restriction. Firewall direct service access. See [reverse proxy setup](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/reverseproxy.adoc).

Management port 9000 inherits HTTPS and belongs only on the private monitoring network. Use an HTTPS-capable probe that verifies the certificate and hostname; the slim server image has no curl.

| Probe | Use |
| --- | --- |
| `/health/started` | Allow startup time before applying steady-state checks |
| `/health/ready` | Admit traffic only when dependencies are ready |
| `/health/live` | Detect a process that cannot continue |
| `/metrics` | Scrape from the restricted monitoring system |

A failed readiness check should remove traffic rather than cause an immediate restart loop. Size CPU, memory, database pools, connection budgets and cluster routing from the expected workload. See [health guidance](https://www.keycloak.org/observability/health) and [observability](observability-incidents.md).

## Rotate keys and preserve access

For routine signing-key rotation, introduce a new signing key through the supported realm key provider, keep prior verification keys available for the required overlap, and test JWKS refresh in every consumer. Emergency key compromise needs a separate revocation and session-containment procedure; do not rely on the routine overlap.

PIN peppers and recovery encryption keys have different rotation rules. Retain versioned material needed by stored records, respect old-PIN verification deadlines and never replace bytes under an existing version name. Follow [support PIN](support-pin.md) and [credential-loss keys](credential-loss-recovery.md).

Use bootstrap administration only to establish permanent named administrators and their factors. Remove temporary accounts and bootstrap secret injection after verifying permanent access and emergency recovery.

## Back up and restore

Back up the database using the platform's consistent logical or physical/PITR process, together with protected keys, secrets and deployment configuration. A realm export does not include a complete database/session backup.

In a sandbox, `pg_dump -Fc` can run inside the exact owned PostgreSQL service and write into a protected backup directory. Check its exit status and inspect the dump using `pg_restore --list`. Select the service/project from `ownership.json`; do not use a broad global container selector.

Restore to a new isolated database with compatible server images and keys, block real external mail/provider traffic, and verify sign-in, factors, links, holds, sessions and pending recovery work. Measure recovery time and data loss against your objectives. [Retained data](retained-data.md) gives the full sequence.

## Upgrade and roll back

1. Review supported server/database upgrade paths, release notes and security advisories.
2. Build an immutable image against the selected version; compare inherited templates and native APIs, scan it and retain the previous image/configuration.
3. Restore the current database into an isolated rehearsal environment and run the migration there first.
4. Exercise sign-in, factor enrollment/challenge, profile protection, client integration, recovery, localization and application authorization.
5. Schedule rollout with named operators, database checkpoints, traffic-switch criteria and an explicit rollback path.

After a schema change, restarting the old image against the migrated database is unsafe. Restore the pre-change database into a compatible target with matching keys/configuration, verify it, then switch traffic. Preserve the failed-upgrade state for diagnosis.
