# Check production settings

Use the configuration checker before applying server and realm changes. It reads local files, checks a supported set of security settings and prints a compact JSON result. It does not connect to Keycloak or change accounts.

## Prepare the inputs

Supply a resolved, nonsecret `keycloak.conf` and complete realm/client exports for `customers`, `workforce` and `administrators`. The administrator export must identify `master`; the other realm names must be distinct. An optional `institutions` export is also supported.

Obtain exports through the authorized administration process and keep them outside the public checkout. Realm-only responses that omit clients are insufficient. Exports can contain confidential fields, so protect them like other administrative configuration.

The server file accepts literal `key=value` entries. Resolve `${…}` placeholders with your reviewed configuration generator; the unrendered production reference is expected to fail. Duplicate keys, backslash continuations, colon separators and expressions are refused. Keep passwords in the secret manager rather than the review file. Each input is limited to 2 MiB.

```sh
python3 scripts/check_production.py \
  --server-config /secure-review/keycloak.conf \
  --realm customers=/secure-review/customers.json \
  --realm workforce=/secure-review/workforce.json \
  --realm administrators=/secure-review/master.json
```

Run the checker in a separate clean review process. It refuses Keycloak/Quarkus/Java override variables in its own environment, rather than guessing their effect. Do not clear variables from a running service and treat that as a review of the service.

## Read the result

Exit code `0` means the supplied settings passed the supported checks; exit code `1` means findings need attention. The result includes fixed finding IDs without echoing paths, hostnames, usernames or secrets. `candidate_checks_passed` describes only these file checks. `production_approved` is always `false`, and `decisions_required` lists the operational areas to review with the deployment team.

| Finding | What to inspect |
| --- | --- |
| `INPUT_INVALID` | Input format/size, duplicate JSON keys, missing fields or duplicate population arguments |
| `EXTERNAL_CONFIG_SOURCE` | Override variables in the checker process |
| `SERVER_UNREVIEWED_OPTION` | A server property outside the supported subset, including raw/SPI trust overrides or alternate public-health placement |
| `SERVER_TRANSPORT` | HTTP listeners, management scheme, hostname strictness, DB TLS mode, outgoing verifier and TLS protocol selection |
| `SERVER_HOSTNAME` | Public/admin HTTPS origins, distinct hostnames and absence of credentials, wildcards, queries or fragments |
| `SERVER_CERTIFICATE_INPUT` | Absolute certificate/key mount paths |
| `SERVER_DATABASE` | Plain PostgreSQL URL, username, mounted CA and absence of driver/TLS overrides |
| `SERVER_STATIC_SECRET_OR_BOOTSTRAP` | Password or bootstrap properties left in normal runtime configuration |
| `SERVER_PROXY_TRUST` | Exact forwarded-header mode and valid, bounded proxy addresses; ranges must not collectively trust every IPv4 or IPv6 address |
| `REALM_POPULATIONS` | Required realm inventory, distinct names and administrative `master` assignment |
| `REALM_POLICY` | Enabled realm, SSL, registration/profile restrictions, verification, refresh rotation and permanent-block settings |
| `REALM_PASSWORD_POLICY` | Missing or duplicated policy terms; identifiers are normalized with Keycloak's trimming rules, including control characters |
| `REALM_SESSION_POLICY` | Missing, nonpositive or excessive idle/access-token lifetimes or a declared administrative maximum session lifetime |
| `REALM_CLIENT` | Incomplete/non-OIDC application clients, unsafe grants, service-account combinations, S256 and exact HTTPS return/origin values |

Fix the specific setting and rerun the same inputs. An unsupported option needs a reviewed extension to the checker; it should not be silently deleted from the review while remaining active in the deployment.

## Database and management setup

The [production reference](../deploy/keycloak.production.conf.example) uses `db-tls-mode=verify-server` with `/run/secrets/database-ca.pem`. In PostgreSQL this selects certificate and hostname verification. The checker accepts a plain single-host PostgreSQL JDBC URL, with no query parameters, user information, custom driver or separate `db-url-properties`.

The pinned [database mapper](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/configuration/mappers/DatabasePropertyMappers.java) preserves conflicting full-URL properties and checks TLS-property names as substrings. Consequently the checker also refuses `sslmode`, `sslrootcert`, `sslfactory` and `sslhostnameverifier` in host/database names. Use an unambiguous plain URL and the first-class TLS options; custom/multi-host arrangements need separate review.

Management uses `http-management-scheme=inherited`, not a literal `https` value. It inherits the main server's HTTPS setup. Use a private HTTPS probe with the correct certificate/name and isolate port 9000. [Management options](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/config-api/src/main/java/org/keycloak/config/ManagementOptions.java).

## Application-client requirements

Enabled application clients must declare `protocol=openid-connect` and complete boolean grant fields. Interactive clients need code/S256, exact HTTPS callbacks and no service-account authority. Noninteractive machine service accounts must be confidential. The checker rejects password, implicit, device, CIBA, token-exchange and JWT-authorization grants in this profile.

Post-logout returns must be exact HTTPS values. The upstream `+` shorthand is allowed only as the entire value and reuses the checked redirect allowlist. Built-in Keycloak clients and explicitly disabled clients are handled separately; review their real console/admin behavior. Scopes, audiences, trusted claim mappers and business permissions still require the application-specific setup in [integration](integration-contract.md).

## Finish the environment review

Keycloak applies CLI, environment, configuration file and keystore in that priority order. Compare the reviewed file with the final deployment command, environment, selected configuration path and keystore. Inspect raw Quarkus/JVM options too. The checker cannot discover undeclared sources or prevent a later override. [Configuration precedence](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/configuration.adoc).

Then complete the operational tasks:

| Area | Required setup |
| --- | --- |
| Authentication | Configure actual customer/workforce factors, privileged phishing-resistant MFA and recovery; a catalogue flag does not enroll users |
| Provisioning | Connect authoritative party/staff/tenant linkage and lifecycle changes |
| Networks/storage | Verify real TLS handshakes, public-route denial, proxy ownership, database privileges and secret mounts |
| Administration | Verify permanent access and removal of temporary bootstrap accounts |
| Recovery/support | Configure the selected proofing adapter and existing-party resolver; provide separate workforce/admin and BPO procedures |
| Communications | Configure real SMTP, advance-block warnings where applicable, monitoring and terminal escalation |
| Resilience | Rehearse retained restore, migrations, rollback, capacity and the chosen HA topology |
| Applications | Verify current authorization, revocation/cache behavior and independent sessions at each receiver |
| Governance | Assign legal applicability, privacy/retention, audit custody, supplier and incident responsibilities |

Use [deployment setup](regulated-deployment.md), [retained data](retained-data.md) and [EU/US controls](controls-matrix.md) to carry out these tasks.
