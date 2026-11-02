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
| `REALM_AUDIT_EVENTS` | Disabled/missing login or administration event capture, missing/nonpositive retention, or a custom event filter |
| `REALM_CLIENT` | Missing/duplicate client identifiers, incomplete/non-OIDC enabled clients, unsafe grants, nonempty or malformed flow-binding overrides, service-account combinations, S256 and exact HTTPS application return/origin values |
| `REALM_CLIENT_SESSION_POLICY` | A client access-token override that is malformed, nonpositive or longer than the checked realm's lifetime |

Fix the specific setting and rerun the same inputs. An unsupported option needs a reviewed extension to the checker; it should not be silently deleted from the review while remaining active in the deployment.

## Database and management setup

The [production reference](../deploy/keycloak.production.conf.example) uses `db-tls-mode=verify-server` with `/run/secrets/database-ca.pem`. In PostgreSQL this selects certificate and hostname verification. The checker accepts a plain single-host PostgreSQL JDBC URL, with no query parameters, user information, custom driver or separate `db-url-properties`.

The pinned [database mapper](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/configuration/mappers/DatabasePropertyMappers.java) preserves conflicting full-URL properties and checks TLS-property names as substrings. Consequently the checker also refuses `sslmode`, `sslrootcert`, `sslfactory` and `sslhostnameverifier` in host/database names. Use an unambiguous plain URL and the first-class TLS options; custom/multi-host arrangements need separate review.

Management uses `http-management-scheme=inherited`, not a literal `https` value. It inherits the main server's HTTPS setup. Use a private HTTPS probe with the correct certificate/name and isolate port 9000. [Management options](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/config-api/src/main/java/org/keycloak/config/ManagementOptions.java).

## Application-client requirements

Enabled application clients must declare `protocol=openid-connect` and complete boolean grant fields. Interactive clients need code/S256, exact HTTPS callbacks and no service-account authority. Noninteractive machine service accounts must be confidential. The checker rejects password, implicit, device, CIBA, token-exchange and JWT-authorization grants in this profile.

Post-logout returns must be exact HTTPS values. The upstream `+` shorthand is allowed only as the entire value and reuses the checked redirect allowlist. Enabled built-in Keycloak clients receive the same protocol, type, grant and token-lifetime checks. Their native return routes and console behavior require separate exact-version review. Disable the built-in `admin-cli` password grant in this production profile; use a purpose-bound confidential workload or the approved interactive administrative path. Explicitly disabled clients are not an active grant path, but their identifiers must still be unique.

An enabled client can select a different authentication flow through `authenticationFlowBindingOverrides`. The [Keycloak 26.8.1 resolver](https://github.com/keycloak/keycloak/blob/26.8.1/server-spi-private/src/main/java/org/keycloak/models/utils/AuthenticationFlowResolver.java) checks a requested browser flow before a client binding override and then the realm browser flow. Checking only the realm binding can therefore miss a client's alternate path. This offline profile conservatively accepts only an absent override field or an empty JSON object, including for all six built-in client names. Nonempty objects, unknown binding keys and malformed values such as `null`, lists, strings, booleans or numbers produce `REALM_CLIENT`. Explicitly disabled clients retain their exemption; reenabling them requires another audit. Even an apparently equivalent override needs separate review and is refused here.

This guard checks the binding map only. Review client policies and requested flows, federation, the actual realm flow and real factor enforcement separately; an empty map does not prove that a fresh sign-in requires the selected factors. Do not remove an override from a review export while leaving it active on the server.

The `access.token.lifespan` client attribute overrides the realm setting. An absent or Java-trimmed empty value inherits the realm lifetime; a positive decimal value may only shorten it. The checker refuses `-1`, which would select the SSO session maximum instead. This includes account and administrative consoles. See the pinned [token expiration implementation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java). Client session/offline policy, scopes, audiences, trusted claim mappers and business permissions still require the application-specific setup in [integration](integration-contract.md).

## Capture security events deliberately

Enable login events and administrative events, keep administrative representation details disabled, and supply a positive `eventsExpiration` in seconds. Leave `enabledEventTypes` absent or empty to retain Keycloak's default saved event types; a custom filter such as only `LOGIN` would omit authentication failures and is refused by this profile. A different event contract needs a reviewed checker extension. The checker requires an explicit finite retention setting; it does not select the institution's retention period. Seven days is the sandbox value, not a banking retention recommendation. Export events to the approved restricted audit destination and verify receipt, failure alerts, access and deletion behavior. Local event storage alone does not provide immutable audit custody or prove downstream delivery.

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

Use the [institution decision guide](production-decisions.md) to assign each item, choose limits and define acceptance. Follow [deployment setup](regulated-deployment.md), [retained data](retained-data.md) and [EU/US controls](controls-matrix.md) to carry out the selected tasks.
