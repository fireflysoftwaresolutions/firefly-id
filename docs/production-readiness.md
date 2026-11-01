# Production decisions and candidate audit

Production readiness has two different inputs: controls the repository can supply and decisions/evidence that belong to the operating institution. This page records both. The independent audit does not require a KYC vendor, start a service, contact an endpoint, alter a realm or enable recovery.

The [server reference](../deploy/keycloak.production.conf.example) now selects verifying database TLS, inherited HTTPS management, explicit TLS 1.2/1.3, normal outgoing hostname verification and no legacy public observability interface. These are supported Keycloak 26.8.1 settings. The [candidate auditor](../scripts/check_production.py) rejects common unsafe configuration and realm/client combinations before they reach an environment. Neither is an approval to deploy a bank.

## Controls implemented independently of KYC

| Control | Implementation | Verification boundary |
| --- | --- | --- |
| Database encryption and identity | `db-tls-mode=verify-server`, `/run/secrets/database-ca.pem` | PostgreSQL maps this to certificate and hostname verification; actual server certificate, CA custody and runtime role still need target evidence |
| Protected management transport | `http-management-scheme=inherited` and disabled main HTTP | Management inherits HTTPS/certificates; network policy must additionally isolate port 9000 |
| Modern protocol and peer defaults | Explicit TLS 1.2/1.3 and `tls-hostname-verifier=DEFAULT` | Actual supported protocols/handshakes require runtime verification |
| No public legacy metrics/health | `legacy-observability-interface=false` | Ingress/firewall denial remains an actual-environment check |
| Unsafe candidate refusal | Dependency-free offline server, population and application-client checks | Only the supplied literal configuration and snapshots are inspected |
| Safe diagnostics | Fixed control IDs, fixed decision IDs, pass/fail only | No file paths, endpoint values, usernames, supplied secrets or exception bodies are emitted |
| Repository documentation publication | Exact-source MkDocs build, actual browser qualification and GitHub Pages deployment | Public documentation deployment is separate from CIAM activation |

The pinned upstream [database mapper](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/configuration/mappers/DatabasePropertyMappers.java) preserves TLS properties already specified in a full JDBC URL. Therefore the auditor's bounded database contract permits **no JDBC query parameters**, user information, custom driver or separate `db-url-properties`. Use a plain dedicated PostgreSQL URL and the first-class TLS options. The pinned mapper also checks for TLS-property substrings anywhere in the full URL, so the audit refuses `sslmode`, `sslrootcert`, `sslfactory` and `sslhostnameverifier` in host/database names as well; otherwise a name such as `identity_sslmode` can suppress upstream injection. Merely adding `db-tls-mode` beside `?sslmode=disable` is unsafe. Multi-host/custom-driver/extra-property arrangements need a separately reviewed extension to this audit; they are not silently accepted.

Management accepts `inherited` or `http`, not a literal `https` scheme value. See the pinned [management options](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/config-api/src/main/java/org/keycloak/config/ManagementOptions.java). Inherited HTTPS requires the main server's valid TLS setup and an HTTPS-capable monitor with the correct trust/name. A plaintext bash TCP probe is not an HTTPS health check.

## Prepare the supplied inputs

Run this check in a protected review/CI workspace, separate from the Keycloak process. Supply one concrete `keycloak.conf` and complete exported realm/client representations for `customers`, `workforce` and `administrators`. The administrator representation must identify `master`; other populations must have distinct non-master realm names. An optional `institutions` representation is also accepted and checked. Assign populations from the approved inventory; the tool cannot establish that an operator labeled an export honestly.

The configuration parser intentionally accepts a small literal `key=value` subset. Duplicate keys, expressions, backslash escaping/continuations, colon separators and unresolved `${…}` refuse. The unrendered reference is expected to fail. Do not use a shell `eval` or broad environment dump to render it. Have the deployment's reviewed configuration generator emit the literal nonsecret settings used for review. Passwords remain in the secret manager, outside that file.

Realm snapshots contain operational identity configuration and may contain confidential fields. Obtain them through the institution's authorized administration/export procedure and keep them outside the public checkout. Use complete client representations, not a realm-only `kcadm get realms/…` response that omits clients. This is a configuration review input, not a backup/restore artifact. Never upload snapshots, raw admin responses, secrets or runtime environment dumps as documentation/CI evidence.

For an already approved local review directory:

```sh
python3 scripts/check_production.py \
  --server-config /secure-review/keycloak.conf \
  --realm customers=/secure-review/customers.json \
  --realm workforce=/secure-review/workforce.json \
  --realm administrators=/secure-review/master.json
```

Each input is bounded to 2 MiB. Duplicate JSON keys, malformed shapes and duplicate population arguments refuse. The tool reads files and prints one bounded JSON report; it performs no network calls, process launch, account operation or state mutation. It exits 1 on findings and 0 when the supported candidate checks pass.

`candidate_checks_passed=true` means only those checks passed. `production_approved` is always `false`; there is no bypass/approve flag. The report retains `decisions_required` even for a technically valid candidate. A safe summary may be retained under institution change-control rules; source snapshots must remain protected separately.

## What the auditor checks

| Finding ID | Refusal conditions |
| --- | --- |
| `INPUT_INVALID` | Ambiguous/malformed/unresolved/oversized input, duplicate keys/populations, unreadable files or invalid JSON structures |
| `EXTERNAL_CONFIG_SOURCE` | The audit process carries `KC_`, `KCRAW_`, `QUARKUS_`, legacy administrator or supported Java override environment variables |
| `SERVER_UNREVIEWED_OPTION` | Any server property outside the explicit supported audit subset, including raw/SPI trust overrides and alternate public-health placement |
| `SERVER_TRANSPORT` | Main HTTP, forced HTTP management, nonstrict/dynamic hostname behavior, missing verifying DB mode, legacy observability, unsafe outgoing verifier or unsupported TLS protocol set |
| `SERVER_HOSTNAME` | Missing/insecure/ambiguous public/admin HTTPS origins, credentials/query/fragment/wildcard values, loopback/unspecified targets or shared public/admin hostname |
| `SERVER_CERTIFICATE_INPUT` | Missing absolute mounted certificate/key paths |
| `SERVER_DATABASE` | Unsafe/unsupported full JDBC URL, URL parameters/user information, custom driver/properties, missing absolute CA path, missing username or obvious superuser name |
| `SERVER_STATIC_SECRET_OR_BOOTSTRAP` | Password properties or any bootstrap administrator properties remain in the supplied normal-runtime configuration |
| `SERVER_PROXY_TRUST` | Missing/unsupported forwarded-header mode, empty/malformed proxy addresses or universal/unspecified/multicast ranges |
| `REALM_POPULATIONS` | Missing required declared populations, unknown population, master misuse, empty or colliding realm names |
| `REALM_POLICY` | Disabled realm, non-`all` SSL, public registration, username editing, duplicate emails, missing email verification, refresh reuse, detailed admin representations or weaker permanent third-failure settings, including a nonzero temporary-lockout budget |
| `REALM_PASSWORD_POLICY` | Required catalogue policy terms missing |
| `REALM_SESSION_POLICY` | Missing/invalid/nonpositive or longer-than-selected idle/access-token settings |
| `REALM_CLIENT` | Missing/incomplete client list, unsupported non-OIDC applications, unsafe grants (including JWT authorization), interactive machine authority, missing S256, wildcard/HTTP/ambiguous application callbacks, logout returns or origins |

The client check distinguishes interactive clients from noninteractive machine clients: it does not globally ban legitimate service accounts. Application clients must explicitly declare `protocol=openid-connect` and complete boolean grant fields. Standard-flow clients require disabled service accounts and exact HTTPS callbacks with S256. Post-logout returns must be exact HTTPS values; the upstream `+` shorthand is allowed only as the entire value and reuses the already checked redirect allowlist. Built-in Keycloak console/account/broker/administration clients and explicitly disabled clients are excluded from application-client checks; qualify them through the separate actual distribution/admin flows. The audit does not establish a machine client's scopes, protocol-mapper authority, audience correctness, trusted profile attributes, service delegation or business entitlement.

## Configuration precedence and limits

Keycloak's supported configuration precedence is CLI, environment, configuration file, then keystore. A static file cannot prove the effective running configuration. See the [pinned configuration guide](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/configuration.adoc).

The server-property allowlist refuses unreviewed SPI/driver/raw settings, including options that disable certificate trust or move health onto the public interface. The CLI refuses known external override variables in its own process rather than pretending to merge them. This is an input-review tool, not a production launcher. Run it in an explicitly clean review job; do not strip variables from a running service and then claim that service was inspected. Review the actual deployment's final command, environment, keystore, raw Quarkus/JVM options and selected configuration path separately. The tool cannot discover undeclared deployment sources, prevent a later override, read live configuration, validate CA/certificate contents or prove routing/privileges.

The catalogue's `mfaRequired` flag is not accepted as evidence of a factor flow. Customer banking MFA, permanent phishing-resistant administration, workforce factors and privileged recovery must be tested against the actual selected flow/enrollment/SSO behavior. Password policy checks establish the selected terms, not the existence of a maintained compromised-password feed, a FIPS-certified cryptographic module or legal compliance. Bootstrap-property absence does not prove a temporary administrator was removed.

## Decisions and evidence still required

| Decision ID | What the institution must choose / provide | Acceptance evidence |
| --- | --- | --- |
| `LEGAL_APPLICABILITY` | Entity, EU/US regulators/state overlays, jurisdictions, journey and processing roles | Signed applicability/control mapping and change owner; see [EU/US matrix](controls-matrix.md) |
| `CUSTOMER_FACTOR_FLOW` | Covered login/enrollment/step-up, payment SCA/dynamic linking, inactivity, phishing resistance and alternate evidence | Real positive/refusal/enrollment/expiry tests for each journey |
| `PRIVILEGED_FACTOR_FLOW` | Named least-privilege administrators, approved phishing-resistant factors, emergency access and private administration | Actual privileged MFA/SSO/refusal and emergency-access review |
| `TRUSTED_IDENTITY_BINDING` | Authoritative customer/staff/tenant linkage and protected provisioning/revocation | Current-state, forged-profile, cross-tenant and substitution refusals |
| `KYC_ASSURANCE_PROVIDER` | Third party, existing-party resolver, evidence/assurance/policy provenance, retention and eIDAS applicability | Actual adapter/vendor conformance; a KYC status is not recovery authority |
| `WORKFORCE_ADMIN_RECOVERY` | Employment/privileged recovery owner and acceptable alternate evidence | Separate approved loss/revocation and termination journeys |
| `BPO_DELEGATION` | Staff/customer/case/call/tenant/purpose authority, supervision and consent | Actual attributed, narrowly delegated receiving-service checks; PIN is insufficient |
| `NETWORK_CERTIFICATES_DATABASE_PRIVILEGES` | Topology, issuer/admin/proxy ownership, CA/mounts, secret manager, monitoring and least-privilege DB roles | Real TLS/hostname failure tests, public-route denial and runtime privilege probes |
| `BOOTSTRAP_ACCOUNT_REMOVAL` | Permanent access and temporary-account removal procedure | Actual account/role readback and refused temporary login after removal |
| `RETAINED_DATA_HA` | Residency, restore objectives, compatible migrations/rollback and cluster topology | Isolated retained restore/migration and selected multi-node failure results |
| `NOTIFICATION_CHANNEL` | Real channel, advance-block notice/restoration, service levels, alert receivers and terminal escalation | Channel outage/recovery and monitored end-to-end notice acceptance |
| `CONSUMER_CURRENT_STATE` | Per-Experience/Domain/Core authorization, revocation/cache/failure policy | Every actual receiver's cross-audience/current-state/refusal results |
| `AUDIT_PRIVACY_INCIDENTS` | Retention, immutable custody, privacy/transfers and applicable incident clocks | Installed audit/alert controls and rehearsed institution procedures |

These are independent decisions. Selecting the KYC provider does not close administration, TLS, database, customer-factor, BPO, HA, incident or notification gates. Conversely, passing offline checks never authorizes the provider, a recovery grant or a banking operation.

## Change and qualification procedure

Run `make check` after changing the audit or reference; the tests mutate valid synthetic candidates into unsafe variants and require refusal, including TLS URL overrides, permanent-lock changes, cross-population substitution, unsafe grants, ambiguous input and secret-safe errors. Keep test fixtures synthetic and provider-free. The hosted Production reference workflow additionally invokes `show-config all` in the actual digest-pinned Keycloak image with synthetic values and no container network, retaining only expected-option/source/hash results. This establishes option parsing, not a TLS handshake, database connection or production startup. The strict handbook workflow separately verifies the actual documentation under `/firefly-id/` before Pages can publish.

For promotion, follow [regulated deployment](regulated-deployment.md), [retained-data rehearsal](retained-data.md), [workforce administration](workforce-administration.md) and the [evidence register](evidence.md). Record exact source/artifact, supplied candidate report, effective live readback, owner decisions and actual-environment acceptance as separate records. Production generation remains closed until the genuine institution contract is supplied.
