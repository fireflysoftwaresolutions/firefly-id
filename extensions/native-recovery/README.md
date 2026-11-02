# Native recovery extension

Native recovery extension for Keycloak 26.8.1 and Java 21. It contains no Jafly dependency. The distribution must explicitly select the `firefly-native-recovery` brute-force provider and deploy this JAR together with the product gateway for known-factor unlock.

Start with the [build and installation procedure](../../docs/native-recovery.md#build-the-native-image), then configure the [server and deployment](../../docs/operations.md). The [recovery guide](../../docs/access-recovery.md) explains which customer or workforce journey to enable.

The known-password/PIN protocol below is distinct from the separate [customer credential-loss purpose](../../docs/credential-loss-recovery.md), which enrolls replacement credentials after independent proofing. Statements about no enrollment in known-password unlock do not describe that separate purpose.

## Native boundaries

The `firefly-recovery` RealmResourceProvider serves native recovery and customer support-PIN pages. Internal JSON RPC is rooted at `/realms/{realm}/firefly-recovery/rpc/{route}`. Browser cookies are Secure, HttpOnly and SameSite Strict; POSTs require exact configured HTTPS Origin and a persisted one-use CSRF digest. Root-owned FreeMarker templates supply the branded UI.

Password bootstrap grants restricted admission only. The second password check and enrolled-TOTP check follow committed Core reservations. Each native budget reservation commits before verification; provider failures do not refund it. Completed negative attestations let Core close a failed reservation without revealing verifier outcomes. Retrying the exact completed reservation returns the same opaque result without another secret check or debit; an in-flight or crash-pending reservation refuses another check. Database reservation uniqueness is an additional fence. Positive attestations are exact-operation/challenge/reservation/generation/credential references, never login tokens. Native checks use the owning password hash and enrolled TOTP; there is no enrollment or ordinary-session creation in recovery.

Each phase uses a new child KeycloakSession. The original request transaction commits once, and no managed entity or native lock crosses a Domain/Core HTTP callback. Final execution rechecks native state and protected credential snapshots, journals the exact Core execution ID, removes online and offline sessions, raises user not-before, and performs the eligible native transition. Existing untracked permanent locks are not automatically enrolled. Administrative/credential/profile changes place outstanding recovery on hold; generic enable uses an actual-JTA veto rather than relying on swallowed listener exceptions.

Master, realm-management administrators, institutions without an explicit human/workforce profile, federated/read-only and service accounts are outside this self-service path. Unmanaged ordinary authentication continues through the native default brute-force implementation. Ordinary resource-server JWT revocation/current-state enforcement remains a separate consumer requirement.

## Explicit realm configuration

All keys below are realm attributes with prefix `firefly.native-recovery.`. There are no trusted defaults:

- `issuer`, `population` (`HUMAN` or `STAFF`), `client-id`.
- `tenant-attribute`, `link-attribute`: server-managed opaque tenant and canonical population-specific UUID link; enforce administrative-only ownership in the deployed user profile.
- `allowed-origin`: exact HTTPS origin; issuer must be that origin plus `/realms/{realmName}`.
- `domain-audience`, `core-audience`: distinct restricted audiences, no business audience.
- `core-workload-client-id`, `domain-workload-client-id`: distinct confidential enabled clients with standard authorization-code, direct-access/password, implicit, service-account/client-credentials, device, CIBA, standard token-exchange and JWT authorization grants disabled, and independently managed native secrets.
- `ttl-seconds`: explicit positive duration, at most 300 seconds for customers and 180 for workforce.

Restricted assertions contain the approved recovery-only vocabulary and exactly one population link. Internal RPC independently checks native workload Basic credentials and that signed assertion. Core workload routes are admit/issue/verify/journal/reject; Domain routes are admit/journal/audit. Domain audit accepts only the two fixed boundary events, persists anonymous refusals without trusting body targets, and acknowledges only after native commit. Post-unlock record admission is audit-only and bound to the native journal; Domain additionally supplies the exact operation ID.

The actual transport implementation is discovered through `NativeCeremonyGateway.Factory`. Its absent or unqualified implementation refuses recovery. The sibling product gateway supplies genuine authenticated Domain callbacks; a sample success implementation is not an accepted substitute.

## Native persistence

Thirteen native JPA entities (eight original unlock/PIN records plus five credential-loss records) are explicitly contributed by standalone `META-INF/orm.xml` to Keycloak's default persistence unit and indexed by Jandex. `JpaEntityProvider.getEntities()` is retained only for the legacy SPI signature; production discovery does not rely on it. The owning Liquibase changelog creates independent native tables and PostgreSQL append-only audit triggers. Installation changes the identity database and requires the deployment's reviewed migration and backup process.

Credential snapshots lock and refresh native credential rows for final checks. Listener snapshots preserve pending changes. Interleaved native administrative paths can have different lock order; database deadlock/rollback must remain fail closed and be covered by real provider concurrency tests. No JVM map, cache flag or HTTP read-then-write is an unlock fence.

Native TOTP replay protection is retained and supplemented by a durable keyed recovery replay record. Raw submitted codes are not persisted. Retention of audit, expired ceremonies, replay records and old execution journals requires an explicitly reviewed identity-owner policy; journals needed for reconciliation must not be removed merely because a browser ceremony expired.

## Customer telephone/support PIN

PIN SET/REVOKE requires an enabled ordinary native identity cookie, the same HUMAN customer, fresh native password and enrolled non-reusable TOTP, HTTPS Origin and one-use CSRF. Status exposes only lifecycle state/dates. An eight-digit PIN rejects weak sequences and is HMAC-peppered with realm/subject binding before native Argon2 hashing. PIN failures/reservations have a distinct durable three-failure budget and do not clear login lock state.

Supply `FIREFLY_SUPPORT_PIN_KEYS_DIR` as an external secret mount, `FIREFLY_SUPPORT_PIN_ACTIVE_KEY` as the active file/version name, and at least 32 random key bytes in that owner-readable file. No group/other read/write permissions or symlink key files are accepted. Approved old verification versions additionally require `FIREFLY_SUPPORT_PIN_VERIFY_UNTIL_<version>` with an explicit future RFC3339 deadline. Missing/revoked keys deny verification. Replacement after strong authentication upgrades the active version; no plaintext retrieval or background PIN reconstruction exists.

`NativeSupportPinServiceImpl` is intentionally not an HTTP business API. It requires exactly one qualified `NativeSupportAuthorization.Factory` that resolves the genuine STAFF actor, customer, case/call, tenant, approval and narrow purpose. No implementation is supplied here. Until the owning support/delegation contract is qualified, BPO verification remains unavailable. A PIN reference is knowledge evidence only and cannot authorize login, unlock, payment or staff impersonation.

## Configure the operating environment

Use [credential-loss recovery](../../docs/credential-loss-recovery.md) for the independent proofing services, workload identities and encryption keys, and [notification operations](../../docs/notification-operations.md) for the delivery worker and monitoring. Configure a real verification adapter before offering credential replacement; no production verifier is included.

Installing this JAR registers additive migrations even while recovery is disabled. Follow [retained-data migration and restoration](../../docs/retained-data.md) before changing an existing database. Workforce lost factors, privileged recovery and BPO authority require their separate owning procedures. Configure [receiving-service current-state enforcement](../../docs/zero-trust.md) and rehearse the actual deployment's concurrency, failover and recovery behavior.
