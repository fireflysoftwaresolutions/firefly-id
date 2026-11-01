# Recovering access after credential loss

This default-off candidate implements a separate customer recovery purpose, `CREDENTIAL_REPLACEMENT`, across Core KYCB, customer KYC Domain and the native Keycloak extension. It does not require the previous password or an existing authenticator to be available. It requires independently verified identity evidence before replacement credentials can be bound.

**No real proofing provider or bank procedure is approved yet.** The successful provider in qualification is test-only and is excluded from production JARs. The actual native/Core/Domain browser lane exercises credential/PIN/session retirement, automatic notification retry and post-expiry restart reconciliation with that provider. This does not establish real documentary/biometric acceptance. Production realm generation remains closed. See [current evidence](progress.md) and [provider evaluation](identity-proofing-evaluation.md).

## Supported identities and journeys

An eligible local customer may have forgotten credentials while their account is active, or while a permanent authentication lock prevents ordinary login. Recovery replaces the password and binds a newly verified TOTP authenticator before activating access. A customer who never enrolled the old TOTP does not need to supply it. Only the fulfilled password/TOTP required actions are completed; other required actions remain in place.

Administrative, fraud and employment holds are not unlock permissions. Service accounts, administrators, foreign credential stores, linked external identities and unsupported credential types such as passkeys are refused. Customer KYC does not recover employees. Workforce recovery needs its separate identity/employment owner; an employee must not be linked to a customer case by email or name.

The existing [known-password unlock](native-recovery.md) remains a different purpose and flow. A support PIN, existing KYC status, email link, caller ID or staff login does not authorize credential replacement.

## Ownership

| Owner | Responsibility |
| --- | --- |
| Core KYCB | KYC/KYB system of record; durable recovery cases, provider-start reservations, evidence references, one-time grants, budgets, execution/audit and optional notification polling |
| Customer Domain | Independent provider adapters, verification orchestration, exact response validation and genuine generated Core SDK integration; no Domain database |
| Native Identity | Browser ceremony, current identity/hold/revision admission, credential replacement, old-session retirement, canonical execution and notification outbox |
| Jafly | Existing generic framework security facilities; no Identity, Keycloak or proofing-provider dependency is added |

Every receiving product boundary authenticates a distinct workload and authorizes its permitted operations. A successful Basic authentication over trusted TLS establishes the caller, not the customer's identity or a recovery decision. Domain independently checks the native ceremony; Core independently retrieves provider evidence and current native admission; native execution checks the exact consumed grant and current state again.

The product chains protect their complete recovery paths even when the feature is disabled. They must not replace the application's generic catch-all resource-server chain. If an optional generic resource-server module is enabled but its independent chain is missing, the candidate refuses startup. Qualification explicitly disables that optional module only to isolate the product boundary; this does not qualify unrelated CRUD endpoints or platform-wide live revocation.

The selected operating model uses third-party verification, with Core retaining authoritative records and Domain integrating the provider. The [identity system-of-record contract](https://github.com/fireflysoftwaresolutions/domain-customer-kyc-kyb/blob/codex/identity-reproofing-domain-20261031/docs/identity-system-of-record.md) distinguishes implemented records from the assurance metadata, authoritative party binding and vendor acceptance still required. eIDAS is the design baseline; no scheme qualification or regulatory certification is inferred. No biometric engine is installed.

## Provider adapters

The Domain `ReproofingProviderPort` has two operations:

- `begin(ReproofingCaseResponse)` returns a provider session and an allowlisted HTTPS verification URL. Use Core's persisted `providerStartId` as the provider's actual idempotency key. A timeout or restart must reconcile the same session; an ambiguous start must not create another opportunity.
- `verify(ReproofingEvidenceRequest)` independently retrieves and authenticates the provider-owned result for Core's exact stored case/session/nonce/customer/policy. It returns an authenticated evidence envelope, including genuine negative outcomes. It must not trust browser redirects, callback fields or a supplied `approved=true`.

A real adapter must establish document/issuer authenticity, live matching capture, the approved reference identity, fraud checks and all policy requirements. The reference must bind the existing customer; do not create or auto-link an account by matching email/name. Provider signatures, callbacks, result freshness, replay, substitution and model/data licenses need their own acceptance.

An authenticated negative result spends that case's refusal budget. Forged, expired, substituted or unavailable results never mint a grant. Operational unavailability must not become a fabricated business rejection. Raw images, document data and biometric templates remain with the evidence owner, outside Keycloak attributes, these DTOs and application JWTs.

There is no generic public approval endpoint. Only the separately authenticated Core verifier may use Domain's `/internal/identity-recovery/evidence` endpoint. Native's orchestration workload cannot verify its own evidence.

## Case and grant protocol

Both product owners use `/api/v1/identity-recovery/cases`. Core additionally exposes the private provider-session binding operation. The [frozen wire contract](superpowers/specs/2026-10-31-reproofing-wire-contract.md) defines every field and operation.

1. The native browser accepts the account identifier and creates an unpredictable cookie-bound ceremony. Known, unknown and held accounts receive the same verification journey; private decoys cannot pass final admission. The previous password is not requested.
2. Core creates a bounded case and immutable provider-start reservation. Domain begins the provider journey and durably binds its session in Core. The provider opens in a separate tab; the customer keeps the native page open and returns there to check verification. This preserves the Strict ceremony cookie without a cross-site callback shortcut.
3. Domain PREPARE authenticates the server ceremony without asserting customer eligibility. Core obtains an authenticated provider result from the private Domain verifier. A genuine negative result can terminate only that case. Complete affirmative proof still requires fresh eligible native ADMIT before any grant, followed by a locked recheck.
4. A grant binds the existing issuer, realm, tenant, subject, party, purpose, stable epoch, complete credential revision, ceremony nonce, case, approved policy/evidence and one canonical execution UUID. Its original expiry is at most 120 seconds and never exceeds the case. Case lifetime is at most 600 seconds, bounded by the original native ceremony. Retrying never renews either.
5. Native presents new password/confirmation and a new authenticator setup key. Password validation uses the actual realm policy/history. TOTP proof uses the configured supported algorithm, digits, period and clock window against database time; the ordinary Keycloak provider also consumes the new credential's code. Credentials never leave Keycloak and raw passwords never persist in the ceremony.
6. Core consumes the grant for its canonical execution. Native verifies that consumed receipt online before acquiring its mutation locks. Under those locks it rechecks current eligibility/revision/expiry, replaces required factors, retires old authenticator and PIN authority, clears only an eligible authentication lock, retires online/offline sessions, advances not-before and records execution plus notification intent atomically. There is no public reset-password/enable sequence or temporary enablement gap.
7. Core records the exact native journal through independently authenticated RPC. A lost response reuses the original case, grant and execution. After expiry, the workload may read and record that exact committed journal; it cannot obtain another grant, mutate credentials or restore a session. The customer signs in normally with the replacement factors.

The complete credential snapshot also binds verified contact information, required actions, effective roles and the native invalidation/policy revisions. Handled administrative user changes join the native user lock and invalidate pending work without resetting its epoch/budgets. Global role/group/client/realm events participate in a bounded realm-policy fence; native checks read current metadata/effective roles after that fence. Lock ordering accounts for stock administrative transactions already holding the user row. Direct SQL, custom writers that bypass these events and full cluster behavior are separate acceptance gates.

## Budgets and public feedback

There are at most three authenticated rejected confirmations per case. That limit does not disclose which check failed or how many attempts remain. Unauthenticated claims and incomplete proof must not exhaust another customer's recovery.

The separate subject/epoch ledger counts at most three **fully verified grant issuances**, across new cases and service restarts. It is charged only after every mandatory proofing check and native admission pass. Native also bounds failed new-factor verification after identity proofing. New ceremonies, administrative invalidation, HTTP retries and outages cannot reset these ledgers. Exhaustion requires an approved escalation procedure; no public reset endpoint is supplied.

A production provider deployment additionally needs its approved source-abuse/rate policy and capacity/retention controls. Provider availability and source rate limits are not evidence that an account exists.

## Native secrets and key rotation

Configure each owner independently. The hosted fixture's addresses and synthetic provider are not production defaults. Keep the feature disabled until the actual adapter, evidence policy, infrastructure and operating procedure are approved.

| Native realm attribute | Required value or meaning |
| --- | --- |
| `firefly.reproofing.enabled` | Explicit `true` to opt in; omitted by production realm generation |
| `firefly.reproofing.population` | `HUMAN`; master/workforce recovery is excluded |
| `firefly.reproofing.issuer` | Exact HTTPS issuer, equal to allowed origin plus `/realms/{realm}` |
| `firefly.reproofing.allowed-origin` | Exact browser origin, including a nondefault port |
| `firefly.reproofing.tenant` | Tenant authorized by all three owners |
| `firefly.reproofing.tenant-attribute`, `firefly.reproofing.link-attribute` | Protected, single-valued user attributes for tenant and canonical party UUID; never public self-service fields |
| `firefly.reproofing.ttl-seconds` | Positive original ceremony lifetime, at most `600` |
| `firefly.reproofing.core-workload-client-id`, `firefly.reproofing.domain-workload-client-id` | Distinct confidential native RPC clients with all ordinary token grants disabled |
| `firefly.reproofing.notification-workload-client-id` | Separate confidential, grant-disabled client restricted to notification dispatch/status; required for the new poller |
| `firefly.reproofing.domain-origin`, `firefly.reproofing.domain-client-id` | Trusted HTTPS Domain origin and separate native-to-Domain workload identity |
| `firefly.reproofing.provider-origin` | Exact allowlisted origin for the external verification journey |

Mount the native-to-Domain secret privately through `FIREFLY_REPROOFING_DOMAIN_SECRET_FILE`. Configure outbound JVM trust for the real service certificates; do not bypass certificate or hostname verification. Inbound native RPC verifies each configured Keycloak client's current confidential, grant-disabled state as well as its credential and route authority.

Core uses the `firefly.reproofing` property prefix for its explicit `enabled`, `issuer`, `realm`, `tenant`, `provider-id` and `policy-id`. Its `receiver.client-id`/`receiver.secret-file` authenticate Domain; `native.base-url`/`native.client-id`/`native.secret-file` reach native RPC; `evidence.base-url`/`evidence.client-id`/`evidence.secret-file` reach Domain's private verifier. Use distinct credentials for each direction.

Domain independently configures the same issuer/realm/tenant/provider/policy, the allowlisted `verification-origin`, its `native-client`/`native-secret-file` receiver, `verifier-client`/`verifier-secret-file` receiver, `core-origin`/`core-client`/`core-secret-file`, and `native-base-url`/`native-rpc-client`/`native-rpc-secret-file`. Select a real `ReproofingProviderPort` implementation explicitly. The qualification-only `fixture-*` settings and controller must never be installed as production verification authority. Neither workload credentials nor provider settings belong in browser forms or application JWTs.

Native pending enrollment and notification destinations are encrypted with explicit 256-bit key material. Two mutually exclusive configurations exist:

- An explicit `FIREFLY_REPROOFING_ENROLLMENT_KEY_FILE` containing exactly 32 raw bytes, private permissions, is version `v1`.
- A mounted `FIREFLY_REPROOFING_KEYS_DIR` with private 32-byte files named by version, plus `FIREFLY_REPROOFING_ACTIVE_KEY`, supports rotation. New encryption uses only the active version; retained versions decrypt existing records.

Ciphertext uses `ffr1:<version>:<ciphertext>` and authenticates its format, version and purpose-specific context. Unknown/removed versions, context tampering, mixed/partial configuration and unversioned candidate ciphertext refuse. Never reuse the support-PIN pepper as this encryption key.

To rotate, retain the exact original `v1` file, provision an independent `v2`, switch to the explicit keyring configuration and make `v2` active. Keep `v1` while any protected ceremony/outbox entry still needs it, according to the approved retention procedure. Replacing a single key file is not a migration. There is no automatic repair, silent fallback or deletion of retained records.

## Notification and interruption handling

The native transaction queues a notice to the previously verified destination captured for that case. Changing contact or verification status invalidates unexecuted work; dispatch does not substitute a newly supplied address. The dispatcher uses the actual Keycloak email provider and the realm's approved SMTP configuration.

With the notification client configured, only that dedicated workload may POST `/firefly-recovery/lost-credentials/rpc/dispatch` or `/notification-status`; it cannot prepare, admit or journal a ceremony. Existing installations without that attribute retain Core-only manual dispatch, with no status fallback. Dispatch accepts `{}` (legacy limit ten) or an exact integer `limit` from one to ten. Durable leases, attempt fencing, backoff and at most eight delivery attempts preserve failure evidence. An obsolete worker cannot overwrite a newer delivery. An expired final sending lease becomes a durable failed/review state without another send. Delivery is **at least once**, so a process failure after SMTP acceptance can produce a duplicate notice.

Core now supplies an opt-in managed poller. Enable both `firefly.reproofing.enabled` and `firefly.reproofing.notifications.enabled`; the latter defaults false. Supply separate notification `client-id`/`secret-file` and `monitor.client-id`/`monitor.secret-file` under the notifications prefix. Identity and secret values must differ from one another and the ceremony/evidence credentials. Secret files must be private regular nonsymlink files. The worker uses the existing trusted native RPC URL, dispatches one row per cycle, then reads the realm-scoped aggregate. Fixed delay begins after each bounded cycle completes; shutdown cancels active work. Restart reobserves the same Native queue without resetting any recovery or delivery budget.

Default durations are `poll-interval=PT30S`, `request-timeout=PT30S`, `stale-after=PT90S` and `overdue-after=PT2M`. Request timeout bounds the complete dispatch/status cycle. Read the [Core operating runbook and exact bounds](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/blob/codex/identity-reproofing-core-20261031/ops/reproofing-notifications/README.md) before configuring them.

Only the independent monitor credential may use HTTPS GET `/internal/identity-recovery/notifications` and its exact `/metrics` child. Other methods/subpaths and ordinary, case or notification callers are denied. The snapshot exposes `STARTING`, `HEALTHY`, `DEGRADED`, `UNAVAILABLE` or `STALE`, observation timestamps and nonidentifying queue counts; cached counts retain their original timestamp. Staleness is computed on reads even if scheduling stops. The private worker-only Prometheus registry is excluded from the global composite and `/actuator/prometheus`; no global endpoint policy is changed. Its bounded labels contain no customer, destination or case identifier.

Install the [external alert rules](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/blob/codex/identity-reproofing-core-20261031/ops/reproofing-notifications/alerts.yml) with the dedicated HTTPS scrape credential and an assigned operations owner. Alerts cover missing/stale observations, dependency failures, retry/backlog and terminal/invalid rows. A disabled worker cannot report its own absence. Quiesce new recovery ingress and drain/review pending work before normal disabling; emergency disabling preserves the queue for follow-up. The hosted browser test stops SMTP, observes automatic retry/degraded status, restarts only Core, restores SMTP and awaits automatic delivery without manual dispatch. It also proves realm-scoped terminal failure supervision and no ninth send. Do not enable recovery while the real notification channel and operating procedure remain unapproved.

Source and synthetic-runtime qualification can prove outbox behavior and a test SMTP delivery. They do not approve a bank's real notification channel. Failed deliveries, pending execution recording and exhausted budgets need an approved operational review process; do not delete rows, clear counters, replay verification or manufacture a new human assertion to repair them.

## Installation and evidence boundaries

Installers own Core's separate `ops/reproofing-installer/install.sql` objects and roles. The native candidate has additive versioned JPA/Liquibase mappings. Installing its JAR registers those mappings at Keycloak startup even when the recovery feature is disabled; default-off is not a database-migration switch. Neither is a qualified retained-database rollout. Back up and rehearse each owner independently; do not manually apply these to production from a source test result.

Current candidates are in [Core KYCB PR #3](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/pull/3), [customer Domain PR #3](https://github.com/fireflysoftwaresolutions/domain-customer-kyc-kyb/pull/3) and [Identity PR #1](https://github.com/fireflysoftwaresolutions/firefly-id/pull/1). They remain drafts. Source qualification uses exact source-parent/Jafly 26.10.23 fixtures and a distinct genuinely generated candidate SDK; it does not replace published parent/service/SDK coordinates.

Retiring Keycloak sessions/not-before is not proof of immediate rejection of previously issued self-contained JWTs by every receiving service. Read [zero trust](zero-trust.md) for the separate receiving-service enforcement boundary. Real documentary/biometric assurance, workforce/administrator recovery, approved escalation and notification delivery, retained-database migration, multi-node crash/HA behavior, release adoption and production authorization remain separate gates.
