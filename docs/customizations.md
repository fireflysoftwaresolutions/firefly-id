# Firefly customizations and defaults

Firefly Identity combines supported Keycloak configuration, inherited presentation and optional product extensions. This catalog locates those changes and explains their intent, enforcement and verification. It also identifies controls that are deliberately unavailable until their independent owner is approved.

Use the [generated policy catalogue](reference/effective-defaults.md) for literal policy values, [configuration reference](configuration-reference.md) for every configuration layer and [evidence](evidence.md) for exact runtime revisions. A capability described here is not automatically enabled in every installation. The ordinary theme distribution, optional native package and independently deployed Core/Domain candidates have different prerequisites.

## Presentation and identity

| Customization | Implementation / reason | How to verify and maintain |
| --- | --- | --- |
| Protected-identity symbol and family signature | Approved original SVG assets under [brand](../assets/brand/firefly-id-dark.svg); symbol sits beside lowercase `identity`, preserving the parent Firefly artwork | Compare the original geometry and light/dark variants; preserve proportions and small-size legibility. Do not retype the parent wordmark |
| Canonical typography | Self-hosted Manrope and its OFL notice are packaged from the same original source for web surfaces | Check actual font loading/hash after the page settles. Email uses the documented system fallback because mail clients can block web fonts |
| Shared color, spacing and controls | [Token layer](../themes/tokens.css), supported surface styles and semantic light/dark roles | Review actual input, heading, label, focus, error and disabled states in both modes; PatternFly variable names are aliases rather than literal physical colors |
| Illustrated authentication layout | [Login stylesheet](../themes/firefly-id/login/resources/css/firefly.css) and approved isometric artwork | Check desktop/two-column and narrow/single-column layouts. Depth ordering must remain coherent, especially connectors/pipes; artwork never carries authorization |
| Login, logout and required-action branding | Inherited templates plus exact-version [macro adaptation](../themes/firefly-id/login/template.ftl) | Preserve form actions, CSRF/action tokens, upstream required actions and authenticator semantics. Reconstruct/check intentional template differences on upgrades |
| Functional icons | Dedicated icon properties/classes and optical-size SVGs, with source licenses | Verify the named controls and actual 16/20/24 px usage. Do not globally mask arbitrary console SVGs or replace meaningful labels with decorative icons |
| Generic public responses | English/Spanish presentation messages normalize supported authentication failures and recovery acknowledgements | Compare visible main content/status for known, unknown, disabled and blocked cases; omit factor outcomes and remaining-attempt counts. This is not a complete timing-side-channel proof |
| Masked password presentation | [Field adaptation](../themes/firefly-id/login/field.ftl) and supported console presentation script remove available reveal controls | Test real login and administrative credential dialogs after upstream upgrades. This does not prevent the browser owner inspecting their own typed value or replace server policy |
| Branded account and administration | Supported theme properties, shared [console CSS](../themes/console.css), canonical assets and localized scripts | Test the actual upstream consoles, long content, tables, responsive masthead and real error dialogs. Do not replace their administrative permission model with frontend conditions |
| Error and completion states | Shared illustrated forms, clear localized recovery/return actions and console retry presentation | Exercise actual protocol/expiry/unavailable paths, rather than a standalone HTML mock. Presentation must not suppress an authoritative refusal or fabricate success |
| English/Spanish locale handling | Supported upstream preference resolution and custom message bundles; quiet optional footer override | Test browser fallback, explicit `ui_locales`, saved/selected preference precedence, clean-URL persistence and both appearances. System-language changes do not erase a deliberate choice |
| Foundation and upstream recognition | Copyright and Keycloak attribution on scoped web/email surfaces | Retain actual Apache LICENSE/NOTICE, icon licenses and font OFL separately. A footer phrase is a product choice, not a substitute for distribution obligations |

The implementation details and visual evidence are maintained in [themes](themes.md), [localization](localization.md), [tokens/icons](design-tokens.md), [brand](brand.md) and [isometric artwork](isometric-backgrounds.md). A theme-only installation does not advertise working native APIs. Operators select the native variant only after its real dependencies are installed and qualified; the theme property itself does not perform a backend availability check.

## Authentication policy selected by Firefly

| Policy decision | Selected behavior | Why and acceptance boundary |
| --- | --- | --- |
| Separate populations | Customer, workforce and institutional-human realms/stores; master is administrative | Prevents a customer session or customer proofing case becoming employee/administrative identity. A logical realm alone is not every institution's required operational isolation |
| Password length/history | Customer/institution 16–128 characters and history 5; workforce/admin 20–128 and history 10 | Supports long passphrases and reuse resistance. These are product values, not a universal EU/US statutory password recipe |
| Password validation | Argon2 selection, whole-value username/email exclusion and baseline denylist | Enforce at the server and prove actual boundary acceptance/refusal. A static list is not a maintained compromised-password feed; algorithm selection is not FIPS/NIST certification |
| Composition and expiry | No arbitrary mixed-character recipe or routine expiry in the base catalogue | Avoids representing composition as assurance. A covered regime may require an interval/incident policy; the institution must select it under [applicability](controls-matrix.md) |
| Permanent lock | Third failed authentication permanently disables ordinary access; no timed release | Selected stricter threshold with a distinct secure restoration path. Applicable advance notification and operational restoration still need approval; ordinary password reset does not unlock |
| Customer MFA | Optional in the synthetic base profile | Deliberately not described as an accepted banking SCA policy. Covered production customer/high-risk journeys require their approved factor/enrollment/step-up profile |
| Workforce MFA | Dedicated browser flow with required password and OTP for fresh authentication | Requires native enrollment before code issuance when absent. Existing eligible SSO can be reused; TOTP is not phishing resistant |
| Administrator MFA | Catalogue intent plus separate production acceptance | A flag is not an enforced permanent privileged flow. Qualify private ingress, named least-privilege admins, phishing-resistant factors, emergency access and bootstrap removal |
| Sessions and refresh | Population-specific short idle/access lifetimes, refresh rotation and zero reuse | Read back actual settings and test real clients. IdP idle time does not measure payer inactivity in an application kept alive by refresh |

The complete shared properties and per-profile realm values are generated from [the same catalogue the generator consumes](../config/authentication-policies.json). [Authentication policies](authentication-policies.md) explains exact policy IDs, effective overlay order, the actual third-failure algorithm and scoped EU/US context. Do not duplicate those values in a new configuration fork.

## Client and profile boundaries

The [generator](../scripts/generate.py) makes the evaluation contract explicit. It disables public registration and username self-editing, requires verified email policy, disables unmanaged attributes and keeps tenant/party/staff references administrator-owned. Ordinary profile-name/email updates do not acquire another population, tenant or signed authority.

Interactive public and confidential clients use code plus PKCE S256, exact callback/logout allowlists, narrow scopes and intended resource audience. Password/direct, implicit, device and CIBA grants are disabled. `basic` remains an explicit default scope so the provider issues the native opaque subject and authentication-time mapping. The confidential API receiver has its own credential without an ordinary token grant.

Only access tokens receive the selected business-reference mappers. Customer/institution humans receive the party link, workforce receives the staff link, and `principal_kind`/client values come from controlled mappings. An ID token, account-console token or arbitrary browser header is not a substitute resource access token. [Claims](provider-claim-profile.md) and [audiences](receiver-audiences.md) record the measured shapes.

The optional [Configuration lookup](configuration-service-client.md) is an explicit exception to the default service-account-free profile. It requires a distinct nonreserved client, realm and opaque tenant. It issues a narrow `MACHINE` principal without customer/staff linkage, human delegation or financial authority. Its successful synthetic issuance/Jafly fixture is separate from adoption by a real Configuration service.

Every Experience, Domain and Core receiver still authenticates and authorizes its own operation. The [independent Jafly integration](jafly.md) adds no Identity-specific framework dependency; a signed identity link does not remove business-policy, consent, mandate or current-state checks. [Zero trust](zero-trust.md) defines that receiving boundary.

## Optional native unlock and PIN

| Addition | Implemented responsibility | Boundary to retain |
| --- | --- | --- |
| Native lock tracking and eligibility | Capture/recheck current tracked lock generation, protected native state and administrative/credential changes | Fraud, employment and administrative holds are not ordinary authentication locks and cannot be removed by self-service proof |
| Existing-factor verification | Native password and previously enrolled nonreusable TOTP checks under committed owning reservations | No old-factor enrollment, ordinary login token or forgotten-password replacement is invented inside known-password unlock |
| Core/Domain SCA authority | Independent owning challenges, exact purpose/binding and canonical operation | Native workload credentials identify a service, not a customer or financial permission |
| Execution/journal/replay fences | Locked current-state transition, durable reservations/replay records, old-session retirement and exact execution evidence | Retrying ambiguous work reconciles only the original identifiers; no replay, refunded attempt or fresh grant repairs a lost response |
| Browser ceremony security | Exact HTTPS Origin, secure Strict ceremony cookie and persisted one-use CSRF digest | These are native ceremony controls; ordinary upstream cookies have their separate measured purposes and attributes |
| Customer support PIN lifecycle | Enabled customer session plus fresh native password/TOTP for create/rotate/revoke; eight-digit weak-value checks, keyed protection and native hashing | No plaintext retrieval; PIN is customer knowledge evidence, not login, unlock, payment or staff delegation authority |
| PIN key rotation | External versioned key mount, explicit active key and bounded old-key verification deadlines | Preserve valid original keys/versions; missing or revoked keys refuse. Do not reconstruct stored PINs or reuse this pepper for recovery encryption |
| Attributed privileged PIN revocation | Actual administrator/client/event attribution and preserved recovery budgets | Administrative mutation is not a substitute customer proof or a permission for a BPO operator |
| BPO verification boundary | Requires the real staff/customer/case/call/tenant/purpose authorization owner | No qualified implementation is supplied, so the support-verification operation remains unavailable |

[Native recovery](native-recovery.md), [the native owner README](../extensions/native-recovery/README.md) and [support PIN](support-pin.md) provide the exact realm attributes, purpose rules and keys. These additions require both provider/gateway installation and genuine owning services. Their thirteen JPA mappings are additive installation changes, including separate credential-loss records; default-off does not suppress schema registration.

## Separate lost-credential recovery

Credential replacement is a different purpose from known-password unlock. An eligible local customer may forget the old password, lose the authenticator or lack an old enrolled TOTP. The candidate requires independent evidence first, then verifies a replacement password and new native TOTP before the exact atomic transition. It can remove only an eligible authentication lock; unrelated holds and unsupported populations/stores remain refused.

Core KYCB owns durable cases, provider-start idempotency, immutable provider-session binding, original expiry, evidence/grant/execution references and separate refusal/verified-grant budgets. Customer Domain integrates a future third-party verifier and independently retrieves authenticated results. Native checks fresh eligibility, the exact consumed authorization and protected revision before changing credentials, retiring PIN/session authority and recording notification intent.

Unknown/held identities share a generic public journey without receiving a final grant. Forged, substituted, stale or unavailable evidence cannot become approval. A genuine negative result is distinct from operational unavailability. Retries retain the original provider reservation/session, case, grant, execution and expiry; post-expiry reconciliation can record an exact already committed journal without another mutation or grant.

Enrollment/notification data uses explicitly provisioned versioned encryption. Raw passwords do not persist in the ceremony. The prior verified destination is retained for notice; changing contact invalidates unexecuted work rather than silently replacing that destination. The [credential-loss guide](credential-loss-recovery.md) gives the precise contract, storage, budgets and key procedure.

The selected KYC/KYB model is a system of record with independent third-party adapters. There is no chosen verifier or biometric engine. An authentic existing-party resolver, structured assurance provenance, immutable policy version, defined evidence hashing and mandate/revocation acceptance still need their approved contract. [Provider integration](assurance-provider-contract.md) separates current records/ports from those future requirements. A KYC status or vendor LoA label never unlocks an account by itself.

## Notification worker and supervision

Native owns the encrypted outbox, leases, backoff, actual email provider and eight-attempt terminal budget. Core's optional managed poller dispatches one row then reads a strict realm-scoped aggregate. It is disabled by default, requires the global recovery opt-in and separate sender/monitor credentials, bounds the complete cycle and cancels active work at shutdown.

Private HTTPS GET status and metrics expose only safe state/counts/timestamps. The worker's Prometheus registry is excluded from global Actuator. External alert rules cover missing/stale observation, failures, retry/backlog and terminal work. A worker that is disabled cannot emit its own absence alarm.

Delivery is at least once. An expired eighth sending lease becomes a retained terminal failure without a ninth send. There is no automatic terminal replay, delete, destination replacement or budget reset. [Notification operations](notification-operations.md) supplies exact defaults, secret/TLS constraints, monitoring paths, drain/disable and escalation. Approved real SMTP, advance-block communications and operational ownership remain production acceptance.

## Packaging, deployment and operating controls

The distribution pins the upstream server and image digests, packages original themes/assets/notices and keeps business records out of the identity database. Native Java 21 and separate platform-service Java 25 fixtures remain explicit; updating a version tag does not qualify a new runtime.

The synthetic generator creates random credentials in a protected new directory, records an immutable Compose ownership hash and refuses overwrite. Lifecycle operations require a local Unix engine and appropriate capacity, act only on that owned project and retain data on stop. No global prune/reset/cleanup helper is supplied. Mailpit and HTTP convenience are evaluation-only.

Production reference configuration fixes canonical/private hostnames, strict proxy trust, HTTPS, private management, structured logs and bounded shutdown. Actual database TLS/privileges, ingress route denial, secret-manager injection, bootstrap removal, keys, backup/restore, migration and selected HA topology require target-environment evidence. [Regulated deployment](regulated-deployment.md), [operations](operations.md), [retained data](retained-data.md) and [incident response](observability-incidents.md) explain the implementation sequence and acceptance owners.

The production generator deliberately refuses an unselected institution contract. This prevents a synthetic example from becoming an accidental banking deployment. It is not a missing flag to remove during rollout.

## Documentation is also a maintained surface

The handbook uses MkDocs with source-derived policy/image references, local Manrope/brand resources, original responsive architecture diagrams, scoped light/dark tokens, search and accessible breadcrumbs. The navbar identifies the product through the logo without a repeated text label. The repository link does not make automatic third-party statistics requests.

Build provenance distinguishes committed source from unpublishable dirty previews. Strict validation checks links/anchors and excludes private state/internal planning. Actual browser checks cover every guide in both appearances and viewport sizes, real-keyboard search, navigation, palette persistence, canonical font/colors, branding and overflow. The documentation Site is owner-private; publishing it does not deploy the CIAM service. [Documentation maintenance](documentation.md) describes dependencies, licensing and the reproducible workflow.

## Verify a customization before promotion

For each affected population and journey, record the exact source/artifact, selected setting, owner, expected positive behavior and refusal behavior. Rebuild the real package, read back server configuration and run the relevant browser/provider/receiver tests. Retained installations additionally need the reviewed migration/rollback procedure. Preserve original state and failed evidence when a check fails.

The [qualification register](evidence.md) records actual 48-control known-password/PIN and 25-control customer credential-loss lanes, with their different owning services and unchanged native binary. Passing those synthetic tests does not approve a bank's actual verifier, factor policy, immutable custody, every receiving service, retained database or regulatory rollout. The [EU/US matrix](controls-matrix.md) connects the implementation to applicable obligations without converting this catalog into a compliance certificate.
