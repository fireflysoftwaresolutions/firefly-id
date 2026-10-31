# Architecture and identity lifecycle

Firefly Identity owns authentication and identity sessions. A dedicated PostgreSQL database stores credentials, authenticators, identity-provider links and identity configuration. It must never become the banking customer, product, employee or consent database.

## Identity and resource ownership

The identity key is `(verified issuer, opaque subject)`. A username or email is mutable and does not replace that key. An institution's platform tenant namespace is a string scoped by issuer. Core's resource tenant is a separately typed UUID obtained through the currently authorized Configuration binding. Preserve both throughout calls and audit records.

Server-managed party and staff references link the identity to authoritative Core records. Customers use party relationships; workforce uses a staff actor relationship and employment/membership status. Institutional users need their own authoritative organization/membership permissions. A realm name, email domain, organization label or realm role cannot establish those relationships.

Keep customers, workforce, service accounts and administrators in separate trust profiles. Use institution-specific realms and issuer allowlists, and separate instances/databases where the operational isolation requirement exceeds a logical realm. The sandbox's three population realms demonstrate separation for synthetic data; they are not a multi-institution production topology. The master realm is administrative only. Production administrators use a private ingress, least-privilege roles and phishing-resistant MFA.

## Application calls

Experience orchestrates Domain; Domain orchestrates Core through genuine original-producer OpenAPI-generated SDKs. Core owns business persistence through Spring Data. Domain and Experience may cache and orchestrate but cannot take ownership of business records. Generic Jafly business interfaces carry verified principals and purpose-specific authorization inputs, with no Keycloak administration models leaking into them.

Every receiver validates the signature, exact trusted issuer, intended audience, approved algorithms, expiration and applicable not-before. It reads a verified framework principal, never identity headers supplied by a browser. Machine OAuth authenticates the calling service; approved signed human delegation separately binds original subject, tenant, purpose, delegating client and bounded lifetime. Where that exchange/verification contract is not implemented, the path stays unavailable. Do not forward arbitrary bearer tokens across audiences or simulate human proof with client credentials.

Coarse identity roles classify access. The current business PDP, consent and authoritative resource ownership determine financial actions. Fulfill policy obligations or refuse the operation. Authentication, email verification and MFA do not imply KYC, AML screening, consent or transaction authority.

## Provisioning and linking

1. Receive an approved joiner/onboarding request through the owning application API. Validate institution, population, identity-proofing status and required consent there.
2. Obtain/create the Core party or employee record through its actual owner API. Persist business state in Core and record an idempotent provisioning intent through the application's existing durable workflow/outbox mechanisms.
3. A narrowly privileged provisioning adapter creates or links the identity using approved issuer/subject and authoritative business identifiers. It must not resolve a person by email alone or attach arbitrary user-supplied tenant attributes.
4. Complete credential enrollment and verified communications through identity required actions. Keep enrollment success separate from business onboarding approval.
5. Reconcile partial failure with explicit retry/idempotency and compensation policy. Do not silently provision broad realm administration or financial roles to make a retry succeed.

For a mover, revalidate membership and business policy before changing tenant/staff/party linkage. Revoke affected sessions and grants where required and record both old and new authoritative links. For a leaver, disable access, revoke identity sessions/refresh credentials and business grants, remove federation access where applicable, and preserve required audit/retention. Short-lived JWTs remain cryptographically valid until expiry unless the receiver uses the approved revocation/current-policy mechanism; logout alone does not promise instant offline JWT invalidation.

Password replacement and permanent-account unlocking are separate operations. The selected unlock policy requires previously enrolled independent knowledge and possession evidence, a purpose-bound single-use recovery transaction, and current authorization of the exact lock state. Email, a party/staff identifier, an SCA CRUD status or service authentication alone cannot authorize unlocking. Lost knowledge or possession requires approved assisted identity reproofing; it must not silently lower the assurance level. Recovery cannot rewrite business ownership or grant financial authority. See [permanent blocking and recovery](permanent-recovery.md) for the exact provider limitations and implementation gates.

## Audit and operations

Deliver identity and administration events to the broader audit pipeline through a reviewed collector or supported event-listener extension. Specify authenticated transport, bounded retries/backpressure, deduplication, event ordering and failure handling before deploying it. The repository does not ship a durable immutable-audit bridge yet. Keycloak's mutable event tables, application logs and unit tests do not prove immutable custody or regulatory compliance.

Use the [operations guide](operations.md) for protected backups, restore rehearsals, key/client rotation and upgrade review. Review real consumer behavior before accepting any lifecycle change.
