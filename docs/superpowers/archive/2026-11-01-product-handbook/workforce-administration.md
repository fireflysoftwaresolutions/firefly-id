# Workforce and administration

Employees, support operators and identity administrators have distinct authority. Workforce sign-in identifies an employee under its workforce issuer. Privileged administration controls the identity service through a separate administrative plane. Neither grants permission to act for a customer without current business authorization.

## Workforce authentication

The generated `sandbox-workforce` realm uses its own store, clients, protected staff linkage and policy. Its dedicated `firefly-workforce-browser` flow allows an existing eligible SSO session or requires the password and OTP forms. Password and TOTP are required on fresh authentication; the initial synthetic employee has `CONFIGURE_TOTP` and must enroll before a code can be issued. Existing SSO does not mean an employee is asked for a new OTP on every navigation.

The current generated TOTP configuration and password/session values are defined in the [generator](../scripts/generate.py) and [policy catalogue](../config/authentication-policies.json). Use the [policy guide](authentication-policies.md) for effective values and the qualification boundary. These are synthetic defaults, not a universal employee policy for every institution.

To evaluate the journey in an approved synthetic environment:

1. Complete the [sandbox setup](sandbox.md), then start an authorization-code/PKCE journey against the workforce issuer, rather than using a customer session.
2. Authenticate the synthetic employee and follow the inherited authenticator-enrollment action. Protect the server-generated setup secret and any retained test-factor file as credential material.
3. In a fresh browser context, confirm a factor challenge occurs and that an invalid OTP cannot complete the callback. Authenticate with a fresh valid code; do not relax the nonreusable-code policy to make a retry pass.
4. Validate the signed workforce token at the receiver. Its `principal_kind=STAFF` and managed `staff_actor_id` identify workforce linkage; they do not grant business roles or customer delegation. Reject a customer issuer even if another field happens to match.

The [extended runtime guide](extended-flows.md) explains actual enrollment, retained-factor testing and protected-profile probes. The latest [ordinary distribution receipt](progress.md) records passing hosted OIDC, policies/locales and published Jafly integration; older setup-time pending notes are historical, not the current result.

## Joiner, mover and leaver ownership

| Event | Identity responsibility | Workforce/business responsibility |
| --- | --- | --- |
| Joiner | Enroll/link the identity only through approved provisioning; establish authenticators and verified channels | Establish employment/membership, tenant and staff actor through the authoritative owner |
| Mover | Apply authorized link/policy changes and retire affected identity sessions/grants as required | Re-evaluate current role, institution membership, delegated access and resource policy |
| Leaver or suspension | Disable relevant identity access, retire sessions and refresh credentials, handle federation access | End employment/delegation/business grants and preserve required audit/retention |
| Recovery | Apply only the approved purpose and credential owner protocol | Revalidate employment/security eligibility and required approvals; an employee's customer KYC record is insufficient |

Do not match an employee to an identity or customer recovery case by email/name alone. A server-managed staff reference must come from the authoritative workforce owner. [Architecture](architecture.md) describes idempotent provisioning and partial-failure handling.

Where a corporate identity provider owns the credentials, its approved enrollment/recovery policy remains authoritative. This local distribution must not create a bypass by provisioning a replacement customer credential. General workforce lost-factor recovery is not qualified by the customer credential-loss candidate.

## Known-password employee unlock

The optional native known-password unlock supports explicitly configured local `STAFF` identities with a valid password and a previously enrolled TOTP. Employee and customer issuers, owner links, clients, budgets and service configurations are independent. Native self-service excludes master administrators, privileged realm administrators, service accounts and external credential stores.

The separate SCA owners authorize the exact current authentication lock; they cannot remove an employment, fraud or administrative hold. Fresh sign-in follows the native transition. The 48-control integration at Identity `15fd1b7` includes customer/workforce separation, concurrent workforce execution and session retirement with Core SCA `cc826d27` and Domain SCA `3cf19a0d`. It does not qualify lost employee credentials. See [native recovery](native-recovery.md) and [current exact pins](progress.md).

## Staff acting for a customer

A staff session proves the employee authenticated. A service credential proves which software called. The receiving service still needs current authority binding the real staff actor, customer, tenant, support case, action/resource, purpose, lifetime and required approvals. Each Domain and Core receiver makes its own decision and preserves the employee attribution.

For example, a call-center operator viewing a customer's PIN status and an operator initiating a payment are different permissions with different owners and assurance requirements. Successful customer PIN verification cannot supply either permission automatically. No genuine BPO case/call authorization owner is currently integrated; the support-verification boundary therefore remains closed. Workforce-wide signed delegation and every receiver's current-state enforcement also need independent acceptance. [Zero trust](zero-trust.md) and [support PIN](support-pin.md) define these contracts.

## Privileged administration

The master realm is an administrative plane. Production needs permanent least-privileged administrators, phishing-resistant MFA, private administrative ingress and an independently approved emergency-access procedure. The catalogue's administrator `mfaRequired` intent and short-lived token/session profile do not implement or qualify that complete privileged flow. Workforce TOTP is not a substitute for the permanent-administrator phishing-resistant requirement.

The synthetic `sandbox-bootstrap` account exists to initialize and evaluate the owned stack. The [production reference](../deploy/keycloak.production.conf.example) supplies no production realm or credential. Use a narrowly controlled supported temporary bootstrap process, establish and verify permanent administration, then remove temporary accounts and bootstrap secret injection under the operating procedure. Do not copy the synthetic shared account into production.

A separate admin hostname does not itself prevent Admin REST access through the public hostname. The ingress must restrict administrative paths and direct service access; management port 9000 belongs only on the private monitoring network. Proxy header trust, TLS and allowed paths need actual deployment verification. [Security](security.md) and [operations](operations.md) cover these controls.

## Safe administrative changes and incident response

| Action | Required distinction |
| --- | --- |
| Replace a password | Does not authorize removal of a permanent authentication lock or unrelated hold |
| Clear a failure-counter record | Does not prove the native user's disabled state changed; never use as an unlock shortcut |
| Revoke customer support PIN | Uses its explicit privileged permission and real administrator attribution, not a customer proof substitute |
| Disable user or terminate sessions | Does not prove all previously issued self-contained JWTs are immediately rejected by every service |
| Install native provider JARs | May register additive database mappings at startup even with recovery disabled; requires separate migration/restore review |
| Retry interrupted recovery | Preserve the original journal, receipt and budgets; bounded reconciliation cannot mint new human authority |

Use restricted identity/admin events for investigation and retain only approved non-secret evidence. Never place tokens, credentials, TOTP secrets, raw email or full personal profiles in logs or tickets. Retained-database migrations, failover, multi-node concurrency/crash behavior, emergency privileged recovery and bank operating acceptance remain separate gates. The [operations guide](operations.md) provides the deployment and upgrade starting point.
