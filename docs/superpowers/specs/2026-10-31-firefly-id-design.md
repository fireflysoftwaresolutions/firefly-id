# Firefly Identity design

Firefly Identity is the first-party identity distribution for Firefly OpenPlatform. It packages Keycloak with a coherent Firefly identity, reproducible PostgreSQL deployment, and explicit integration guidance. Deployments remain free to select another CIAM through Jafly ports and adapters.

## Boundaries

Keycloak owns credentials, authenticators, identity sessions and identity-provider links in a dedicated PostgreSQL database. Core owns business customer, party and employee records through Spring Data. Experience calls Domain, which calls Core through genuine producer-generated SDKs. This distribution does not manufacture those SDKs or move business records into identity attributes.

Authentication, coarse identity roles and business authorization are separate. Security Center must use the genuine Jafly principal and policy interfaces. A role must never itself confer banking authority. Platform tenant namespaces must be resolved through the current Configuration tenant-resource binding before accessing Core resource UUIDs. Machine OAuth and signed human delegation must preserve issuer, audience, authorized/delegating client, subject and tenant checks. Untrusted headers do not establish identity.

Customers, workforce and administrators have distinct entry points and trust boundaries. Each institution receives its own realm boundaries; the master realm is administrative only. Example client names are sandbox names until current ecosystem contracts are verified. Server-managed linkage attributes cannot be edited during registration or profile updates. Provisioning and unlinking require approved business APIs, audit and revocation.

## Distribution

Pin Keycloak 26.8.1 and actual image digests. Use supported inherited login, account and admin themes, retaining upstream authentication logic and form semantics. Override presentation and transactional email layout, not protocol behavior. Include login, registration, verification, reset, required actions, OTP/passkeys/recovery, logout, errors and account management through inheritance. Record the inherited flow coverage and verify it on the server before claiming runtime acceptance.

The visual system follows the actual Firefly brand kit and koinon/liquidOS reference assets. Original editable vector geometry supplies the product symbol and lowercase wordmark. Self-host Manrope with its OFL license. Provide light, dark, monochrome and tiny-size variants. Operate-mode screens prioritize legibility, a clear action and accessible recovery paths.

The sandbox uses newly owned local resources and synthetic mail only. It has no hardcoded production credentials. Browser and container requests use the same validated issuer. Production configuration requires explicit hostname, TLS/proxy trust, secret injection, dedicated DB grants, redirect allowlists and operations review. No default production deployment is performed.

## Acceptance and resource constraints

Source validation, packaged theme, hosted CI, installed distribution, real server/browser/OIDC flow, Jafly integration and customer/production acceptance are separate evidence levels. Mutable Keycloak events do not prove immutable audit or compliance.

The initial disk floor is 12 GiB; ongoing floor is 8 GiB. Below the initial floor, do source/config/brand work only. Do not download images, start stacks or remove unrelated storage. Preserve newly owned resources and evidence until an explicit cleanup is authorized. Real integration acceptance remains pending until a safe resource window exists.
