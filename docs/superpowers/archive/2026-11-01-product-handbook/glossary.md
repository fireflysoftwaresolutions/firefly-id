# Glossary

These terms describe this implementation. A protocol term, a product policy and a legal assurance level are different kinds of statement; sharing a word does not make their acceptance interchangeable.

## Identity and application protocols

| Term | Meaning here |
| --- | --- |
| CIAM | Customer identity and access management: customer authentication, identity sessions and related account journeys. Business permissions remain with their owners. |
| Issuer (`iss`) | The exact trusted authority that issued the token, including the realm path. Treat `(verified issuer, opaque subject)` as the identity key. |
| Subject (`sub`) | Opaque identity reference within the issuer. Do not require a UUID or substitute an email address. |
| Realm | A logical Keycloak identity/configuration boundary with its own issuer and users. It is not evidence of independent operational/database isolation. |
| OIDC | OpenID Connect: the identity protocol used for application sign-in. Its ID token and an API access token have different recipients/purposes. |
| Authorization code and PKCE S256 | Interactive flow where the client exchanges a bounded code using a verifier bound to a SHA-256 challenge. Generated examples disable direct password and implicit grants. |
| Audience (`aud`) | Intended token receiver. A valid token for one API is not authority at another API. |
| JWKS | Public signing-key set used by the configured receiver to verify tokens. Fetching keys does not replace issuer, audience, algorithm or time validation. |
| Introspection | Authenticated query to the issuer about a token's active state. Correct receiver use and current-state behavior require their own integration contract. |
| Identity session | Server-owned authenticated context. Logging it out does not by itself demonstrate immediate rejection of a self-contained JWT at every receiver. |
| Required action | Server-enforced enrollment/profile/verification step, such as `CONFIGURE_TOTP` or `VERIFY_EMAIL`; it must not be bypassed by presentation code. |
| Workload identity | Authentication of software calling a service. It does not establish a human actor or business permission. |
| Jafly | Independent provider-neutral application framework. Its generic security mechanisms can consume qualified Identity tokens without acquiring an Identity/native-provider dependency. |

Read [provider claims](provider-claim-profile.md), [receiver audiences](receiver-audiences.md) and [Jafly integration](jafly.md) for actual formats and examples.

## Business identity and authority

| Term | Meaning here |
| --- | --- |
| Identity tenant namespace | Issuer-scoped opaque `tenant_id` string. Preserve it separately from the Configuration-owned resource-tenant UUID. |
| Party link | Server-managed `party_id` connecting a customer identity to an authoritative business party. It is not an account permission or financial mandate. |
| Staff actor link | Server-managed `staff_actor_id` connecting workforce identity to its authoritative employee actor. Current employment and delegated permissions remain separate decisions. |
| Principal kind | Verified population classification, such as `HUMAN`, `STAFF` or an explicitly provisioned `MACHINE`; it is not a business role. |
| KYC/KYB | Know-your-customer/know-your-business records and verification processes. Core KYCB is the system of record; customer Domain integrates the independently selected third-party provider. |
| System of record | Authoritative owner of the relevant business state. Identity owns credentials; it does not become the KYC, employment, banking or consent ledger. |
| Identity proofing / reproofing | Independent evidence establishing or re-establishing the actual identity under an approved policy. A redirect, email match or browser-supplied approval is insufficient. |
| Mandate / representative authority | Current legal/business permission for someone to act for an entity. Authenticating a person or verifying a company does not establish it automatically. |
| Consent | Purpose- and operation-relevant permission owned by the applicable business/privacy process; login is not consent. |
| PDP | Policy decision point used for current action/resource authorization. Each receiver must fulfill obligations or refuse an indeterminate decision. |
| Delegation | Bounded authority for the real staff/human actor to perform an allowed operation for another party. Machine authentication and customer PIN knowledge cannot create it. |
| BPO | Business process outsourcing; here, assisted customer-support/call-center work. Its genuine case/call authorization owner is not integrated. |

See [architecture](architecture.md), [zero trust](zero-trust.md) and [workforce administration](workforce-administration.md) for ownership and lifecycle.

## Factors and recovery

| Term | Meaning here |
| --- | --- |
| MFA | Multiple-factor authentication. Generated customer MFA is optional; fresh workforce browser authentication requires password and TOTP. Factor independence and purpose still require assessment. |
| TOTP | Time-based one-time password from an enrolled authenticator. Knowledge of a password and proof of an already enrolled TOTP support the native known-password unlock; enrolling a new factor is a different operation. |
| Phishing-resistant MFA | Authentication designed to resist verifier impersonation. It remains a permanent-administrator production gate; workforce TOTP does not establish it. |
| SCA | Strong customer authentication in its applicable payment/legal context; also the name of the separate Core/Domain authorization service candidates. Neither the service name nor a generic login proves regulatory SCA. |
| Permanent authentication lock | Selected product policy disabling ordinary authentication after three recorded failures, without timed release. The number is not a universal legal requirement. |
| Hold | Administrative, fraud, compliance or employment restriction owned by its actual authority. Self-service unlock cannot remove it. |
| Known-password unlock | **Unlock your account**: prove the remembered password and previously enrolled TOTP, authorize the current native lock transition, then sign in freshly. It does not replace forgotten credentials. |
| Credential-loss recovery | Separate local-customer candidate using independent Core KYCB/customer Domain proofing authority to replace supported password/TOTP credentials without the previous password. Real-provider approval remains pending. |
| Support PIN | Separate customer knowledge credential for narrowly authorized telephone support. Not possession evidence, payment permission, unlock authority or workforce delegation. |
| Ceremony | Short-lived server-owned browser transaction bound to a protected cookie, exact origin and rotating CSRF state. Its page URL alone is not authority. |
| Lock generation / credential revision | Native state bindings preventing a proof or receipt from authorizing a different lock or changed credential state. |
| Recovery grant / consumed receipt | Purpose-bound one-time authority and the owner's verified record of consumption. Ordinary tokens or an asserted status cannot substitute for them. |
| Native execution journal | Durable canonical record of the actual native mutation. Interrupted recording must reconcile this original execution without replaying factors, consuming another grant or resetting budgets. |

Read [access journeys](access-recovery.md), [native unlock](native-recovery.md), [credential loss](credential-loss-recovery.md) and [support PIN](support-pin.md) before selecting a recovery path.

## Operations and evidence

| Term | Meaning here |
| --- | --- |
| Default-off | Explicit opt-in is required for a feature. Installing native JARs can still register database mappings; feature disablement is not a migration switch. |
| Outbox | Durable notification intent recorded with native execution. Dispatch is at least once; a crash after SMTP acceptance may produce a duplicate notice. |
| Poller / monitor | Separate Core notification worker and separately authenticated private supervision surface. Credentials and route authority differ from ceremony/evidence clients. |
| Retained state | Existing identity/business databases, secrets, journals and budgets kept across attempts/restarts. A fresh fixture is not a migration or repair of it. |
| Qualification | Evidence for exact inputs and bounded controls. Source tests, packaged artifacts, real synthetic integration and external production acceptance are separate facts. |
| Fixture | Synthetic test data/process. The signed proofing fixture is test-classpath-only and excluded from production JARs; it is not an approved provider. |
| RTO / RPO | Recovery time and recovery point objectives. They need an operated, rehearsed end-to-end topology; an image build or single-process restart is insufficient. |
| eIDAS design baseline | The selected assurance design reference. It does not mean a qualified trust service, approved proofing vendor or certified product. |
| Regulatory applicability | Whether a particular obligation covers the actual entity, activity, data and jurisdiction. Test success cannot decide that scope or establish legal certification. |

[Progress](progress.md) records exact current receipts and history. [Operations](operations.md) covers deployment preparation; the regulated-deployment and control-mapping guides distinguish obligations, supervisory guidance and technical references.
