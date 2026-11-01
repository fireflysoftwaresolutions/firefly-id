# Glossary

## Identity and protocols

| Term | Meaning |
| --- | --- |
| CIAM | Customer identity and access management: sign-in, identity sessions, account management and related recovery journeys. |
| Realm | Keycloak identity/configuration boundary with its own issuer, users and policies. |
| Issuer (`iss`) | Exact trusted token authority, including the realm path. |
| Subject (`sub`) | Opaque person or service reference within an issuer. Use issuer and subject together as the identity key. |
| OIDC | OpenID Connect, the application sign-in protocol. |
| Access token | Token presented to an API. Its audience, scopes and current authorization determine how the receiver may use it. |
| ID token | Authentication result for the client; not an API access token. |
| Audience (`aud`) | Intended token receiver. |
| PKCE S256 | Binds an authorization-code exchange to a client-generated verifier through a SHA-256 challenge. |
| JWKS | Public signing-key set used to verify token signatures. |
| Introspection | Authenticated issuer query about a token's active state. |
| Required action | Server-enforced verification or enrollment step, such as verifying email or configuring TOTP. |
| Workload identity | Authentication of a service calling another service. |

See [application integration](integration-contract.md), [claims](provider-claim-profile.md) and [audiences](receiver-audiences.md).

## Business authority

| Term | Meaning |
| --- | --- |
| Tenant namespace | Issuer-scoped identity namespace carried in `tenant_id`; preserve its opaque value. |
| Resource tenant | Business-resource tenant resolved through its authoritative owner; may use a different identifier type. |
| Party link | Protected `party_id` connecting a customer identity to a business party. |
| Staff link | Protected `staff_actor_id` connecting workforce identity to an employee actor. |
| Principal kind | Identity classification such as `HUMAN`, `STAFF` or `MACHINE`. |
| Policy decision point | Service that decides current access to an action and resource. |
| Delegation | Bounded authority for the real person or staff actor to perform an operation for another party. |
| Mandate | Current legal/business permission to act for an entity. |
| KYC/KYB | Know-your-customer/know-your-business records and verification processes. |
| System of record | Authoritative owner of the relevant state. Core KYCB owns verification records; Identity owns credentials. |
| BPO | Outsourced customer-support or backoffice operations using an explicitly authorized staff/case/call context. |

See [architecture](architecture.md) and [service-boundary authorization](zero-trust.md).

## Factors and recovery

| Term | Meaning |
| --- | --- |
| MFA | Authentication using independent factor categories under the selected flow. |
| TOTP | Time-based one-time code from a previously enrolled authenticator. |
| Phishing-resistant factor | Authentication designed to resist verifier impersonation, such as an appropriately configured WebAuthn credential. |
| SCA | Strong customer authentication in the applicable payment context; factor success alone does not establish every legal requirement. |
| Permanent lock | Ordinary authentication is disabled until a secure recovery transition authorizes restoration. |
| Hold | Administrative, employment, fraud or compliance restriction managed by its own authority. |
| Existing-factor unlock | Prove the remembered password and enrolled TOTP to unlock the current authentication block. |
| Credential-loss recovery | Independently verify a local customer's identity before replacing supported password/TOTP credentials. |
| Support PIN | Separate customer knowledge credential for an authorized support process. |
| Ceremony | Short-lived server-owned recovery transaction with origin, cookie and one-use request protections. |
| Lock generation | Binding that prevents authorization for an old lock from unlocking a different lock. |
| Recovery grant | Purpose-bound one-time authorization from the recovery owner. |
| Execution journal | Durable record of the native transition, used to reconcile an interrupted response without repeating the operation. |

See [recovery journeys](access-recovery.md) and [support PIN](support-pin.md).

## Operations

| Term | Meaning |
| --- | --- |
| Outbox | Durable notification intent recorded with the credential transition. |
| At-least-once delivery | Delivery may be retried; a crash after SMTP acceptance can produce a duplicate notice. |
| Poller | Optional worker that dispatches outbox work in bounded cycles. |
| Retained state | Existing databases, keys, journals, credentials and budgets preserved across upgrades and recovery. |
| RTO / RPO | Recovery time and recovery point objectives for the operated system. |
| Bootstrap administrator | Temporary account used to establish permanent privileged administration. |

See [deployment](operations.md), [notifications](notification-operations.md) and [backup/restore](retained-data.md).
