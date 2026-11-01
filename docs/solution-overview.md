# Solution overview

Firefly Identity is a branded Keycloak distribution with dedicated identity storage, a synthetic evaluation environment and explicit application contracts. Its optional native package adds tightly scoped account-unlock, support-PIN and local-customer credential-loss protocols. The normal distribution and those extensions have separate installation and acceptance boundaries.

Start here to locate the owner of a decision. Use [architecture](architecture.md) for the full trust/lifecycle model and the linked component guides for configuration and operation.

## Component inventory

| Component | What it owns | Authoritative implementation or guide |
| --- | --- | --- |
| Keycloak 26.8.1 | Local identity credentials, authenticators, realm/client configuration, authentication and identity sessions | [Pinned images](../deploy/images.lock.json), [operations](operations.md) |
| Dedicated identity PostgreSQL | Keycloak state and optional native execution/replay/outbox records | [Deployment initialization](../deploy/postgres/init.sh), [native recovery](native-recovery.md) |
| `firefly-id` theme | Login/account/admin/email/welcome presentation and EN/ES custom copy | [Theme architecture](themes.md), [localization](localization.md) |
| Sandbox generator | New synthetic realms, clients, random credentials and owned Compose resources | [Generator](../scripts/generate.py), [sandbox guide](sandbox.md) |
| Policy catalogue | Explicit population defaults and application mode | [Catalogue](../config/authentication-policies.json), [policy explanation](authentication-policies.md) |
| Native recovery JAR and Domain gateway JAR | Local factor checks, purpose-bound ceremonies, current-state mutation and durable execution evidence; bounded calls to the actual Domain owner | [Installation/protocol](native-recovery.md) |
| Core SCA and Domain SCA candidates | Separate known-password unlock authorization, independent factor challenges and orchestration | [Permanent recovery](permanent-recovery.md), [integration contract](integration-contract.md) |
| Core KYCB and customer Domain candidates | KYC/KYB records, recovery cases/grants and notification supervision in Core; independent third-party adapter/orchestration in Domain | [Credential-loss recovery](credential-loss-recovery.md) |
| Application receivers and Jafly | Per-service token/principal validation and current action/resource authorization through provider-neutral mechanisms | [Jafly fixture](jafly.md), [zero trust](zero-trust.md) |

Mailpit is a local synthetic SMTP sink. It is not a production notification provider. The ordinary distribution can be used without native recovery; selecting a theme that advertises native recovery requires its actual endpoints and owners.

## Follow one ordinary request

The following is the receiving-service integration contract. The repository's fixtures prove the bounded paths recorded in [progress](progress.md); they do not establish adoption by every Experience, Domain or Core service.

1. A customer opens an application. The application creates an authorization-code request using PKCE S256 and its exact registered callback; the issuer authenticates the person according to the selected realm's policy.
2. The client exchanges the returned code and validates the protocol response. A browser client has no distributed client secret; a confidential interactive backend has its separate client credential. Neither uses the password grant in the generated examples.
3. The receiving API verifies the access token's signature, exact trusted issuer, intended audience, approved algorithm and time constraints. It preserves the opaque subject and issuer-scoped tenant namespace rather than guessing a UUID or inferring membership from an email domain.
4. Experience calls Domain; Domain calls Core through the genuine producer SDK. Each receiver authenticates its incoming caller and authorizes its own operation. Where required, approved signed human proof travels separately from machine authentication.
5. Core resolves authoritative business relationships, current policy and the Configuration-owned resource-tenant binding before reading or changing business state. An identity role or `party_id` is insufficient permission to operate on a bank account.

For example, a signed customer identity may contain an opaque `tenant_id`, `principal_kind=HUMAN` and a server-managed `party_id`. That identifies a candidate actor and linkage. A payment service must still determine which account the actor may use, whether consent is valid and whether the operation's required assurance has been met. The [issued-claim profile](provider-claim-profile.md) explains actual token shapes; the [receiver guide](receiver-audiences.md) explains audience boundaries.

## Keep four decisions distinct

| Decision | Owner and evidence | What does not establish it |
| --- | --- | --- |
| Who authenticated? | Identity issuer and validated authentication evidence | An unverified header or email address |
| Which customer or employee is linked? | Authoritative party/staff owner and protected identity linkage | Self-edited profile data or a realm name |
| Is the person/entity verified, and may a representative act? | Core KYCB records and approved independent evidence/mandates | Email verification, MFA or a generic KYC flag alone |
| May this action affect this resource now? | The receiving business service, current policy, consent and applicable assurance | Login, machine authentication or a support PIN alone |

Core KYCB is the KYC/KYB system of record. Customer Domain integrates the future third-party verifier. No documentary/biometric engine is selected or installed, and the structured assurance envelope and representative-authority acceptance remain external work. eIDAS is a design baseline, not a qualification claim. Jafly has no new dependency on Identity, Keycloak or that future provider.

## Population and operational boundaries

Customer MFA is optional in the generated synthetic profile. Workforce password and TOTP are required by a dedicated browser flow. Permanent administrators need a separately qualified phishing-resistant MFA policy and private administrative ingress; the temporary sandbox bootstrap account is not that qualification. Institutional sample humans do not acquire institutional signing authority or machine identity from their realm.

The selected authentication policy permanently blocks ordinary login after three recorded failures. That is a product policy, not a universal legal threshold. A remembered password plus an already enrolled TOTP can support the separate native unlock ceremony. Forgotten/lost credentials require the independent customer proofing path; workforce loss and privileged recovery have separate owners. [Choose the right access journey](access-recovery.md) before configuring recovery links.

The generator deliberately refuses `--mode production`. Its HTTP URLs, local secrets, SMTP sink and synthetic links demonstrate behavior only. [Production configuration](../deploy/keycloak.production.conf.example) is a reference: approved topology, issuer/client contracts, TLS, secrets, bootstrap retirement, migration, restore and operating procedures are still required. Installing native JARs can register additive database mappings even while the feature is default-off; review the [installation warning](credential-loss-recovery.md#installation-and-evidence-boundaries).

## Read qualification at its actual scope

The current runtime-qualified Identity source is `15fd1b7ffa045835f3d4c71fdcc33020d8f24ecf`. Two separate integration lanes passed:

| Lane | Exact service candidates | Bounded result |
| --- | --- | --- |
| [Credential loss and notification supervision](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41332055134) | Core KYCB `26c3b142c66d4d9ad3a0cc9619d476f2b9d24261`; customer Domain `68fa0b7fc849dd3e4dab7756493e344a331bb478` | 25 controls, zero failures; test-only signed proofing and actual synthetic notification/restart behavior |
| [Known-password unlock and customer PIN](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331177242) | Core SCA `cc826d27cd05dac831989ec872d78a8c17e88e8b`; Domain SCA `3cf19a0d2a6baa1e13ad92dc7014b91490996ac4` | 48 controls, zero failures; separate customer/workforce, unlock, concurrency, session retirement and PIN lifecycle |

These service pairs are different contracts. Do not substitute KYCB pins for the SCA lane or promote documentation changes into a new binary qualification. [Progress](progress.md) retains exact receipts, native hashes, normal-distribution/Jafly results and earlier failures. Real-provider assurance, BPO case authorization, workforce credential-loss recovery, every receiver's immediate JWT revocation, retained-database rollout and multi-node HA remain separate acceptance gates.
