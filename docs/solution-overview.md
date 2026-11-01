# Components and responsibilities

Choose the Firefly Identity modules that match the journeys you want to provide. The standard distribution handles application sign-in and account management. Optional native modules add secure unlock, a customer support PIN and recovery after credential loss.

## Standard distribution

| Component | Responsibility | Configuration |
| --- | --- | --- |
| Keycloak | Authentication, credentials, factors, realm/client settings and identity sessions | [Server and realm settings](configuration-reference.md) |
| Dedicated PostgreSQL database | Persistent identity, credential and session state | [Deployment](operations.md) |
| Firefly themes | Login, logout, account, administration, email and welcome presentation | [Theme installation](themes.md) |
| Policy catalogue | Password, lockout and session defaults by population | [Authentication policies](authentication-policies.md) |
| Local environment tools | Example realms, clients, users, mail sink and owned service lifecycle | [Getting started](getting-started.md) |

The standard distribution can operate without native recovery. Applications connect using OpenID Connect rather than calling a Firefly-specific password API. They discover the issuer, redirect to sign-in, exchange an authorization code and validate tokens at their own API boundary.

## Optional recovery components

| Component | Responsibility | Needed for |
| --- | --- | --- |
| Native recovery provider | Local factor checks, lock tracking, protected ceremonies and credential/session changes | Existing-factor unlock, support PIN and credential replacement |
| Domain gateway | Authenticated communication between the native provider and Domain SCA | Existing-factor unlock |
| Domain/Core SCA services | Purpose-bound challenges and authorization for existing-factor unlock | Unlock with remembered password and enrolled authenticator |
| Core KYCB | Authoritative verification records, recovery cases, grants and execution references | Recovery after losing credentials |
| Customer KYC/KYB Domain | Integrates the selected verification provider and coordinates the customer journey | Independent identity verification |
| Notification worker | Dispatches and supervises notices recorded with a credential change | Recovery notifications |

These services have separate credentials and responsibilities. Identity owns passwords, authenticator state and native account restrictions. Core owns business records and recovery authority. Domain coordinates the appropriate service and provider. A successful browser redirect or a machine credential does not substitute for the owner's authorization.

Install the native provider and its database changes before enabling native behavior. The supplied native image bundles both provider JARs; credential-loss communication with customer Domain is implemented inside the native recovery provider. Configure the endpoints, workload identities, origins and keys for the selected journey. Select `firefly-id-native` login only when offering existing-factor unlock, and its customer account theme when offering support PIN management. Configured credential-loss recovery is available from the ordinary `firefly-id` login theme. See [native installation](native-recovery.md) and [credential-loss recovery](credential-loss-recovery.md).

## Identity populations

| Population | Use | Business link |
| --- | --- | --- |
| Customers | Customer-facing applications and account self-service | Protected `party_id` |
| Workforce | Employee terminals and back offices | Protected `staff_actor_id` |
| Administrators | Identity service administration in the master realm | Named privileged identity and assigned administrative roles |
| Services | Noninteractive service-to-service operations | Explicit client identity and narrowly scoped authority |

Keep separate issuers, user stores and policies for customer and employee identities. Use stronger instance/database isolation when your operating model requires it. Provision party, staff and tenant links through trusted administrative processes; never derive them from an email address or a browser header.

## Application responsibilities

Every API validates the incoming token's signature, issuer, audience and lifetime. Every receiving Experience, Domain and Core service then authorizes the requested operation using its current policy and authoritative business relationships. These responsibilities apply regardless of the application language or framework. Experience, Domain and Core describe the optional platform integration; applications do not need that service topology to use Identity.

Read [architecture](architecture.md) for the diagrams, [application integration](integration-contract.md) for protocol steps and [zero trust](zero-trust.md) for service-boundary checks.
