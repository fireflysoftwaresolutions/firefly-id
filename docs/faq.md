# Frequently asked questions

## How do I start using Firefly Identity?

Run the [local evaluation environment](getting-started.md), then register an application against the customer or workforce issuer. Use [Integrate an application](integration-contract.md) for discovery, authorization code with PKCE, token validation and logout. For a hosted environment, follow [deployment](operations.md) before provisioning real clients or users.

## Is Keycloak required?

Yes. Firefly Identity packages themes, policies and optional native modules around Keycloak. Applications connect using standard OIDC interfaces. Any application framework supporting the configured OIDC profile can integrate; no Firefly framework is required.

## Which components do I need?

The ordinary distribution needs Keycloak, a dedicated PostgreSQL database, its Firefly theme and configured realms/clients. Native unlock and support PIN additionally need the native provider. Credential-loss recovery needs the separate recovery services and trusted verification adapter. The [component guide](solution-overview.md) explains each selection.

## How are customers and employees separated?

Use separate realms, issuers, stores and policies. Customer identities carry a protected party link; workforce identities carry a protected staff link. Keep privileged administration in the master realm behind private administration access. See [workforce and administration](workforce-administration.md).

## Does a customer login always require MFA?

The evaluation customer profile allows password-only authentication; the workforce browser flow requires password and TOTP for fresh authentication. Configure the factor/enrollment and step-up policy required by your customer journeys. See [authentication policies](authentication-policies.md).

## Why does an account stay blocked after waiting?

The selected policy permanently disables ordinary access after three recorded failures. There is no timed release. A secure recovery operation must authorize the current lock transition. A password reset or counter change is not a substitute. See [permanent blocking](permanent-recovery.md).

## Which recovery journey should I offer?

Use existing-factor unlock when the person remembers the password and still has the enrolled authenticator. Use independent credential-loss recovery when those factors are unavailable. Administrative or fraud restrictions go to the authority responsible for the restriction. The [recovery selection guide](access-recovery.md) diagrams these choices.

## How can someone recover without the old password?

The [credential-loss flow](credential-loss-recovery.md) first obtains independent identity verification through the configured third-party adapter. The customer then chooses a new password and enrolls a new TOTP. The native transition retires old credentials, PIN and sessions and records a notification.

## Where do I configure a verification provider?

Deploy the customer Domain adapter for the selected provider and configure its origin, workload credentials and authoritative customer binding. Core KYCB retains the verification/recovery records; Identity retains credentials. Follow [Connect identity verification](assurance-provider-contract.md). Firefly Identity does not embed a documentary or biometric verification engine.

## Is email verification enough to unlock a blocked account?

No. It establishes control of an email channel for that action. Unlock requires its configured factors and purpose-bound authorization; credential replacement requires independent identity evidence. A KYC flag or browser redirect is also insufficient.

## Can employees use customer credential-loss recovery?

No. Local-customer credential replacement is separate from employee and administrator recovery. Use the workforce credential owner's process and preserve employment/privileged restrictions. See [workforce administration](workforce-administration.md).

## Can a support PIN authorize a payment or impersonation?

No. It is a customer knowledge credential for a narrowly authorized support process. Customer lifecycle actions require fresh password/TOTP proof. Support verification requires an integrated case/call authorization provider; the PIN alone supplies neither possession proof nor staff delegation. See [support PIN](support-pin.md).

## Does logout immediately invalidate all access tokens?

It ends the relevant server/application session, but an already issued self-contained JWT can remain cryptographically valid until its lifetime ends. APIs must implement their chosen current-state/revocation and application-session behavior. See [token audiences](receiver-audiences.md) and [zero trust](zero-trust.md).

## Can I copy the example environment into production?

Provision production domains, certificates, clients, secret-manager inputs, policies and database roles deliberately. The local environment uses synthetic identities, HTTP convenience and a mail sink. Its generator creates new evaluation state and does not provision production realms. Use [regulated deployment](regulated-deployment.md) and [configuration audit](production-readiness.md).

## How do I upgrade an existing installation?

Build immutable artifacts for the supported server version, restore a copy of the existing state into an isolated environment, rehearse migrations and verify authentication/recovery before switching traffic. Keep the matching keys and service configuration. [Retained data and recovery](retained-data.md) explains the sequence.

## Will disabling native recovery avoid a schema migration?

No. Installing the native JAR registers its database mappings at server startup. Enablement controls behavior; installation changes persistence. Rehearse installation separately from enabling a journey. See [native installation](native-recovery.md).

## What should an operator do after an interrupted recovery?

Reconcile the original case, grant and execution journal through the authorized owner interfaces. Do not create another approval, reset attempts or replay factors to resolve an uncertain response. For delivery failures, use the outbox monitoring and escalation procedure in [notification operations](notification-operations.md).

## How do I customize the interface?

Edit the supported theme resources, rebuild the theme package and exercise the affected server journeys in both languages and appearances. Preserve action URLs, tokens, CSRF and authenticator behavior. Start with [themes](themes.md), [tokens](design-tokens.md) and [language settings](localization.md).

## Is the product automatically compliant with every banking rule?

Compliance depends on the institution, activity, jurisdictions and operated configuration. Use the [EU/US controls guide](controls-matrix.md) to identify applicable requirements, then configure and validate the required factors, recovery, data handling and operations with the responsible owners.
