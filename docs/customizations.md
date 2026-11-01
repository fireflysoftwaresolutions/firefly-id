# Firefly customizations

Firefly Identity adds a consistent experience, explicit security profiles and optional recovery modules around Keycloak. This guide explains what changes, where to configure it and when to use each part.

## The identity experience

The standard `firefly-id` theme covers login, logout, required actions, account management, administration, email and welcome. It uses the protected-identity logo, self-hosted Manrope, canonical Firefly colors, functional icons and an isometric security scene. Desktop layouts pair the illustration with a focused form; narrow layouts keep the form readable with a reduced scene.

Light/dark appearance and English/Spanish copy are shared across the main journeys. Password fields remain masked without a reveal control. Authentication and recovery refusals use generic messages that do not disclose account existence or remaining attempts. Supported server-generated form actions, action tokens, CSRF and authenticators continue to control the journey.

Configure realm themes after installing the packaged theme. For visual changes, edit the theme resources, rebuild and exercise the affected server pages. See [theme installation](themes.md), [language settings](localization.md), [tokens and icons](design-tokens.md) and [brand usage](brand.md).

## Population policies

| Population | Selected password policy | Factor behavior |
| --- | --- | --- |
| Customers | 16–128 characters, history 5, Argon2 and baseline denylist | MFA is optional in the evaluation profile; select the production journey's required factors |
| Workforce | 20–128 characters, history 10, Argon2 and baseline denylist | Fresh browser authentication requires password and enrolled TOTP |
| Administrators | 20–128 characters, history 10, short administrative sessions | Configure a dedicated privileged flow and required phishing-resistant factors |

The selected blocking policy permanently disables ordinary access after three recorded failures. Waiting or replacing a password does not release the lock. Secure restoration follows a distinct recovery operation.

Clients use code with S256 PKCE and exact callback/logout addresses. Public registration, username self-editing, unmanaged profile attributes, password/direct-access grants and implicit grants are disabled in the supplied profiles. Refresh rotation uses zero reuse. Tenant, party and staff links are managed through trusted provisioning.

The [default settings reference](reference/effective-defaults.md) lists exact catalogue values. [Authentication policies](authentication-policies.md) explains application and adjustment; [configuration](configuration-reference.md) explains server, client and extension settings.

## Native recovery

Select the native module when you need secure unlock, support-PIN management or credential replacement. Its provider handles native factor checks and protected account transitions; separate owning services authorize the purpose-bound operation.

| Feature | Person's experience | Required configuration |
| --- | --- | --- |
| Existing-factor unlock | Enter remembered password and enrolled authenticator; sign in afresh after unlock | Native provider/gateway and Domain/Core SCA services |
| Support PIN | View status, create, replace or revoke an eight-digit customer PIN after fresh factors | Native customer account theme, PIN keys and customer profile |
| Credential-loss recovery | Complete independent identity verification, choose a new password and enroll an authenticator | Native provider, Core KYCB, customer Domain and trusted verification adapter |

Native recovery maintains lock generation, credential revision, short-lived ceremonies, one-use authorization and an execution journal. A self-service operation cannot remove an unrelated administrative or fraud hold. The module does not return an ordinary application session as an unlock side effect.

Installing native JARs also registers their database mappings. Plan and rehearse that installation against an isolated copy before changing an existing identity database. Configure the backend dependencies before selecting the native theme. See [installation](native-recovery.md), [credential loss](credential-loss-recovery.md) and [support PIN](support-pin.md).

## Recovery notifications

Credential replacement records notice intent with the native transition. An optional Core worker dispatches the durable outbox with separate sender and monitor credentials, bounded retry and private status/metrics. Delivery is at least once; an interrupted SMTP acknowledgement can result in a duplicate notice.

After the terminal delivery budget is exhausted, an operator follows the configured escalation procedure. Do not reset recovery authority or replay factors to resend a message. [Notification operations](notification-operations.md) explains configuration, monitoring, draining and failure handling.

## Deployment and integration

The distribution supplies optimized ordinary/native image definitions and a production server reference with verifying PostgreSQL TLS, HTTPS management and strict hostname/proxy settings. Operators supply the actual domains, trust anchors, secret-manager inputs, private ingress and database privileges.

Every receiving application service must validate its caller and authorize its own operation. Jafly remains provider neutral; native recovery and proofing adapters are separate product modules. Use [application integration](integration-contract.md), [Jafly](jafly.md), [deployment](operations.md) and [production configuration checks](production-readiness.md) to assemble the service for your environment.
