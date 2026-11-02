# Security model

Firefly Identity authenticates people and workloads and manages their identity sessions. Business services own customer/employment records, tenant membership, consent and permission to act on a resource. Configure both sides when connecting an application.

## Separate identities and authority

Keep customers, workforce and institutional humans in distinct realms with their own clients, credentials and policies. Keep privileged administration private and separate. Use separately operated instances/databases when an institution requires stronger isolation than a logical realm.

Identify a person by the exact verified `(issuer, subject)` pair. Preserve the opaque subject; username/email may change. The protected `tenant_id`, `party_id` and `staff_actor_id` links come from authoritative provisioners, not a browser form or email match.

The generated user profile disables unmanaged attributes and makes those links administrator-owned. Customers/institutional humans receive `party_id`; workforce receives `staff_actor_id`. Controlled mappers emit `principal_kind` and the example client ID. These business-reference mappers affect access tokens, not ID tokens or userinfo. Ordinary profile editing must not create another population or tenant relationship.

Give provisioners only the administrative permissions they need. Do not grant end users manage-users, manage-clients, impersonation or role-mapping authority. Review broker/registration mappings before enabling them so that external attributes cannot overwrite trusted links.

## Protect application entry points

Use authorization code with PKCE S256, state/nonce and exact callback/logout allowlists. Disable password and implicit grants for the interactive profile. Register machine clients separately; the optional [Configuration lookup](configuration-service-client.md) profile authenticates a MACHINE without becoming a human delegate.

Each receiver must verify signature, approved algorithm, exact `iss`, intended `aud`, expiry and applicable not-before, then authorize the current tenant/action/resource. Reject tokens from another population even if a username or tenant value matches. Short token lifetime limits exposure but does not make a blocked user's existing JWT immediately invalid at an offline receiver. Configure the current-state and application-session behavior described in [zero trust](zero-trust.md).

## Keep recovery purpose-bound

The selected policy permanently blocks after three applicable failures. Waiting, ordinary password replacement and failure-counter deletion do not restore access. Use existing-password/TOTP unlock when both factors remain available, or the separate customer credential-loss procedure when independent proofing is required. Preserve unrelated fraud/admin/employment holds.

Customer credential loss needs a configured independent proofing adapter; workforce/admin loss needs its own credential owner. A support PIN, email link, staff login or service credential cannot supply missing recovery or financial authority. See [authentication policies](authentication-policies.md) and [recovery choices](access-recovery.md).

## Protect secrets and transport

Sandbox generation creates random credentials under an owner-only state directory. Some mounted files are mode 0644 so the non-root container can read them; credentials, Compose and ownership files are mode 0600. The host owner and Docker administrators can read local secrets. Use a real secret manager and restricted mounts for production.

The sandbox entrypoint explicitly reads mounted secrets and exports `KCRAW_DB_PASSWORD` and `KCRAW_BOOTSTRAP_ADMIN_PASSWORD`. Keycloak has no assumed generic `*_FILE` loader. PostgreSQL separately supports `POSTGRES_PASSWORD_FILE`; replacing an initialization file does not rotate a retained database password.

Use verified TLS for browser, backchannel, proxy-to-server and database connections. Keep private keys out of image layers and build arguments. Restrict `/admin/` and administrative-realm routes at ingress; an admin hostname alone does not enforce privacy. Keep management port 9000 private with HTTPS probes and restricted scrapes. [Deployment setup](regulated-deployment.md) covers the reference settings.

## Collect useful audit without secrets

Restrict identity/admin events, logs and recovery journals to authorized operators. Exclude tokens, passwords, PINs, OTP/setup secrets, action links, mail bodies and full profiles from shared diagnostics. The sandbox retains user events for seven days and omits administrative representations; set production retention and forwarding explicitly.

An enterprise immutable-audit/SIEM bridge is not supplied. Configure controlled export, custody, retention, alerting and incident ownership for the operating environment. Preserve upstream CSRF/action-token and authenticator behavior when customizing themes; presentation code does not replace server authorization.

Report vulnerabilities through the repository's [private vulnerability reporting form](https://github.com/fireflysoftwaresolutions/firefly-id/security/advisories/new). Follow the [security reporting policy](../SECURITY.md) for the information to include and how to remove sensitive data. Use [incident response](observability-incidents.md) for operational handling; a repository report does not replace the institution's incident channel.
