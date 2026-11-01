# Email verification, profile and authenticator journeys

Firefly Identity uses Keycloak's normal account and required-action flows for email verification, profile changes and authenticator enrollment. These are ordinary identity journeys, separate from [known-factor unlock](native-recovery.md) and [credential-loss recovery](credential-loss-recovery.md).

## Verify an email address

An operator can enable realm `verifyEmail` policy or assign the `VERIFY_EMAIL` required action to a user. Configure the realm's real email provider, sender identity and action-token lifetime before requiring verification.

The person signs in and follows the verification instruction. Identity sends a server-generated link to the configured email address. Opening that link completes the server's verification step; the person may need to return to the original sign-in tab to finish authentication.

| Input | Successful result | If it cannot complete |
| --- | --- | --- |
| Current account session or sign-in flow, plus server-generated verification link | Email is marked verified; the normal authentication flow can continue | Expired, consumed or invalid links require the appropriate resend/sign-in flow; they do not grant a session by themselves |

Applications should validate signed tokens and examine `email_verified` where required by their product policy. A verified mailbox does not establish a bank customer identity, legal mandate or recovery authorization. Do not interpret an already consumed link as another successful verification grant.

When delivery is delayed, use the native resend control if available. Check the configured email service and token lifetime rather than editing action URLs or enabling a disabled account. Keep action links private and out of logs, tickets and screenshots.

## Manage profile information

Use the account console from an authenticated online session. The operator's user-profile policy determines which fields a person may edit and which require verification or another action.

Protect `tenant_id`, `party_id`, `staff_actor_id`, `principal_kind` and `client_id` as server-owned identity metadata. Do not expose tenant or customer/workforce linkage as public profile inputs. Unknown unmanaged attributes must not become a route to shadow security claims.

Applications use the issuer and subject as the identity reference, then apply current business authorization. Customer and workforce tokens remain separate: customers use `principal_kind=HUMAN` and their party linkage; workforce uses `principal_kind=STAFF` and its staff linkage. A changed display name or email must not relink an account to another party.

Changing a verified notification destination or other protected recovery state invalidates unfinished credential-loss work. Existing committed notices retain the previous verified destination. See [recovery notifications](notification-operations.md).

## Enroll and use an authenticator

Configure the realm's OTP policy and required authentication flow on the server. Assign `CONFIGURE_TOTP` where enrollment is mandatory. Hiding or showing a theme control does not enforce MFA.

The person opens the server's setup form, adds its server-generated account/key to an authenticator, and proves a code before finishing. Keep the secret private. On later sign-in, use a fresh code from the retained authenticator rather than creating another factor automatically.

The normal supported setup displays the realm's policy. The native credential-loss enrollment specifically supports `HmacSHA1`, `HmacSHA256` or `HmacSHA512`, 6–8 digits, periods from 1 to 300 seconds and a configured clock window from 0 to 10 steps, with nonreusable codes. Its [replacement form](credential-loss-recovery.md#customer-steps) displays the actual algorithm, digits and period.

An incorrect or reused code refuses authentication. Check the account selected in the app, algorithm/digits/period, device time synchronization and whether a fresh interval is needed. Do not remove or reset an enrolled credential merely because the app's secret is unavailable; choose the appropriate recovery journey.

Workforce MFA must be required by the workforce realm flow and policy. A customer's authenticator or recovery case cannot restore an employee. Credentials managed by an external corporate identity provider remain that provider's responsibility.

## Integrate ordinary sign-in

Use authorization code with PKCE S256, validate issuer/audience/signature and keep redirect URLs exact. Handle required-action screens as part of the server's browser flow; do not fabricate successful email verification or MFA claims in an application.

Account management and support PIN pages require an online SSO session. Request `offline_access` only for an approved offline-token use case; an initial offline exchange may remove the temporary online session, so a returned token alone does not establish account-console access.

Passkey/WebAuthn, recovery-code enrollment, external credential-store recovery and privileged/workforce lost-factor recovery are not supplied by the customer credential-loss path. Configure any separate capability with its actual identity owner and supported deployment procedure. Successful identity authentication is not payment consent or business authorization; see [zero trust](zero-trust.md).
