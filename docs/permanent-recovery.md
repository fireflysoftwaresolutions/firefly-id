# Account locks and restoration

The default authentication policy permanently blocks ordinary authentication after three recorded failures. There is no timed release. Someone who remembers the current password and still controls the enrolled authenticator can use the configured known-factor unlock. Someone who has lost either factor needs [credential-loss recovery](credential-loss-recovery.md).

## Configure permanent blocking

For the supported Keycloak 26.8.1 deployment, the selected realm policy uses:

| Setting | Value |
| --- | --- |
| `bruteForceProtected` | `true` |
| `permanentLockout` | `true` |
| `failureFactor` | `3` |
| `maxTemporaryLockouts` | `0` |
| `quickLoginCheckMilliSeconds` | `0` |

An ordinary successful authentication before the permanent block resets applicable failures. After the permanent threshold, the native state is disabled with reason `permanentLockout`; waiting does not enable it.

For managed native realms, select the `firefly-native-recovery` brute-force provider as described in [native installation](native-recovery.md). It records the lock transition needed by recovery. Install the native components before relying on this behavior.

## Restore the appropriate restriction

| Restriction | Authorized restoration |
| --- | --- |
| Captured permanent authentication lock; current password and enrolled TOTP available | [Known-factor unlock](native-recovery.md) |
| Eligible permanent authentication lock; password or authenticator lost | Independent proofing followed by [credential replacement](credential-loss-recovery.md) |
| Administrative, fraud, compliance or employment hold | The authority that placed the hold, using its approved procedure |
| Support PIN held after verification failures | Authenticated [PIN replacement or revocation](support-pin.md); this does not change an account lock |

Deleting an attack-detection failure record is not the same as enabling a disabled user. Resetting a password is also not a lock-restoration decision. Do not combine generic administrative reset-password and enable calls into a public recovery flow. The native listener rejects generic administrative re-enablement of a tracked authentication lock.

Known-factor unlock preserves the password and authenticator. Credential-loss recovery replaces them and, when appropriate, clears the eligible authentication lock in the same native transition. Neither route overrides another hold.

## Help a person who cannot continue

Ask which recovery capability they can still use; never ask them to reveal a password, authenticator code or PIN to an operator. Give the appropriate recovery URL or direct them to the owner of an excluded identity or hold.

Expired requests, changed credentials or identity links, invalidated account state and exhausted limits refuse continuation. A new browser request does not clear retained budgets. Use the approved escalation procedure when the person cannot complete self-service; no public counter-reset or assisted-verification endpoint is supplied.

Sign-in and recovery messages remain generic. Configure source-abuse controls and the institution's required warning and notification procedures separately; do not rely on an explanatory paragraph or remaining-attempt counter in the login form.

## Sessions and application access

Successful native restoration retires online and offline sessions and advances the user's not-before time. The person must authenticate again. Applications must also enforce their own current identity and business authorization rules.

An already issued self-contained access token may remain acceptable to an application that validates it offline until expiry. Session retirement alone does not guarantee immediate rejection at every receiving service. Configure receiving-service controls and token lifetimes according to the application's requirements; see [zero trust](zero-trust.md).

Workforce credentials owned by a corporate identity provider remain that provider's responsibility. Master and privileged administrators require a separate privileged recovery procedure. Customer proofing and customer support PINs do not provide an administrative recovery path.
