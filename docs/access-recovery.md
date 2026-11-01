# Choose the right access journey

An account lock, a forgotten password and a lost authenticator are different problems. A form asking for the current password must never be presented as the general solution for forgotten credentials. Firefly's native password/TOTP route is therefore labeled **Unlock your account / Desbloquea tu cuenta**. It is a known-credential unlock, not a password recovery service.

## Journeys and current implementation

| Customer situation | Appropriate journey | Current boundary |
| --- | --- | --- |
| Remembers the password and has the enrolled authenticator, but ordinary authentication is permanently locked | Verify those existing factors in the restricted native ceremony; authorize the exact current lock transition; require fresh sign-in | Optional native implementation; complete qualification tracked in [progress](progress.md) |
| Forgot the username but remembers the registered email | Use the email where that realm allows email sign-in; do not disclose a username through a public lookup | Realm-aware username/email resolution; unknown-account responses stay generic |
| Forgot the password and still controls other previously bound recovery/authentication methods | Dedicated credential replacement under the approved assurance policy; never ask for the forgotten password | The synthetic sandbox exercises stock Keycloak email password replacement for an enabled account. That is not qualified bank-grade recovery or permanent unlock |
| Forgot the password and the account is also permanently locked | Approved alternative recovery evidence or assisted identity reproofing, followed by an explicitly authorized credential-replacement/unlock transaction | No qualified owner contract or combined native route is delivered; fail closed |
| Lost the authenticator, lost multiple credentials or suspects takeover | Use previously established approved recovery methods, or assisted identity reproofing and controlled re-enrollment | Not part of the password/TOTP unlock; assisted owner and acceptance remain required |
| Has a fraud, compliance, employment or administrator hold | Resolve that hold through its authoritative owner and approvals | Self-service unlock never overrides it |

The ordinary sign-in form's **Forgot password?** action and the optional **Unlock your account** entry must remain distinct. The unlock page explicitly requires the current password and an already enrolled authenticator, and provides a return to sign-in. Do not add an apparently working recovery button backed by an email-only unlock, a bare administrative enable call or a nonexistent support service.

## Why a locked password can still be checked

Permanent blocking denies ordinary authentication; it does not destroy the stored credential. The native extension verifies the existing credential inside Keycloak's protected credential boundary without temporarily enabling the user or issuing a login session. A separately reserved and verified enrolled possession factor is still needed. Eligibility, current owner, credential revision, holds, purpose and lock generation are checked before the native transition.

That mechanism is useful when someone remembers their credentials after a lock. It is unusable when the password or required authenticator is genuinely unavailable. Changing the title to a generic “recovery” label cannot fix that missing proof.

## Forgotten credentials need independent recovery evidence

The recovery mechanism must have been established before the loss, or rely on a genuine identity-proofing process. The replacement password is a new credential; entering it is not evidence that the person knew the previous credential. Two messages sent to the same mailbox do not establish independent factors. The telephone support PIN is a separately scoped knowledge credential and must not silently become an unlock or password-reset permission.

NIST distinguishes binding a replacement password using other authenticators from recovery after authenticator loss. Its AAL2 recovery options include independently obtained recovery methods, a recovery method with an existing authenticator, or repeated identity proofing; recovery also requires notification. This is useful engineering guidance, **not European law or automatic banking certification**. [NIST SP 800-63B-4, account recovery](https://pages.nist.gov/800-63-4/sp800-63b.html#account-recovery).

For applicable payment authentication, factor categories and independence need their own assessment. An OTP and an email link must not simply be relabeled as knowledge and possession. The approved bank procedure determines acceptable alternative evidence and any required stronger controls. [EBA factor categories](https://www.eba.europa.eu/single-rule-book-qa/qna/view/publicId/2020_5619), [EBA factor independence](https://www.eba.europa.eu/single-rule-book-qa/qna/view/publicId/2019_4637).

## Assisted recovery and combined replacement/unlock

The owning service must establish the identity-proofing case, independently verified evidence, actual operator, customer, tenant, permitted action, approvals, current holds, expiry and one-time authorization. A staff login, caller ID, contact record, account history or machine token cannot supply that authority by itself. Notify through an approved previously verified channel, retire affected sessions and preserve durable evidence of the decision and native execution.

A permanently locked account with a forgotten password needs an explicitly scoped recovery purpose and native transaction designed for **credential replacement plus the eligible lock transition**. It must not reuse the current known-password proof, clear a hold or call stock Admin REST reset-password/enable as two uncoordinated public steps. Partial completion and retries must retain the original case, operation, lock generation and execution identity.

The actual case/delegation and identity-proofing owner contracts, producer SDKs and operational procedures must exist before that route is enabled. The current native grant proposal is not such an authority. See [support PIN](support-pin.md), [native unlock protocol](native-recovery.md) and [zero trust](zero-trust.md). Production generation remains closed; this document does not claim that the missing assisted journey is implemented.

## Workforce and privileged accounts

Employees recover through the workforce identity owner and employment/security policy. When a corporate identity provider owns their credentials, its approved recovery procedure owns replacement; customer CIAM must not create a local bypass. The current native extension qualifies only explicitly configured local identities.

Master and privileged administrators use their separate privileged recovery plane and independently approved emergency-access procedure. Neither the customer PIN nor customer/employee self-service unlock can restore an administrator. Keep the operator's real identity in the audit throughout assisted action; recovery is not customer impersonation or a financial grant.
