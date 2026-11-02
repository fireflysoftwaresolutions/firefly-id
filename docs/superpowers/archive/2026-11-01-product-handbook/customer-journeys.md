# Customer journeys

This guide follows a customer from application sign-in to account management and recovery. It separates ordinary Keycloak behavior from optional Firefly native protocols and from business approvals owned elsewhere. For a safe evaluation environment, complete the [sandbox guide](sandbox.md) first; use only its synthetic identities and local mail sink.

## Sign in to an application

The customer starts in the application, which redirects to the configured customer issuer. The generated public example is `sandbox-web` with an exact `http://localhost:3000/oidc/callback` callback and PKCE S256. The confidential `sandbox-backend` example is an interactive code-flow client, not a machine account. Both disable password/direct-access and implicit grants. These settings come from the [generator](../scripts/generate.py); production clients need independently approved HTTPS callbacks, audiences and scopes.

1. Enter the configured username or registered email and password on the issuer's sign-in page. Email sign-in is allowed in the synthetic customer realm; a public username-discovery service is not supplied.
2. Complete the actions required by the actual realm, such as email verification or an enrolled factor challenge. Customer MFA is **optional** in the generated synthetic customer profile. A successful basic login therefore does not demonstrate banking strong customer authentication.
3. Return through the exact client callback. The client validates its protocol response; the API separately validates the access token and current authorization. The person does not gain financial permissions merely by reaching the application.
4. Use the application's normal logout path when finished. Retiring the identity session does not by itself prove every API immediately rejects a previously issued self-contained JWT.

The [provider-claim profile](provider-claim-profile.md) explains which claims an actual access token carries. [Jafly integration](jafly.md) demonstrates a published generic receiver without making the framework dependent on this identity provider.

## Verify email and manage the profile

An unverified synthetic fixture exercises the server's `VERIFY_EMAIL` required action. The email link is generated and signed by Keycloak; the customer opens it, completes the server's confirmation and returns to the pending application journey. The hosted lane checks real verification and consumed-link refusal. Genuine natural expiry of that verification action is a separate gate; a tampered link is not an expiry test. See [extended flows](extended-flows.md) and the latest [qualification receipt](progress.md).

Email verification establishes control of a communication channel for that action. It does not establish legal identity, KYC completion, representation of a company or a financial mandate.

Account self-service uses the inherited Keycloak Account Console. Customers may manage permitted profile fields and available credentials according to realm policy. The generated declarative profile protects `tenant_id`, `party_id` and `staff_actor_id` from customer writes and disables unmanaged attributes. A changed email address cannot relink the customer to another party or tenant. The real profile-integrity lane checks storage through both administrative views and a fresh signed token, rather than treating an HTTP status alone as proof. [Security](security.md) describes provisioning and trusted-claim ownership.

An application onboarding flow must obtain the authoritative customer record and link through its actual owner API. Self-registration is disabled in the generated realm. Inherited registration templates are presentation support, not an enabled onboarding or approved identity-proofing process.

## Choose recovery by what the customer still has

| Situation | Customer-facing route | Evidence and owner |
| --- | --- | --- |
| Forgot username, knows registered email | Use email at ordinary sign-in where enabled | Native account resolution; generic public refusal |
| Remembers password and has enrolled TOTP, but ordinary login is permanently locked | **Unlock your account** | Native existing-factor verification plus separate Domain/Core SCA authorization of the current lock |
| Forgot password, lost TOTP or lost both, with an eligible local customer identity | Separate credential-loss/proofing journey | Core KYCB case/grant, independent customer Domain provider adapter and native factor replacement; real-provider approval pending |
| Has a fraud, compliance or administrative hold | Owner's approved assisted process | The hold's authoritative owner; self-service recovery cannot override it |
| Uses a foreign credential store or unsupported credential type | Its approved recovery procedure | The credential owner; local password/TOTP replacement is unavailable |

The stock **Forgot password?** email flow is useful to evaluate inherited action-token behavior in the sandbox. It is not qualified banking recovery and does not unlock a permanent authentication block. The [access journey guide](access-recovery.md) explains the alternatives and the boundary between credential replacement and unlocking.

## Known-password unlock

This optional native journey is for someone who can still prove both the current password and a TOTP enrolled before the lock. Installing the ordinary theme alone does not enable it. Operators must select the native login theme only after installing and configuring the extension and owning services. The theme property exposes the entry; theme selection does not verify backend availability or qualification.

The customer opens **Unlock your account**, enters the remembered password and then the enrolled authenticator code. Native verification keeps credentials inside Keycloak. Domain/Core SCA authorize the exact operation, independently reserve factor attempts and bind the result to current owner, credential revision and lock generation. Unknown and ineligible identities receive the same public journey; the screen does not disclose the incorrect factor or remaining attempts.

On success, native execution retires affected sessions and presents fresh sign-in. It does not issue an ordinary login session, restore an old token, replace a forgotten password or remove an unrelated hold. Reloading a completion page cannot authorize another unlock. If remote execution recording is interrupted, the original journal supports only bounded recording of the original mutation. Preserve it; do not restart proof or clear counters to manufacture a successful retry. The [native protocol](native-recovery.md) documents installation, retry phases and reconciliation.

The customer/workforce known-password/PIN integration passed 48 configured controls at Identity `15fd1b7`, with the distinct Core/Domain SCA pins recorded in [progress](progress.md). This does not qualify a customer with no enrolled possession factor or any privileged administrator.

## Lost credentials and independent proofing

The separate candidate never asks for a forgotten previous password. The customer begins a native ceremony, opens the independently verified provider journey in another tab and returns to the native page to check its outcome. A browser redirect or a supplied approval flag cannot authorize recovery. Core obtains authenticated provider evidence through the independent Domain verifier and issues a narrowly bound one-time grant only after current native admission.

After accepted proofing, the customer chooses a new policy-valid password and proves a newly bound TOTP. Native execution atomically replaces the supported local factors, retires old factor/PIN/session authority, clears only an eligible authentication lock and queues notification to the previously verified destination. It finishes with ordinary fresh sign-in. A lost response or expired presentation preserves the original case, grant, execution and budgets; a replacement ceremony cannot reset them.

The real Keycloak/Core/Domain lane passed **25 controls** at Identity `15fd1b7`, Core KYCB `26c3b14` and customer Domain `68fa0b7`, using a **test-only signed proofing fixture** excluded from production JARs. No real verifier, biometric engine or assisted bank process is approved. Core KYCB is the system of record; Domain's third-party adapter still needs genuine documentary/biometric and reference-identity acceptance. Read [credential-loss recovery](credential-loss-recovery.md) before interpreting this candidate as operational.

## Telephone support PIN

An authenticated customer can view PIN status in the optional native customer Account Console. Creating, replacing or revoking the PIN requires fresh password/TOTP proof; privileged administrative revocation has a separate permission and attributed audit path. The workforce console does not expose this customer credential.

A PIN verification is a scoped knowledge check. It is not possession proof, a payment instruction, an unlock grant or permission for a staff member to impersonate the customer. Support verification remains closed until a genuine authorized support case/call owner exists. The [support PIN guide](support-pin.md) covers storage, pepper rotation and the BPO contract still required.

## Feedback, languages and support handling

Sign-in and recovery use English/Spanish native locale negotiation and a discreet optional language control. Public refusals remain generic: they must not expose account existence, lock counters or which factor failed. Operators should diagnose through approved non-secret events and exact current evidence, never by asking the customer to send passwords, OTPs, setup keys, action links or tokens.

The [troubleshooting guide](troubleshooting.md) addresses callback, discovery, mail and theme failures. A stalled recovery, exhausted budget or pending notification needs its authorized operating procedure. Keep original retained evidence and state; styling a retry button is not a recovery decision.
