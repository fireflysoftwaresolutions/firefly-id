# Native recovery installation and protocol

Firefly Identity supplies an optional, version-specific Keycloak extension for recovery from a permanent authentication lock. It verifies an existing password and an already enrolled TOTP credential inside Keycloak. It does not send those secrets to application services, create a login session, replace a forgotten password, enroll a new factor or restore an administrative hold.

Its user-facing name is **Unlock your account**, not general access recovery. Someone who forgot that password cannot use this flow. The [access journey guide](access-recovery.md) separates remembered-credential unlock, forgotten credentials and assisted identity reproofing, including the missing owner contract for combined replacement and unlock.

The native implementation, Core SCA owner and Domain orchestration are separate artifacts. Their source tests and actual integrated runtime have separate acceptance gates. Read [current evidence](progress.md) before treating this candidate as deployable. Production realm generation remains closed; this guide describes the explicit integration contract rather than a production provisioning command.

## Components and prerequisites

| Component | Responsibility |
| --- | --- |
| `firefly-id-native-recovery` | Native local credentials, lock generation, restricted assertion, factor replay fences, atomic unlock and native execution journal |
| `firefly-id-native-domain-gateway` | Bounded HTTPS calls to the explicitly configured owning Domain service |
| Core SCA candidate | Durable operation/challenges, committed attempt reservation, independent evidence categories, one-time authorization and execution audit |
| Domain SCA candidate | Current boundary authorization and orchestration using the genuine Core producer SDK; no credential or business persistence |
| Independent Jafly framework | Generic Spring Security receiver mechanisms; no dependency on this extension or Firefly branding |

The native JARs target Java 21 and **Keycloak 26.8.1 exactly**. Owning Core/Domain services use their own Java 25 and Jafly train. Install both native JARs together, with the matching Firefly theme. Do not place application service dependencies, another Keycloak runtime or Jafly inside the provider directory.

Only explicitly configured local customer (`HUMAN`) and employee (`STAFF`) realms qualify. Master administrators, service accounts, privileged realm administrators and external/federated credential stores are excluded. Customer and employee issuers, clients, owner links, budgets and service configurations remain distinct. A user must have both a valid local password and pre-enrolled nonreusable TOTP before the account is locked. A customer sample without possession enrollment cannot qualify by knowing its password.

## Build and installation candidate

Run native builds only in an approved environment with sufficient resources. The hosted `Native extension qualification` workflow runs this same Maven reactor with a fresh private dependency repository and retains bounded test results plus the two candidate JARs.

```sh
mvn -B -ntp -f extensions/pom.xml verify
python3 tooling/build_theme.py
python3 tooling/package_native.py \
  --native-jar extensions/native-recovery/target/firefly-id-native-recovery-26.10.1-SNAPSHOT.jar \
  --gateway-jar extensions/native-domain-gateway/target/firefly-id-native-domain-gateway-26.10.1-SNAPSHOT.jar
```

The packager checks Java 21 class versions, required service/migration resources and exact distribution notices. It writes two providers and a SHA-256 manifest into a **new** `dist/native` directory, refusing an existing output. Supply another new `--output` for a separate attempt; preserve previous evidence. These checks establish artifact integrity, not runtime acceptance.

[Containerfile.native](../deploy/Containerfile.native) is the optional optimized image reference. It consumes the built theme and `dist/native/providers`, uses the same digest-pinned Keycloak release as the base distribution and runs the upstream augmentation step. Image building does not provision realms, approve a database migration or enable a recovery endpoint for any population. Review the [operations guide](operations.md) for TLS, database isolation, private administration, backup and rollback requirements.

Select `firefly-id-native` as the managed realm's **login theme** only after installing the extension and its actual owners. This inherited variant adds a discreet recovery link to ordinary sign-in. Select its **account theme only for customer realms** to expose customer support PIN management. Keep the workforce account theme as `firefly-id`. Administration, email and welcome retain `firefly-id`. This preserves the approved Manrope, light/dark composition and inherited server forms without advertising unavailable native endpoints in a theme-only installation.

Explicitly select `--spi-brute-force-protector--provider=firefly-native-recovery` at native startup. The provider uses the upstream implementation for unmanaged identities. Its managed path serializes local user admission and permanent failure capture; the mandatory global invalidation listener rejects generic administrative re-enablement of a tracked lock. An Admin REST permission is not an unlock grant.

## Realm and service configuration

The native realm reads the following **realm attributes**. These are server-controlled configuration, never editable user-profile fields.

| Prefix: `firefly.native-recovery.` | Meaning |
| --- | --- |
| `population` | Exactly `HUMAN` or `STAFF` |
| `issuer` | Exact public HTTPS issuer, including this realm |
| `allowed-origin` | Exact browser HTTPS origin matching the issuer origin |
| `client-id` | Dedicated restricted ceremony client; no ordinary grant |
| `tenant-attribute` | Protected user attribute containing the opaque identity tenant namespace |
| `link-attribute` | Protected party UUID for customers or staff actor UUID for employees |
| `domain-audience`, `core-audience` | Distinct intended recovery receivers |
| `domain-workload-client-id`, `core-workload-client-id` | Distinct confidential, grant-disabled private RPC clients |
| `domain-url` | Exact HTTPS Domain origin, without credentials, query, fragment or redirect |
| `ttl-seconds` | Positive value, at most 300 for customers or 180 for employees |

Protect tenant/link attributes from self-service writes. A business owner must establish them through its authoritative linking process; a claim is neither a business permission nor workforce delegation.

Each owning service must explicitly opt in to its native owner adapter and narrow self-recovery policy. Its remote base URL is the exact issuer followed by `/firefly-recovery/rpc`. Workload client IDs and mounted secret files are population specific. Use actual platform TLS trust; redirects and trust-all settings are not supported. The native Domain gateway bounds responses to 64 KiB and request completion to five seconds. See the actual [Core draft](https://github.com/fireflysoftwaresolutions/core-common-sca-mgmt/pull/2) and [Domain contract/configuration](https://github.com/fireflysoftwaresolutions/domain-common-sca/blob/codex/firefly-id-domain-sca-recovery-20261031/docs/RECOVERY_SOURCE_CONTRACT.md) for their independent properties and qualification pins. A default-off source candidate is not a released platform default.

## Browser journey and service contract

1. `GET {issuer}/firefly-recovery` creates or resumes a short-lived server ceremony. Its Secure, HttpOnly, SameSite=Strict cookie is scoped to this native path; POST requires its rotating CSRF value and exact Origin. Browser/system locale selects English or Spanish through native Keycloak negotiation.
2. The password step resolves the configured username/email lookup and checks eligibility privately. Unknown, ambiguous, held and ineligible users move to the same public next step. Password checks stay native; a restricted signed assertion carries no raw factor or ordinary grant.
3. Domain starts an operation through the genuine Core SDK. Core durably reserves a knowledge attempt **before** the native committed check. The native opaque attestation binds the exact operation, challenge, reservation, provider challenge, category, credential revision, owner and lock generation.
4. The possession step uses an already enrolled TOTP. Native durable replay state and Keycloak single-use handling reject reuse. Core independently reserves and completes the possession challenge. Native and Core budgets are bounded; no UI names the incorrect factor or remaining attempts.
5. Core consumes a one-time authorization. Domain verifies the exact consumed receipt online. Native compares that receipt and the current lock, generation, holds, credentials and owner before its atomic transition. It records the native execution, retires online/offline sessions and advances user not-before.
6. Native reports the exact execution to Core through Domain and shows a fresh-sign-in action. Recovery does not issue OAuth tokens, restore an old session or create business authority. Ordinary login and applicable MFA run again.

Only the native unlock/PIN documents select `same-origin` referrer policy through server-controlled head metadata. This preserves an actual Origin on browser form POSTs while withholding cross-origin Referer. Stock login/action-token pages retain their upstream policy. Exact Origin and CSRF validation remain mandatory. The real browser runner checks the observed outgoing Origin without injecting that header.

An accepted native form POST returns **303 See Other** to its canonical GET: the recovery root for an unfinished step and `/firefly-recovery/complete` after native execution. Refresh therefore resumes a GET document rather than resubmitting passwords, OTPs or PINs with a consumed CSRF value. The ceremony stores only generic failure feedback for presentation; credentials and failure details never enter redirect URLs. GET resumes the same live operation and rotates CSRF without reserving or verifying another factor. Invalid Origin, CSRF and pre-consumption expiry still receive their direct refusal.

Expiry after an already committed native mutation does not turn result presentation into another authorization. Feedback finalization requires the original canonical execution journal, or the same owner's consumed PIN ceremony, and leaves the original expiry unchanged. The completion GET can always display a generic processed/sign-in instruction. Only a live cookie-bound canonical journal can expose the bounded audit-retry form; expired or absent authority gets no CSRF/action capability. Neither the completion URL nor its presentation is authentication or proof of account state.

Domain's HTTP root is `/api/v1/sca/recovery-operations`. It exposes create, reserve, complete, consume, online authorization verification and execution recording. The native browser server uses a per-request bearer restricted to those services; no unsigned actor headers or singleton bearer configuration supply authority. The private native RPC accepts only its separate workload credential **and** the genuine restricted signed actor, then performs phase-specific current admission.

## Retry, interruption and retained state

Native database phases commit and release their locks before outbound HTTP. A lost response cannot safely be treated as a failed remote mutation. Core challenge reservation and native attestation reuse preserve the original attempt identity. Native execution and execution recording are different durable facts.

After native execution commits, the original exact receipt and operation are retained in the native journal. Reload resumes the completion screen. Its bounded CSRF retry performs execution **recording only**; it never verifies another factor, consumes another authorization or unlocks again. Original assertion expiry is preserved. If the outage outlasts that assertion, retain the journal and pending/unknown Core state for a separately authorized assisted reconciliation process. A machine token must not manufacture a replacement human proof.

The extension adds native tables through its versioned Keycloak JPA/Liquibase provider. Core uses its own installer-owned boundary audit storage. Back up and rehearse both owners independently. Do not manually clear native tables, reset generation counters or delete pending evidence to recover an interrupted ceremony. Retention, evidence export, migration and cluster/concurrent crash acceptance require explicit operational qualification; no automatic janitor is advertised.

## Acceptance limits

The hosted `Real native recovery integration` lane builds exact native, Core, genuine SDK and Domain sources, starts separate customer/workforce processes with real HTTPS trust and uses synthetic enrolled credentials. It must prove its actual browser assertions and retain bounded evidence before integrated acceptance is claimed. Passkey recovery, external credential stores, lost-factor reproofing, bank notifications, BPO case authorization, all-service immediate revocation, high availability and production rollout are separate gates. There is no blanket claim of European regulatory compliance.
