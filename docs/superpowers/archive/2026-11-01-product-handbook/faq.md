# Frequently asked questions

## What is shipped, and what remains a candidate?

The repository ships a branded Keycloak distribution, deterministic theme packaging, policy-driven synthetic generation, operational references and application integration fixtures. The optional native extension adds known-password unlock, customer support-PIN lifecycle and the separate credential-loss protocol. Core/Domain recovery owners and their generated SDKs remain independently qualified source candidates; their presence in a passing test does not publish or adopt new platform releases. [Solution overview](solution-overview.md) identifies each owner.

## What has actually passed?

At runtime-qualified Identity source `15fd1b7ffa045835f3d4c71fdcc33020d8f24ecf`, the ordinary distribution and native source/packaging lanes passed. The [known-password/PIN integration](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331177242) passed 48 controls with Core SCA `cc826d27cd05dac831989ec872d78a8c17e88e8b` and Domain SCA `3cf19a0d2a6baa1e13ad92dc7014b91490996ac4`.

The separate [credential-loss integration](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41332055134) passed 25 controls with Core KYCB `26c3b142c66d4d9ad3a0cc9619d476f2b9d24261` and customer Domain `68fa0b7fc849dd3e4dab7756493e344a331bb478`. It used test-only signed proofing and actual synthetic Keycloak/Core/Domain, SMTP failure/retry, restart retention and private-monitor checks. [Progress](progress.md) records artifacts, hashes and historical failures. Documentation-only successors do not create a new runtime qualification.

## Why does production generation refuse?

`scripts/generate.py --mode production` intentionally stops before generation because production realm/client/claim and deployment contracts have not been selected and approved. The production configuration file and Containerfiles are references, not an activated production environment. The synthetic HTTP issuer, loopback exposure, local SMTP and example links must not be promoted as production settings. Follow [sandbox](sandbox.md), [security](security.md) and [operations](operations.md) at their separate scopes.

## Does every customer login use MFA or banking SCA?

No. Customer MFA is optional in the generated synthetic profile; fresh workforce authentication requires password and TOTP. Permanent administrators still need a separately qualified phishing-resistant MFA flow. Payment SCA depends on the applicable activity, factors, independence and other obligations. A service named SCA, a password/OTP screen or a green test does not establish that legal conclusion. [Authentication policies](authentication-policies.md) explains the exact selected defaults and limitations.

## Why three failed attempts, and will waiting unblock the account?

Three recorded failures and permanent blocking are the selected product policy. They are not a universal European or US legislative threshold. There is no timed release under this policy. Password replacement, failure-counter clearing and a bare administrative enable call are not authorized substitutes for the bound recovery transition. Public feedback stays generic and omits remaining attempts. [Permanent recovery](permanent-recovery.md) explains ownership and the native enforcement model.

## Is “Unlock your account” for a forgotten password?

No. It verifies the current password and a TOTP enrolled before the lock. It is useful when a customer or eligible local employee still has both factors but cannot authenticate ordinarily. A person who forgot either required factor needs the separately approved recovery process. The [access journey guide](access-recovery.md) and [customer walkthrough](customer-journeys.md) keep the entry points distinct.

## Can the credential-loss candidate replace forgotten factors?

For an eligible local customer, the implemented candidate replaces password/TOTP after independent Core KYCB/customer Domain proofing authority, current native admission and a bound one-time grant. It can clear an eligible authentication lock as part of that transaction and retires superseded factors, PIN and sessions. It excludes workforce/administrators, foreign credential stores and unsupported types such as passkeys. Real documentary/biometric proofing, escalation and bank operating acceptance remain pending. Read [credential-loss recovery](credential-loss-recovery.md) before installing it.

## Which KYC or biometric engine is installed?

None is selected or installed. Core KYCB is the KYC/KYB system of record; customer Domain integrates the future independent third-party verification provider. The successful provider fixture is test-only and excluded from production JARs. eIDAS is the design baseline, not a scheme qualification or vendor approval. The [provider evaluation](identity-proofing-evaluation.md) and [credential-loss contract](credential-loss-recovery.md) describe the remaining evidence and integration work.

## Does email verification or an existing KYC record authorize recovery?

No. Email verification establishes a bounded communication-channel fact. An existing KYC record, party ID, caller ID, staff login or browser approval flag does not supply fresh purpose-bound recovery evidence. A replacement password is a new credential, not proof that the person knew the old one. Legal-person representative mandates and financial authority also need their own current evidence and owners. See [architecture](architecture.md).

## Can a support PIN unlock an account or authorize a payment?

No. The PIN is a separate customer knowledge credential. Customer lifecycle mutations require fresh password/TOTP proof; privileged revocation uses its own permission and attributed administrator identity. Verification remains closed until a genuine support case/call authorization owner is integrated. It does not establish possession, customer impersonation, financial permission or BPO/workforce delegation. [Support PIN](support-pin.md) documents the boundary.

## Does a lock or logout immediately revoke every API JWT?

No blanket result is established. Native recovery retires online/offline sessions and advances user not-before, but an already issued self-contained JWT can still pass offline cryptographic validation until its applicable time limit. Every receiver needs its approved current-state enforcement and authorization path. The tested introspection/receiver lanes are bounded fixtures, not proof that all OpenPlatform applications adopted them. [Zero trust](zero-trust.md) and [receiver audiences](receiver-audiences.md) explain the required service decisions.

## Is Jafly tied to Keycloak or Firefly Identity?

No. Jafly remains an independent, provider-neutral framework using generic Spring Security facilities. This repository's actual published-artifact fixture checks selected decoder/principal behavior against a real synthetic issuer; it does not change the framework or prove a production application's full filter chain/business authorization. Native provider JARs and proofing adapters stay outside Jafly. See [Jafly integration](jafly.md) and the [integration matrix](integration-contract.md).

## Can I copy the sandbox realms into production or regenerate retained state?

No. Generation creates new synthetic fixtures and refuses an existing output path, including a symlink. It does not migrate an imported realm or rotate a retained database password. Preserve the database together with its matching secrets, ownership and factor state. A separate new fixture is a separate environment, not repair or migration evidence. Use the [sandbox lifecycle](sandbox.md) and [operating procedure](operations.md) for the actual owner-controlled actions.

## Can I enable the native feature after installing its JARs without a migration review?

Installation and enablement are separate gates. The native JPA/Liquibase mappings can register at server startup even while recovery is default-off. Back up and rehearse the identity and Core-owned stores independently before an approved retained-database rollout. Single-process restart tests do not establish backup restoration, multi-node crash behavior or end-to-end HA. [Native installation](native-recovery.md) and [credential-loss installation limits](credential-loss-recovery.md#installation-and-evidence-boundaries) identify the risks and required evidence.

## What happens if recovery execution or notification loses a response?

Retain the original journal, case, grant, execution identity and budgets. The protocol can reconcile an already committed original execution without authorizing another mutation. Notifications use a durable native outbox and an optional default-off Core poller; automatic synthetic retry/restart behavior passed, but the bank's real delivery channel and operating procedure remain unapproved. At-least-once delivery can duplicate a notice after SMTP acceptance and a process failure. Pending, terminal or exhausted states need authorized review, never row deletion, factor replay or budget reset. See [credential-loss operations](credential-loss-recovery.md#notification-and-interruption-handling).

## Are passkeys, registration and every inherited screen qualified?

No. Theme inheritance preserves upstream presentation mechanisms, while actual enabled flows need independent server/browser evidence. Real TOTP, verification, profile and ordinary flows have bounded receipts; passkey/WebAuthn enrollment/assertion, recovery codes, registration/broker forgery and other listed flows retain their own gates. The [theme coverage table](themes.md) and [progress history](progress.md) distinguish inheritance from observed behavior.

## Is this certified for EU or US regulated use?

No certification or universal legal assurance is claimed. Applicability depends on the entity, activity, jurisdiction, data and selected operating model. NIST is technical guidance rather than automatic law; EU payment authentication is not the same scope as every customer login; US banking and FTC Safeguards applicability are distinct. Tests, images and documentation cannot approve those decisions. Use the regulated-deployment/control mappings with the institution's accountable reviewers and actual operational evidence.

## Where should I customize the experience?

Use the supported theme sources and canonical assets, rebuild the deterministic theme and review actual desktop/mobile server journeys in both color schemes and languages. Preserve action tokens, CSRF, authenticator semantics and protected claims; do not replace missing server controls with CSS or browser code. [Themes](themes.md), [localization](localization.md) and [brand](brand.md) identify the maintained customization points and licensing/attribution boundaries.
