# Qualification and acceptance

This is the concise current evidence register, reviewed November 1, 2026. It separates source/build checks, actual synthetic runtime qualification, published dependencies and the institution/provider acceptance still required. [Implementation history](progress.md) preserves the earlier checkpoints and failed attempts without turning them into current successes.

## Identity distribution and native extension

| Receipt | Exact source / result | What it proves |
| --- | --- | --- |
| [Ordinary distribution 41331178246](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331178246) | Identity `15fd1b7ffa045835f3d4c71fdcc33020d8f24ecf` | Actual synthetic OIDC/PKCE, refresh/logout, account/admin, policy, profile integrity, workforce OTP, EN/ES and published Jafly integration |
| [Native source/packaging 41331182922](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331182922) | Same Identity source; 79 tests, zero failures/errors/skips | Compilation, focused native/gateway boundary regressions and package notices |
| [Known-password/PIN integration 41331177242](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331177242) | Same Identity source; Core SCA `cc826d27cd05dac831989ec872d78a8c17e88e8b`, Domain SCA `3cf19a0d2a6baa1e13ad92dc7014b91490996ac4`; 48 controls, zero failures | Customer/workforce real password/enrolled-TOTP unlock, permanent lock/restart, current native checks, scoped concurrent execution, session retirement, PIN lifecycle and attributed privileged revocation |
| [Credential-loss integration 41332055134](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41332055134) | Identity `15fd1b7`; Core KYCB `26c3b142c66d4d9ad3a0cc9619d476f2b9d24261`, customer Domain `68fa0b7fc849dd3e4dab7756493e344a331bb478`; 25 controls, zero failures | Local-customer credential replacement with test-only signed proofing, durable budgets/holds, old-factor/PIN/session retirement, automatic notifications/Core restart/private metrics and natural-expiry journal reconciliation |

The 48-control lane uses SCA owners; the 25-control lane uses the distinct KYC/KYB recovery owners. Do not substitute one tuple for the other or use an older binary receipt to qualify a newer shared provider.

Native JAR SHA-256 is `6d163a808152f21ee9f7158d39df487a5a0c42175f5479b58660af009f6d40ab` in both passing integration lanes. Gateway is `749a583a67b09cdad5dfa6104fac361b818404364dad1ae0abb774e98971c050`. The ordinary theme/brand/JPA/SPI resources were unchanged by notification completion. The later documentation work does not change those runtime inputs.

## KYC/KYB source and genuine SDK

| Receipt | Result |
| --- | --- |
| [Core source 41331774478](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/actions/runs/41331774478) | Exact Core `26c3b142c66d4d9ad3a0cc9619d476f2b9d24261`: 170 tests including 19 actual PostgreSQL cases, zero failures/errors/skips |
| [Domain recovery 41332030859](https://github.com/fireflysoftwaresolutions/domain-customer-kyc-kyb/actions/runs/41332030859) | Exact Domain `68fa0b7fc849dd3e4dab7756493e344a331bb478`: 43 focused tests, zero failures/errors/skips |
| [Domain full KYB reactor 41332030842](https://github.com/fireflysoftwaresolutions/domain-customer-kyc-kyb/actions/runs/41332030842) | Same Domain/Core tuple: 102 tests, zero failures/errors/skips |

Original producer specification SHA-256 remains `39da00b3cb287d0df9675b6c57975decc6b7271447b2ca01f0556a613ba2ed24`; its original generated SDK remains `e6c7c2b7277dfcf3898a152af5ead54dba3fdd5a0703f6c28481206c9489b46a`. The separate genuine consumer candidate SDK is `26.10.6-reproofing-source-26c3b142c66d-SNAPSHOT`, SHA-256 `7158c8669188a1c1abea02b2da08372631ee4877d3fab83f5a935da6e283e2d0`; descriptor SHA-256 `620e87f325fa8c00d89b8e08b854c8a32b4f18f2c7d165790a6d51b9c8d2ac9e`.

Source-parent `6442bd51733ade4d5f4583e1afe812dd2c520b40` and published Jafly train `26.10.23` are explicit qualification fixtures. No mutated released parent, new service release or new SDK adoption is inferred. Successful proofing fixtures are excluded from production JARs.

## What the notification result adds

Artifact `13093699199` from the final 25-control lane pins the complete source/spec/SDK tuple. It proves automatic persisted SMTP retry, degraded status, owned Core restart without new cases/grants/budget reset, automatic delivery after channel restoration, private monitor authorization and absence of worker series from global Actuator. Real database probes verify realm scope, invalid/null status constraints and an expired eighth lease becoming terminal without a ninth send.

The artifact includes 32 safe EN/ES desktop/mobile light/dark captures and eight measured canonical Manrope surfaces. Images contain empty/masked/completion states; raw passwords, TOTP setup material, mail/provider payloads and logs are excluded. Visual proof does not replace authorization proof.

Review found and corrected a private-metrics leak before final acceptance. A later downstream test exposed a cold-TLS one-second deadline and generic rejection catcher that could produce false positives; the final test-only correction requires valid warmup, exact failure categories, actual server request/write receipts and a separate held-response timeout. Original failures remain in [history](progress.md), and a same-source retry is not presented as the fix.

## Documentation evidence is separate

This handbook's strict MkDocs build, link/anchor checks, source-derived defaults, local assets and desktop/mobile browser checks qualify the **documentation site**. Its generated `documentation-provenance.json` identifies the exact documentation source, catalogue and Manrope hashes. The documentation workflow records resolved build dependencies and bounded browser results. A successful private documentation publication is not a production identity-service deployment or regulatory acceptance.

## Acceptance still owned by the deployment

| Gate | Required owner / evidence |
| --- | --- |
| EU/US applicability and policy | Institution legal/security decision, relevant entity/journey/regulator, approved factor and session requirements, residual risk |
| Real identity proofing | Selected verifier, trust/assurance profile, authentic existing-party resolver, structured policy/evidence provenance and actual vendor conformance |
| Workforce/admin lost-factor recovery | Separate authoritative employment/privileged owner, approved alternate evidence and recovery procedure |
| BPO/backoffice delegation | Genuine staff/customer/case/call/purpose authority and receiving-service enforcement; PIN alone is not authorization |
| Customer MFA/payment SCA | Approved enrollment, applicable step-up/transaction binding and actual payer-inactivity behavior; optional base MFA is insufficient where stronger access is required |
| Permanent administration | Private route enforcement, named least-privilege accounts, phishing-resistant MFA, emergency access and bootstrap removal |
| Notification operations | Approved real SMTP/channel, required advance-block warnings, alert installation/receivers and terminal escalation |
| Retained database and HA | Reviewed installation migration, isolated restore/rollback, cross-owner consistency and actual selected multi-node failure behavior |
| Zero trust at consumers | Every receiving Experience/Domain/Core service's current authorization/state/revocation checks and bounded caches; session removal alone is insufficient |
| Privacy/audit/incidents | Data-owner policy, lawful biometric/document processing, residency/transfers/retention, immutable external custody and applicable reporting procedures |
| Release and rollout | Approved artifact coordinates, consumer adoption, service operating acceptance and production authorization |

The candidates remain draft PRs: [Identity #1](https://github.com/fireflysoftwaresolutions/firefly-id/pull/1), [Core KYCB #3](https://github.com/fireflysoftwaresolutions/core-common-kycb-mgmt/pull/3), [customer Domain #3](https://github.com/fireflysoftwaresolutions/domain-customer-kyc-kyb/pull/3). No table entry, green test or documentation claim turns a missing acceptance owner into an implemented control.
