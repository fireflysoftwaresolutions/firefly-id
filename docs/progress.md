# Implementation evidence

2026-10-31: Authoritative repository lookup returned 404; explicitly authorized public repository created. New isolated checkout initialized; parent handoff remains read-only. Canonical brand repository located and current Keycloak 26.8.1 release verified through official GitHub metadata. Independent source-contract, brand and deployment workstreams started.

Initial disk preflight is below 12 GiB. Container downloads and runtime tests have not been admitted. No cleanup performed. Source implementation and public delivery proceed without implying runtime or production acceptance.

## Source implementation checkpoint

The visible identity is now Firefly Identity, following the owner's explicit naming direction. Technical repository/theme identifiers remain `firefly-id`. The owner selected the geometric protection enclosure; Manrope and canonical Firefly tokens remain authoritative. Account, administration, login, email and welcome themes are included, with a global default to cover the master administrative realm.

Local qualification: 11 Python source/package/deployment tests and 2 Node error-redaction regressions pass. All three custom FreeMarker templates parse using the available FreeMarker 2.3.35. Python compilation, shell syntax, JavaScript syntax and generated Compose validation pass. The theme archive reproduces byte-for-byte. These checks did not start an identity server or resolve Maven dependencies.

An independent source review found and prompted fixes for token-bearing browser error logging, unproven reset success, remote Docker-context mutation, and inaccurate ephemeral-mail retention wording. Runtime reset acceptance now requires a fresh login and protected credential-state update. Local lifecycle rejects non-Unix remote/TCP Docker endpoints. No production provider or consumer acceptance is inferred.

The hosted workflow is configured to exercise an isolated pinned Keycloak/PostgreSQL/Mailpit stack, actual browser/OIDC/recovery/account/admin flows and the genuine published Jafly 26.10.23 decoder/principal converter. Its actual outcome is pending first publication/execution. MFA/passkey/lost-factor flows, profile-forgery enforcement, verification action expiry/reuse, confidential clients, signing rotation, restart/restore, durable event delivery and full OpenPlatform consumer integration remain separate unqualified work.
