# Provider claim profile

This records the synthetic Firefly Identity profile and its evidence boundary. Production issuers, clients, audiences, business links and institution topology remain explicit deployment inputs. Jafly stays an independent, provider-neutral framework.

| Claim | Source and type | Receiver rule |
| --- | --- | --- |
| `iss` | Issuer URL, separate customer/workforce realm | Exact configured trusted issuer; transport aliases are not issuer aliases |
| `sub` | Opaque issuer-scoped string from Keycloak's built-in `basic` client scope | Preserve exact string; do not parse as a business UUID |
| `tenant_id` | Server-managed user attribute, opaque string | Preserve namespace and compare with verified principal projection; resolve Core resource UUID through Configuration |
| `principal_kind` | Per-population hardcoded mapper: `HUMAN` for synthetic customer/institution humans; `STAFF` for workforce | Exact approved population; never infer from a caller header or a realm role |
| `client_id` | Per-client hardcoded signed mapper | Exact expected registered/delegating client according to the receiving profile; no permissive fallback to another claim |
| `party_id` | Server-managed canonical UUID string; customer/institution human only | Authoritative business linkage still requires approved owner provisioning/current policy |
| `staff_actor_id` | Server-managed canonical UUID string; workforce only | Separate from opaque OIDC subject; no customer token may acquire a staff link |
| `aud` | Explicit sandbox receiver audience `sandbox-api` | Validate intended receiver; do not infer from issuer, client name, or endpoint URL |
| `exp` | JSON number on the actual provider wire; verified `Instant` after genuine Jafly 26.10.23 decoding/projection | Require future expiration at admission and after asynchronous policy work |
| `nbf` | **Absent in the actual tested customer access token** | Do not fabricate a not-before value. A supported profile must validate it when present and explicitly handle legitimate absence |

The generator is [scripts/generate.py](../scripts/generate.py). Protected tenant/party/staff attributes are admin-editable only; unmanaged attributes are disabled. Registration cannot create these links. No machine service account is enabled by this sandbox, so `MACHINE` issuance/delegation is not demonstrated here.

The explicit default scope list must include `basic`: in [Keycloak 26.8.1](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolFactory.java), that scope supplies subject and authentication-time mappers. Omitting it produced a real access token without `sub`, which our receiver test refused. Restoring it corrected the issued subject without weakening validation.

## Actual hosted observation

[Run 41237666931](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41237666931), source `358ea319191b410e801993c6d67331d4fe2d46b6`, passed the source job and exercised the real pinned Keycloak/PostgreSQL/Mailpit stack. The browser completed code + PKCE, state/nonce and live JWKS signature/issuer/audience checks. The safe report confirmed expected customer tenant/population/client/party presence, no staff claim, numeric expiration and absent not-before. Cross-realm use was refused. No raw token is published.

The run subsequently failed because its code-replay negative preceded refresh and invalidated that session. The successor isolates the replay case and issues a fresh token for the receiver fixture. This observation does **not** establish a passing whole provider job, Jafly normalization, workforce MFA, business authorization, consumer rollout or production acceptance.

## Later native and framework evidence

[Run 41243967826](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41243967826), source `196b2f7811393a7a59493f090d1ea728dd280f3c`, completed the main real browser/OIDC/account/admin/recovery/logout lane and all eight genuine published Jafly 26.10.23 integration tests with no skips. The actual converter preserved opaque identity/tenant, projected `exp` as `Instant`, and retained absent `nbf` as absent. Tampered signature, wrong issuer/audience, cross-population issuer and missing/ambiguous tenant were refused at their tested boundaries. Projection-only opaque-subject tests remain distinct from signature proof.

The separately issued access tokens for both interactive clients had `aud` as a JSON string with one audience: the expected resource was present and the account audience was absent. The native account-console token separately had one account audience and no sandbox-resource audience. [The bounded audience lane](receiver-audiences.md) records only type/count/presence and source identity. These observations do not impose a universal one-audience rule or justify changing a receiver's intended audience.

Real customer Account REST tests permitted an unchanged ordinary profile update, then attempted writes/removals of protected, cross-population and unmanaged fields. Supported read-only administrative user **and unmanaged-attribute** snapshots stayed unchanged after every attempt, as did fresh cryptographically verified subject/security claims. The same run enrolled a real workforce TOTP factor and issued the signed staff profile, but the subsequent wrong-OTP UI wait stopped before the workforce storage probe. The successor corrects that exact upstream selector. No complete workforce integrity/whole-job or production acceptance is inferred from the customer result.
