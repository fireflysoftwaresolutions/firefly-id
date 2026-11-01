# Token claims and identity links

An access token carries a signed identity for an intended receiver. Read claims only after validating the signature, exact issuer, audience and time constraints. Claims identify the actor and its trusted links; the receiving application still decides whether that actor may perform the requested business operation.

The profiles below describe clients produced by the sandbox generator. For another deployment, configure the issuer, audience, population and authoritative identity links explicitly.

## Common access-token claims

| Claim | Type and meaning | How to use it |
| --- | --- | --- |
| `iss` | String; exact realm issuer URL | Match the configured authority, including realm path. Internal routing aliases are not additional trusted issuers. |
| `sub` | Opaque string; subject within that issuer | Preserve it exactly with `iss`. Do not parse it as a business UUID or replace it with username/email. |
| `aud` | String or array of strings; intended receivers | Require this API's configured audience membership. See [audiences](receiver-audiences.md). |
| `exp` | Numeric timestamp on the JWT wire | Require valid unexpired authority. Spring's verified JWT/Jafly principal represents it as `Instant`. |
| `nbf` | Optional numeric timestamp | Enforce it when present. Do not fabricate a value when absent; configure an issuance profile if an operation requires it. |
| `tenant_id` | Protected opaque string | Preserve the identity namespace. Resolve a distinct business resource-tenant UUID through Configuration where required. |
| `principal_kind` | Signed string classifying the configured population | Require the population appropriate to this operation; do not infer it from a request header. |
| `client_id` | Signed string naming the configured client | Match the exact approved client where the receiver's policy requires client binding. Do not silently fall back to another claim. |
| `scope` | Space-delimited string of scopes | Map only the scopes understood by the receiver. Identity scopes are not payment permissions. |

The default interactive clients include `basic`, `profile` and `email` client scopes and request `openid profile email` during sign-in. Keep `basic`: it supplies the native subject/authentication-time mappers. Custom tenant, link, population, client and API-audience mappers are configured for access tokens, not ID tokens or userinfo.

## Population-specific profiles

| Profile | `principal_kind` | Trusted link | Not included |
| --- | --- | --- | --- |
| Customer human | `HUMAN` | `party_id`, a server-managed canonical UUID string | `staff_actor_id` |
| Workforce employee | `STAFF` | `staff_actor_id`, a server-managed canonical UUID string | `party_id` |
| Institutional human example | `HUMAN` | `party_id`, a synthetic party reference | Staff identity, machine status or institutional signing authority |
| Optional Configuration service client | `MACHINE` | Configured opaque `tenant_id` and its own `client_id` | `party_id`, `staff_actor_id` and human delegation |

The default sandbox creates no service accounts. The [optional service-client profile](configuration-service-client.md) provisions a separate machine explicitly. A confidential interactive backend remains an interactive human client; holding a secret does not make its users machine principals.

## Example customer payload

This illustrative payload shows claim structure, not a usable token. Its timestamps, subject and links are example values; decoding similar JSON from a bearer token does not verify it.

```json
{
  "iss": "http://id.firefly.test:8180/realms/sandbox-customers",
  "sub": "opaque-customer-subject",
  "aud": "sandbox-api",
  "exp": 2000000000,
  "tenant_id": "synthetic-tenant",
  "principal_kind": "HUMAN",
  "client_id": "sandbox-web",
  "party_id": "a11f3098-6513-4db4-a474-e29ce1d6f34a",
  "scope": "openid profile email"
}
```

The subject may happen to look like a UUID in one issuer, but clients must still treat it as opaque. The party UUID identifies a linked business actor; it is not the subject and cannot replace signature/issuer validation. The absent `nbf` is valid for a profile that allows its absence.

## Configure and protect the links

In the generated declarative user profile, `tenant_id`, `party_id` and `staff_actor_id` are single-valued, administrator-managed attributes. Unmanaged attributes are disabled. Customer profile editing cannot create a staff relationship, change tenant ownership or persist a shadow population/client claim.

An authorized provisioning adapter must obtain links through their authoritative business APIs and write them with narrow identity-management permissions. Do not map self-registration fields, uncontrolled broker attributes, caller headers or frontend values into trusted links. Changes to email/display name do not change the business actor.

Configure client roles separately if the application uses them. The generated clients have `fullScopeAllowed=false`; the identity examples do not distribute financial entitlements. A receiver mapping Keycloak client roles must select its own client path, such as `resource_access.sandbox-api.roles`, rather than accepting every client's roles.

## Translate claims into application decisions

A receiver first verifies the token, then projects the principal. Required missing or ambiguous tenant values must refuse authentication. Jafly preserves the opaque subject/tenant and verified claims; custom party/staff/client values remain claims, not dedicated permission fields.

Before a business action, validate the current linked actor, tenant/resource binding, required consent and policy. Recheck expiration after asynchronous work when authority must still be live at mutation. Authentication context such as `acr`, `amr` or email verification must have an explicit meaning in the operation's policy; its presence alone does not establish KYC, payment SCA or a legal-person mandate.

Continue with [Jafly configuration](jafly.md), [application integration](integration-contract.md) and [authorization at each service](zero-trust.md).
