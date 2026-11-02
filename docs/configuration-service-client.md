# Configure a service client for tenant lookup

An unattended application uses its own client-credentials identity. It does not sign in as an employee or borrow a customer's refresh token. Firefly Identity provides an optional sandbox profile for a service that needs Configuration's current tenant-resource binding.

This profile creates the identity client only. To perform the business lookup, deploy Configuration with the current-binding API enabled, register the exact service identity in its authorization policy and configure the appropriate generated producer SDK.

## Create the optional sandbox client

Build the theme and choose a new owned state directory as described in [sandbox setup](sandbox.md). Supply all three client inputs together:

```sh
python3 scripts/generate.py --mode sandbox \
  --output .state/configuration-example \
  --configuration-lookup-client-id configuration-lookup \
  --configuration-lookup-realm customers \
  --configuration-lookup-tenant synthetic-platform-namespace
```

| Input | Meaning |
| --- | --- |
| `--configuration-lookup-client-id` | Distinct nonreserved service client ID |
| `--configuration-lookup-realm` | Existing generated population realm: `customers`, `workforce` or `institutions` |
| `--configuration-lookup-tenant` | Nonblank bounded opaque platform namespace, not an invented resource-tenant UUID |
| `--output` | New state directory; generation refuses an existing path |

The generated `configuration-lookup-client.json` supplies issuer, client ID, tenant, audience, token endpoint, JWKS URI and a relative `secret_file` reference. The random secret is stored at `secrets/configuration-lookup-client-secret` inside the protected state directory. Read it only in the service process or secret-management integration; do not print it or put it in browser configuration.

Start the matching owned stack using the normal lifecycle and selected state:

```sh
python3 scripts/sandbox.py preflight --state .state/configuration-example
python3 scripts/sandbox.py pull --state .state/configuration-example
python3 scripts/sandbox.py up --state .state/configuration-example
```

Use an environment meeting the sandbox resource requirements. A different output creates a different isolated environment; it does not migrate an existing realm.

## Request a machine access token

Configure the service's OAuth client with the descriptor's issuer/token endpoint, registered client ID and protected secret. Send a token-endpoint POST using confidential client authentication and form field `grant_type=client_credentials`. Use the client's supported HTTP Basic client authentication; do not place its secret in a URL or command-line argument.

A successful response contains a bearer `access_token` and its lifetime. The client-credentials profile does not issue a refresh token; obtain a new token with the same workload credential before expiry. Verify the response and use the token only at the intended API.

| Issued field | Meaning |
| --- | --- |
| `sub` | Actual issuer-generated opaque service subject; discover from a verified token, never derive from the client ID |
| `tenant_id` | Exact configured namespace |
| `client_id` | This service's registered client ID |
| `principal_kind` | `MACHINE` |
| `aud` | Includes the sandbox receiver `sandbox-api` |
| `party_id`, `staff_actor_id` | Absent: the workload is not a human |

Only this opt-in profile enables its service account. It disables standard interactive, direct password, implicit, device, CIBA and standard token-exchange grants, has no callbacks and retains only the `basic` client scope. [Claims](provider-claim-profile.md) explains the common token format and [application integration](integration-contract.md) explains receiver validation.

## Authorize the Configuration lookup

Configure the receiving service's exact HTTPS issuer/audience and authorization policy for the verified service subject and namespace. The relevant operation is:

```http
GET /api/v1/tenant-resource-bindings/current
Authorization: Bearer <service-access-token>
```

The current-binding API must be present in the installed Configuration version and enabled through `firefly.configuration.tenant-resource-binding.enabled`. Configure current policy for the action `configuration.tenant-resource-binding.current` and the exact allowed URL/operation at the receiver's required phases. Use a finite request/decision budget and refuse unavailable or stale decisions.

The lookup maps the identity namespace `(verified issuer, platform tenant string)` to a separately typed resource-tenant UUID and its current binding metadata. Preserve the original namespace in the caller; do not rewrite its principal into the returned resource UUID. Use the installed producer SDK's response model and validate the returned namespace, resource UUID, binding version/digest, eligibility and observation deadline according to that API's contract.

The generic policy input does not automatically forward every custom claim. Do not assume that `client_id` or `principal_kind` is enforced merely because it appears in a token; bind the actual verified issuer/subject/tenant used by the receiving policy. A token authenticates the service but cannot create a missing tenant binding.

## Restrict the service identity

Grant only the current-binding lookup needed by the application. Do not reuse a workforce/operator role or invent OAuth scopes to bypass policy. A Configuration lookup grants no payment, insurance, document-signing or recovery command by itself.

Rotate the client secret through the issuer and service secret store with an explicit cutover procedure. Do not modify an initialization file and expect a retained realm's credential to change automatically. Keep the workload separate from human delegation, support case authorization and native recovery clients. See [service authorization](zero-trust.md) and [operations](operations.md).
