# Optional Configuration lookup service client

This opt-in sandbox profile prepares a noninteractive application to obtain its own client-credentials token for the current Configuration tenant-binding lookup. It leaves browser, confidential interactive and introspection clients unchanged. Default sandbox generation still provisions no service accounts; production provisioning requires its reviewed deployment contract.

## Provision a fresh synthetic profile

After building the theme, explicitly select the existing realm, a distinct client ID and the opaque namespace:

```sh
python3 scripts/generate.py --mode sandbox \
  --output .state/configuration-example \
  --configuration-lookup-client-id configuration-lookup \
  --configuration-lookup-realm customers \
  --configuration-lookup-tenant synthetic-platform-namespace
```

The generator refuses incomplete/conflicting arguments and existing output. It creates a random credential under `secrets/configuration-lookup-client-secret` in the protected state directory. `configuration-lookup-client.json` contains configuration and a credential-file reference, never its value or an invented subject. Keep all generated state private. Preserve retained data and follow the normal sandbox lifecycle with the selected `--state` path.

The client permits client credentials only. Standard, implicit, password/direct access, device, CIBA and standard token-exchange grants are disabled. It has no redirects, optional scopes, authorization-service grant, human links or reused operator role. The built-in `basic` scope preserves the actual issuer-generated subject. Its access-token mappers emit the configured opaque `tenant_id`, its own `client_id`, truthful `principal_kind=MACHINE` and the existing receiver audience `sandbox-api`.

## Verify actual issuance

The hosted qualification workflow selects this profile explicitly in its fresh owned sandbox. It obtains a real client-credentials token, checks signature against the actual JWKS, verifies issuer/audience/tenant and absence of `party_id`/`staff_actor_id`, and exercises wrong-secret, password-grant and cross-realm refusals. A separate fixture passes that issued token through the genuine published Jafly 26.10.23 decoder and principal converter. It checks opaque subject preservation, normalized `Instant` expiry, honest optional `nbf` and absence of financial authorities. Tests do not skip when their required token is missing.

Only safe metadata and the bounded framework summary are eligible for evidence upload. The token stays in a mode-0600 state file and its credential is never uploaded. Read the actual workflow result before claiming successful issuance or decoder acceptance; source implementation is not runtime proof.

## Configuration authorization remains independent

The actual Configuration lookup identifies the caller by exact issuer, observed opaque service subject and opaque tenant. Obtain the subject from verified issuance; never derive it from a client ID, username, party ID or Core UUID. Concrete deployment issuer/audience, namespace and current policy data remain deployment inputs.

For the reviewed current-binding contract, the owning authorization policy must permit only the exact `GET /api/v1/tenant-resource-bindings/current` URL decision and `configuration.tenant-resource-binding.current` action at its required phases, with the actual namespace and finite budget. A token does not establish a binding or grant an insurance, payment or other business command. The reviewed generic OPA input does not forward `client_id` or `principal_kind`; their presence in evidence does not prove that Configuration enforces them. Do not invent OAuth scopes or reuse an operator role to bypass that contract.

This profile qualifies synthetic issuance separately from Configuration service, policy and generated-SDK consumer acceptance. It does not enable machine-to-human recovery, customer impersonation or BPO delegation.
