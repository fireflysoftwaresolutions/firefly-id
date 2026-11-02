# Troubleshooting

## The sandbox refuses to start

Run the lifecycle preflight and read its exact refusal. A disk refusal occurs before Docker; do not bypass it or prune unrelated storage. A missing theme requires `make theme`. A changed Compose hash means the generated ownership contract was modified; inspect the change and preserve retained data instead of editing the marker to pass.

Use the exact owned Compose file/project from `ownership.json` to inspect service status and bounded logs. Never print generated realm imports or environment/secret files into public logs. Keycloak readiness may take time while its dedicated PostgreSQL schema is first initialized. A failed import requires inspecting the current pinned schema, not disabling profile or issuer protections.

## Issuer or JWKS cannot be resolved

Confirm `id.firefly.test` resolves to loopback on the host and to Keycloak on the sandbox network. Inspect discovery from each actual caller. The canonical issuer is the browser-facing URL, including scheme and port. Container `localhost`, the Docker service name and an internal backchannel transport URL do not automatically become valid issuer aliases.

A TLS/proxy problem must be fixed at DNS, certificates, trusted forwarded headers or routing. Do not turn off issuer/audience or hostname validation. In production, restrict direct access to Keycloak and ensure a proxy overwrites incoming forwarding headers.

## Callback, logout or PKCE fails

Compare the request with the client's exact registered callback/logout allowlist and its S256 challenge. A changed scheme, hostname, port or path is a different URI. Do not add wildcards or enable password/implicit grants. Check the application's state/nonce and code-verifier storage and that a code is redeemed only once by the correct client.

## Credentials or realm changes did not take effect

First-start realm import skips an existing realm. PostgreSQL initialization also runs only for a new data directory. Editing an import or a mounted secret does not update retained identities/database passwords. Use a reviewed migration/admin operation, preserve a backup, and explicitly revoke affected sessions where required.

## A recovery message is missing

Use only the synthetic `example.invalid` accounts and local Mailpit. Confirm the realm's SMTP host is `mailpit:1025`, inspect the local mailbox and server delivery error, and check that the action is valid for the account. Never connect a sandbox to a real customer mail system to debug recovery. A successful mail delivery does not prove link expiry/reuse, factor replacement or lost-factor recovery.

## Branding or fonts are missing

Rebuild and verify the JAR includes all five theme properties, logo files, CSS, font and OFL. Confirm realm theme selection and the exact deployed artifact, then inspect resource responses and actual font loading. Production caches require a versioned artifact/restart strategy. Standalone brand preview success does not establish server theme success.

## A business action is refused after successful login

Check the verified principal population, issuer/audience, authoritative business link, current policy/consent, and Configuration namespace-to-resource binding. Authentication and email verification do not grant banking authority. A refused action must not be fixed by making user-controlled attributes trusted, substituting resource UUIDs into opaque tenant claims, or forwarding identity headers.
