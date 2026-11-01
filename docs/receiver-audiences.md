# Receiver audience measurement

`tooling/receiver-audience-runtime.mjs` measures the actual customer access-token audience independently for the interactive public `sandbox-web` client and confidential `sandbox-backend` client. It changes no provider audiences and imposes no exact-single-audience rule. The expected API receiver is `sandbox-api`; `account` membership is recorded independently, whether present or absent. Audience membership authorizes a receiver, not a business operation or tenant entitlement.

Each client uses a separate fresh browser context, the protected synthetic customer credentials, a real authorization code, state, nonce and S256 PKCE. The confidential client also authenticates its code exchange with its own protected secret. Callback listeners bind only to loopback, on ports 3000 and 8081, and are closed with the browser on success or failure. The runner does not use a password grant, client-credentials grant, service account, copied token or fabricated identity. It does not change users, roles, passwords, counters or client settings.

Before recording a result, the runner verifies the actual provider's RS256 signature through its advertised JWKS, exact issuer, future numeric expiration, applicable not-before time, nonempty subject and expected audience membership. It checks the identity token's client audience and nonce, the access token's authorized client, and agreement between both subjects. This is a provider-token measurement, not proof that a consuming framework accepts every valid audience shape or applies online revocation correctly.

Run from the repository root against the explicitly owned synthetic stack with the pinned Playwright installation and the exact checked-out hosted `GITHUB_SHA`:

```sh
node tooling/receiver-audience-runtime.mjs
```

`FIREFLY_ID_STATE` may select the existing owned sandbox directory. Credentials remain in its owner-only `credentials.json`; do not upload that file. Hosted qualification runs this lane sequentially with the other browser lanes, guarded by successful stack and browser setup even if another flow failed.

The only per-client console/artifact fields are the configured client name, `audienceType` (`string` or `array`), `audienceCount`, `resourcePresent` and `accountPresent`. `.work/receiver-audiences/summary.json` adds schema version, exact source commit and a fixed passed/failed status. It contains no actual audience values, subject, token, credentials, headers or raw errors/URLs. A failed result can contain only the already validated client measurements; require overall `status=passed` and both clients before treating the lane as qualified. Account-console audience and positive Account API evidence belong to the separate main console runtime.

The shape is observed rather than predicted. Multiple audiences are not rejected merely because there is more than one. Receiver membership remains mandatory. Any consuming owner that requires exactly one audience must review that contract against the measured signed tokens; this probe does not weaken its audience checks or declare that integration complete. Production audience/authorization contracts remain separate from these provisional sandbox examples.

Current execution status: [ordinary hosted distribution 41331178246](https://github.com/fireflysoftwaresolutions/firefly-id/actions/runs/41331178246) passed the separate public/confidential interactive audience measurements at source `15fd1b7ffa045835f3d4c71fdcc33020d8f24ecf`. The bounded report records one resource audience in each measured token and no account audience; this observation does not impose an exact-single-audience rule on every consumer. Initial local execution was withheld under the resource restriction. Target deployment and actual consumer authorization remain separate acceptance. See [evidence](evidence.md).
