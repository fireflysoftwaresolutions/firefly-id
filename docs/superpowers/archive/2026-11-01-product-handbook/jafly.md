# Published Jafly JWKS integration fixture

[examples/jafly](../examples/jafly/pom.xml) is a genuine consumer of the published `org.fireflyframework:fireflyframework-security-resource-server:26.10.23` artifact. It inherits the published `fireflyframework-parent:26.10.23` with an empty `relativePath`, uses one release train, and includes no copied framework implementation, local source checkout, system-scoped JAR, or repository-specific Maven path. Maven Central returned HTTP 200 for both release POMs during metadata inspection on 2026-10-31. That metadata check does not prove dependency resolution or compilation.

## Run against the synthetic stack

Use Java 25 and Maven. Complete the safe-capacity and stack-readiness steps in [sandbox.md](sandbox.md), then obtain a fresh `sandbox-web` customer access token through the actual browser authorization-code flow with PKCE S256. The fixture does not use a password grant, mint an unsigned token, or substitute a locally signed token for the issuer's token.

The runner must resolve `id.firefly.test` to the sandbox host, reach port 8180, and write the browser-issued compact access token directly into an owner-only regular file. The hosted browser runner uses `.state/sandbox/runtime-token.txt` with mode 0600. Do not print or paste the token into the shell, command arguments, CI logs, test reports, screenshots, caches, or artifacts. Pass only its absolute file path:

```sh
export FIREFLY_ID_TOKEN_FILE="$PWD/.state/sandbox/runtime-token.txt"
mvn -B -ntp -f examples/jafly/pom.xml test
```

The environment variable is required. Missing/unprotected token files or unavailable live JWKS fail the suite; there is no skipped or mocked acceptance path. A token must still be unexpired when the fixture runs. The example does not delete retained state or the token; the owning runner controls the lifetime of its explicitly owned secret files. Exclude `examples/jafly/target/` from source control and do not publish test output if a future test or dependency logs credentials.

The configured customer issuer is exactly `http://id.firefly.test:8180/realms/sandbox-customers`; audience is `sandbox-api`; JWKS is that issuer's `/protocol/openid-connect/certs`. HTTP is the isolated local sandbox exception. Production must use the approved HTTPS issuer/audience and network/TLS configuration rather than promoting these example names.

## What the fixture exercises

The test calls the published `ResourceServerAutoConfiguration.fireflyReactiveJwtDecoder(new InMemoryKeyManagementAdapter(), properties)`. Setting `jwkSetUri` selects the real remote-JWKS decoder; the in-memory key adapter is required by the factory signature and is not used to sign or verify this external token. The allowlist is RS256, with explicit issuer and audience validators. It then calls the published authority mapper, `PrincipalFactory`, and `fireflyJwtAuthenticationConverter` with `tenantClaimPaths=[tenant_id]` and `tenantRequired=true`.

The live token path checks signature validation, exact customer issuer, intended audience, preserved opaque subject, the opaque string tenant `synthetic-tenant`, normalized `Instant` expiration, and the actual presence/absence of `nbf`. It emits only a fixed claim-shape summary. If `nbf` exists, its projected type/value must remain an `Instant`; if absent, the fixture records absence and does not create a synthetic not-before claim. Purpose-specific consumers that demand `nbf` still need an approved compatible issuance profile.

The customer example must project `principal_kind=HUMAN`, `client_id=sandbox-web`, no financial authorities, only identity scopes, and no inferred product attributes. A signed party reference is not a financial entitlement or authoritative business relationship. The fixture does not call a financial service or grant one permission.

Decoder rejection cases alter a signature byte, configure a different expected issuer, configure a different expected audience, and apply the workforce issuer policy to the customer token even while using the customer JWKS. This last case isolates issuer enforcement; it does not claim a separately obtained workforce token was exercised.

Separate, explicitly named **projection-only** cases copy an already verified JWT's claims into a new in-memory `Jwt` object, remove or make `tenant_id` ambiguous, and check that the required-tenant converter rejects both. Another projection-only case proves a non-UUID subject remains opaque. Those mutated objects never pass through the decoder and are not evidence of signature validation or a remotely accepted token.

## Reviewed official API source

These APIs were inspected at the exact public release tag, rather than inferred from another release:

- [ResourceServerAutoConfiguration](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-resource-server/src/main/java/org/fireflyframework/security/rs/ResourceServerAutoConfiguration.java) selects remote JWKS and constructs the configured converter and validators.
- [ResourceServerProperties](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-resource-server/src/main/java/org/fireflyframework/security/rs/ResourceServerProperties.java) defines issuer, audience, algorithm, claim-path, and required-tenant setters.
- [JwtToFireflyPrincipalConverter](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-resource-server/src/main/java/org/fireflyframework/security/rs/JwtToFireflyPrincipalConverter.java) and [ConfigurableTenantResolver](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-core/src/main/java/org/fireflyframework/security/core/tenant/ConfigurableTenantResolver.java) preserve a single opaque tenant and reject required unresolved/ambiguous projection.
- [PrincipalFactory](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-core/src/main/java/org/fireflyframework/security/core/context/PrincipalFactory.java), [SecurityPrincipal](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-api/src/main/java/org/fireflyframework/security/api/domain/SecurityPrincipal.java), and [FireflyAuthenticationToken](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-webflux/src/main/java/org/fireflyframework/security/webflux/authentication/FireflyAuthenticationToken.java) define the actual claims/principal API used by the assertions.
- [Published train's parent](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/build/parent/pom.xml) and [resource-server POM](https://github.com/fireflyframework/fireflyframework-jafly/blob/v26.10.23/modules/security-resource-server/pom.xml) define Java 25 and dependency/plugin versions.

## Acceptance boundary

At fixture creation, only POM XML parsing, exact-release API inspection, and public release-POM availability were checked. Local dependency download, compilation, and live tests were deliberately not run because the development host was below the disk gate. A future successful hosted Maven run must be reported separately with its run URL and actual test results; merely adding this fixture is not Jafly acceptance.

Even a green fixture proves only this published resource-server decoder and principal-projection path against the tested synthetic token. It does not prove a full application security filter chain, downstream policy enforcement, financial permissions, authorization-code implementation in a production application, customer registration/provisioning, or any OpenPlatform service's production acceptance. Firefly Identity and Jafly remain independent releases, with no framework source or behavior changes in this repository.
