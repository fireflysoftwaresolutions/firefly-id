package org.fireflyframework.id.example;

import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.core.key.InMemoryKeyManagementAdapter;
import org.fireflyframework.security.rs.ResourceServerAutoConfiguration;
import org.fireflyframework.security.rs.ResourceServerProperties;
import org.fireflyframework.security.webflux.authentication.FireflyAuthenticationToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.publisher.Mono;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakJaflyContractTest {
    private static final String ISSUER = "http://id.firefly.test:8180/realms/sandbox-customers";
    private static final String JWKS = ISSUER + "/protocol/openid-connect/certs";
    private static final Duration DEADLINE = Duration.ofSeconds(20);
    private static final ResourceServerAutoConfiguration FRAMEWORK = new ResourceServerAutoConfiguration();
    private static String token;
    private static Jwt verified;

    @BeforeAll
    static void verifyBrowserIssuedTokenWithPublishedDecoder() throws Exception {
        String filename = System.getenv("FIREFLY_ID_TOKEN_FILE");
        assertTrue(filename != null && !filename.isBlank(),
                "FIREFLY_ID_TOKEN_FILE must name the protected browser-issued token file; runtime tests never skip");
        Path path = Path.of(filename);
        assertTrue(path.isAbsolute() && Files.isRegularFile(path) && !Files.isSymbolicLink(path),
                "Token file must be an absolute regular file, not a symlink");
        assertTrue(Files.size(path) > 0 && Files.size(path) < 32768, "Unexpected token file size");
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
        assertTrue(permissions.stream().allMatch(permission ->
                        permission == PosixFilePermission.OWNER_READ || permission == PosixFilePermission.OWNER_WRITE),
                "Token file must be readable only by its owner");
        token = Files.readString(path).strip();
        assertTrue(token.split("\\.", -1).length == 3, "Expected a compact signed JWT");
        try {
            verified = decode(token, properties(ISSUER, "sandbox-api"));
        } catch (RuntimeException failure) {
            // Do not attach the JWT, decoded claims, or an upstream error containing them to test reports.
            fail("Published Jafly live JWKS validation failed (" + failure.getClass().getSimpleName() + ")");
        }
        assertNotNull(verified, "Live JWKS decoder returned no token");
    }

    @Test
    void projectsVerifiedOpaqueIdentityWithoutBusinessEntitlements() {
        SecurityPrincipal principal = project(verified, properties(ISSUER, "sandbox-api"));
        assertEquals(ISSUER, principal.issuer());
        assertTrue(principal.subject() != null && !principal.subject().isBlank());
        assertEquals(verified.getSubject(), principal.subject(), "Subject must be preserved without UUID coercion");
        assertEquals("synthetic-tenant", principal.tenantId(), "Tenant is an opaque namespace");
        assertEquals("HUMAN", principal.claim("principal_kind", String.class));
        assertEquals("sandbox-web", principal.claim("client_id", String.class));
        assertTrue(principal.authorities().isEmpty(), "Identity examples must not acquire financial authorities");
        assertTrue(Set.of("openid", "profile", "email").containsAll(principal.scopes()),
                "Sandbox token must carry only identity scopes");
        assertTrue(principal.attributes().isEmpty(), "No product enrichment is inferred by authentication");
        assertInstanceOf(Instant.class, principal.claims().get("exp"));
        assertEquals(verified.getExpiresAt(), principal.claim("exp", Instant.class));
        assertTrue(principal.claim("exp", Instant.class).isAfter(Instant.now()));
        if (verified.getClaims().containsKey("nbf")) {
            assertInstanceOf(Instant.class, principal.claims().get("nbf"));
            assertEquals(verified.getNotBefore(), principal.claim("nbf", Instant.class));
            System.out.println("Jafly verified claim shape: exp=Instant; nbf=Instant; tenant=opaque; principal_kind=HUMAN");
        } else {
            assertFalse(principal.claims().containsKey("nbf"), "Do not fabricate missing not-before proof");
            System.out.println("Jafly verified claim shape: exp=Instant; nbf=absent; tenant=opaque; principal_kind=HUMAN");
        }
    }

    @Test
    void rejectsTamperedSignatureAtTheRealJwksBoundary() {
        String[] parts = token.split("\\.", -1);
        assertFalse(parts[2].isEmpty());
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + parts[1] + "." + replacement + parts[2].substring(1);
        assertThrows(JwtException.class, () -> decode(tampered, properties(ISSUER, "sandbox-api")));
    }

    @Test
    void rejectsWrongConfiguredIssuerWithTheRealJwksBoundary() {
        assertThrows(JwtException.class,
                () -> decode(token, properties(ISSUER + "/untrusted", "sandbox-api")));
    }

    @Test
    void rejectsWrongConfiguredAudienceWithTheRealJwksBoundary() {
        assertThrows(JwtException.class,
                () -> decode(token, properties(ISSUER, "not-the-sandbox-api")));
    }

    @Test
    void rejectsCustomerTokenAtWorkforceIssuerBoundaryEvenUsingCustomerKeys() {
        String workforceIssuer = "http://id.firefly.test:8180/realms/sandbox-workforce";
        assertThrows(JwtException.class,
                () -> decode(token, properties(workforceIssuer, "sandbox-api")));
    }

    @Test
    void projectionOnlyRejectsMissingRequiredTenant() {
        Map<String, Object> claims = new HashMap<>(verified.getClaims());
        claims.remove("tenant_id");
        assertThrows(OAuth2AuthenticationException.class,
                () -> project(projectionFixture(claims), properties(ISSUER, "sandbox-api")));
    }

    @Test
    void projectionOnlyRejectsAmbiguousRequiredTenant() {
        Map<String, Object> claims = new HashMap<>(verified.getClaims());
        claims.put("tenant_id", List.of("synthetic-tenant", "another-tenant"));
        assertThrows(OAuth2AuthenticationException.class,
                () -> project(projectionFixture(claims), properties(ISSUER, "sandbox-api")));
    }

    @Test
    void projectionOnlyPreservesAnOpaqueNonUuidSubject() {
        Map<String, Object> claims = new HashMap<>(verified.getClaims());
        claims.put("sub", "opaque/subject:external-human");
        SecurityPrincipal principal = project(projectionFixture(claims), properties(ISSUER, "sandbox-api"));
        assertEquals("opaque/subject:external-human", principal.subject());
        assertEquals("synthetic-tenant", principal.tenantId());
    }

    private static ResourceServerProperties properties(String issuer, String audience) {
        ResourceServerProperties properties = new ResourceServerProperties();
        properties.setIssuer(issuer);
        properties.setAudiences(List.of(audience));
        properties.setJwkSetUri(JWKS);
        properties.setSignatureAlgorithms(List.of("RS256"));
        properties.setTenantClaimPaths(List.of("tenant_id"));
        properties.setTenantRequired(true);
        properties.setRoleClaimPaths(List.of("realm_access.roles", "resource_access.sandbox-api.roles"));
        properties.setScopeClaimPaths(List.of("scope"));
        properties.setStrictPolicy(true);
        return properties;
    }

    private static Jwt decode(String compact, ResourceServerProperties properties) {
        return FRAMEWORK.fireflyReactiveJwtDecoder(new InMemoryKeyManagementAdapter(), properties)
                .decode(compact).block(DEADLINE);
    }

    private static SecurityPrincipal project(Jwt jwt, ResourceServerProperties properties) {
        Converter<Jwt, Mono<AbstractAuthenticationToken>> converter = FRAMEWORK.fireflyJwtAuthenticationConverter(
                FRAMEWORK.fireflyPrincipalFactory(FRAMEWORK.fireflyAuthorityMappingPort(properties)), properties);
        AbstractAuthenticationToken authentication = converter.convert(jwt).block(DEADLINE);
        assertInstanceOf(FireflyAuthenticationToken.class, authentication);
        return ((FireflyAuthenticationToken) authentication).securityPrincipal();
    }

    private static Jwt projectionFixture(Map<String, Object> claims) {
        // This object is deliberately not signature proof. Only converter behavior is tested below admission.
        return Jwt.withTokenValue("projection-only-not-a-signed-token")
                .headers(headers -> headers.putAll(verified.getHeaders()))
                .claims(target -> target.putAll(claims))
                .build();
    }
}
