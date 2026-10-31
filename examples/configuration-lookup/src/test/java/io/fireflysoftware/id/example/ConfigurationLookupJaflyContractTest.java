package io.fireflysoftware.id.example;

import org.fireflyframework.security.core.key.InMemoryKeyManagementAdapter;
import org.fireflyframework.security.rs.ResourceServerAutoConfiguration;
import org.fireflyframework.security.rs.ResourceServerProperties;
import org.fireflyframework.security.webflux.authentication.FireflyAuthenticationToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurationLookupJaflyContractTest {
    private static final ResourceServerAutoConfiguration FRAMEWORK = new ResourceServerAutoConfiguration();
    private static String issuer;
    private static String audience;
    private static String tenant;
    private static String client;
    private static String compact;
    private static Jwt verified;

    @BeforeAll static void nativeServiceToken() throws Exception {
        issuer = required("FIREFLY_ID_LOOKUP_ISSUER");
        audience = required("FIREFLY_ID_LOOKUP_AUDIENCE");
        tenant = required("FIREFLY_ID_LOOKUP_TENANT");
        client = required("FIREFLY_ID_LOOKUP_CLIENT_ID");
        Path token = Path.of(required("FIREFLY_ID_LOOKUP_TOKEN_FILE"));
        assertTrue(token.isAbsolute() && Files.isRegularFile(token) && !Files.isSymbolicLink(token));
        assertTrue(Files.size(token) > 0 && Files.size(token) < 32768);
        assertTrue(Files.getPosixFilePermissions(token).stream().allMatch(value -> value == PosixFilePermission.OWNER_READ || value == PosixFilePermission.OWNER_WRITE));
        compact = Files.readString(token).strip();
        try { verified = decode(compact, properties(issuer, audience)); }
        catch (RuntimeException error) { fail("Published decoder refused synthetic service token; raw errors are suppressed"); }
        assertNotNull(verified);
    }

    @Test void preservesActualServiceSubjectAndNormalizedExpiryWithoutHumanAuthority() throws Exception {
        var properties = properties(issuer, audience);
        var converter = FRAMEWORK.fireflyJwtAuthenticationConverter(
                FRAMEWORK.fireflyPrincipalFactory(FRAMEWORK.fireflyAuthorityMappingPort(properties)), properties);
        var authentication = converter.convert(verified).block(Duration.ofSeconds(20));
        assertInstanceOf(FireflyAuthenticationToken.class, authentication);
        var principal = ((FireflyAuthenticationToken) authentication).securityPrincipal();
        assertEquals(issuer, principal.issuer());
        assertEquals(verified.getSubject(), principal.subject());
        assertTrue(principal.subject() != null && !principal.subject().isBlank());
        assertEquals(tenant, principal.tenantId());
        assertEquals(client, principal.claim("client_id", String.class));
        assertEquals("MACHINE", principal.claim("principal_kind", String.class));
        assertFalse(principal.claims().containsKey("party_id"));
        assertFalse(principal.claims().containsKey("staff_actor_id"));
        assertTrue(principal.authorities().isEmpty());
        assertTrue(principal.attributes().isEmpty());
        assertInstanceOf(Instant.class, principal.claims().get("exp"));
        assertEquals(verified.getExpiresAt(), principal.claim("exp", Instant.class));
        assertTrue(principal.claim("exp", Instant.class).isAfter(Instant.now()));
        if (verified.getClaims().containsKey("nbf")) assertInstanceOf(Instant.class, principal.claims().get("nbf"));
        else assertFalse(principal.claims().containsKey("nbf"));
        Path output = Path.of("../../.work/configuration-lookup/framework-summary.json");
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, "{\"published_jafly\":\"26.10.23\",\"signature_verified\":true,\"exp_type\":\"Instant\",\"nbf_present\":"
                + principal.claims().containsKey("nbf") + ",\"human_links\":false,\"financial_authorities\":false,\"scope\":\"Synthetic service issuance; no Configuration authorization\"}\n");
    }

    @Test void refusesAnotherIssuer() { assertThrows(JwtException.class, () -> decode(compact, properties(issuer + "/untrusted", audience))); }
    @Test void refusesAnotherAudience() { assertThrows(JwtException.class, () -> decode(compact, properties(issuer, "unrelated-resource"))); }
    @Test void refusesTamperedSignature() {
        String[] parts = compact.split("\\.", -1);
        String altered = parts[0] + "." + parts[1] + "." + (parts[2].startsWith("A") ? "B" : "A") + parts[2].substring(1);
        assertThrows(JwtException.class, () -> decode(altered, properties(issuer, audience)));
    }

    private static ResourceServerProperties properties(String trustedIssuer, String intendedAudience) {
        var value = new ResourceServerProperties(); value.setIssuer(trustedIssuer); value.setAudiences(List.of(intendedAudience));
        value.setJwkSetUri(issuer + "/protocol/openid-connect/certs"); value.setSignatureAlgorithms(List.of("RS256"));
        value.setTenantClaimPaths(List.of("tenant_id")); value.setTenantRequired(true);
        value.setRoleClaimPaths(List.of("realm_access.roles", "resource_access.sandbox-api.roles"));
        value.setScopeClaimPaths(List.of("scope")); value.setStrictPolicy(true); return value;
    }
    private static Jwt decode(String token, ResourceServerProperties properties) {
        return FRAMEWORK.fireflyReactiveJwtDecoder(new InMemoryKeyManagementAdapter(), properties).decode(token).block(Duration.ofSeconds(20));
    }
    private static String required(String name) {
        String value = System.getenv(name); assertTrue(value != null && !value.isBlank(), "Explicit synthetic service contract required; tests never skip"); return value;
    }
}
