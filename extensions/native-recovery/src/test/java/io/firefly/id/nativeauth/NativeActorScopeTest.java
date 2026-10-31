package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeActorScopeTest {
    @Test void nativeSigningUsesScopeFieldThatSurvivesActualAccessTokenDecoding() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        var realm = session.getContext().getRealm();
        when(realm.getName()).thenReturn("customers");
        Map<String, String> attributes = Map.ofEntries(
                Map.entry("issuer", "https://identity.test/realms/customers"), Map.entry("population", "HUMAN"),
                Map.entry("client-id", "recovery"), Map.entry("tenant-attribute", "tenant_id"),
                Map.entry("link-attribute", "party_id"), Map.entry("allowed-origin", "https://identity.test"),
                Map.entry("domain-audience", "recovery-domain"), Map.entry("core-audience", "recovery-core"),
                Map.entry("core-workload-client-id", "native-core"), Map.entry("domain-workload-client-id", "native-domain"),
                Map.entry("ttl-seconds", "300"));
        when(realm.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.getArgument(0, String.class)
                .substring("firefly.native-recovery.".length())));
        when(session.tokens().encode(any(AccessToken.class))).thenAnswer(call -> {
            AccessToken token = call.getArgument(0);
            assertEquals("firefly.recovery", token.getScope());
            assertFalse(token.getOtherClaims().containsKey("scope"));
            return JsonSerialization.writeValueAsString(token);
        });
        NativeCeremony ceremony = new NativeCeremony(); ceremony.id = "ceremony"; ceremony.subject = "subject";
        ceremony.generation = "generation"; ceremony.ownerLink = "owner"; ceremony.expiresAt = System.currentTimeMillis() + 120000;
        ceremony.bindingJson = NativeActor.json(new NativeContracts.Binding("https://identity.test/realms/customers", "opaque",
                "recovery", null, "subject", "https://identity.test/realms/customers", "customers", "subject", "HUMAN",
                NativeContracts.PURPOSE, "generation"));
        AccessToken decoded = JsonSerialization.readValue(NativeActor.sign(session, ceremony), AccessToken.class);
        assertEquals("firefly.recovery", decoded.getScope());
        assertFalse(decoded.getOtherClaims().containsKey("scope"));
        assertEquals("firefly-restricted-recovery", decoded.getType());
    }
}
