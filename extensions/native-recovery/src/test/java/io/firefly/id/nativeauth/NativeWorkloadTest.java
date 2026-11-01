package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeWorkloadTest {
    private final NativeProfile profile = new NativeProfile("https://id.test/realms/customers", "HUMAN", "recovery",
            "tenant_id", "party_id", "https://id.test", "domain", "core", "native-core", "native-domain", 300);

    @Test void disabledGrantsPreserveCoreAndDomainRouteBoundaries() {
        for (String id : List.of("native-core", "native-domain")) {
            var session = session(id);
            for (String route : List.of("admit", "journal"))
                assertDoesNotThrow(() -> workload(session, id, route));
            if ("native-core".equals(id)) {
                for (String route : List.of("issue", "verify", "reject"))
                    assertDoesNotThrow(() -> workload(session, id, route));
                assertThrows(NativeRefusal.class, () -> workload(session, id, "audit"));
            } else {
                assertDoesNotThrow(() -> workload(session, id, "audit"));
                for (String route : List.of("issue", "verify", "reject"))
                    assertThrows(NativeRefusal.class, () -> workload(session, id, route));
            }
            assertThrows(NativeRefusal.class, () -> workload(session, id, "unknown"));
        }
    }

    @Test void implicitGrantRefusesBothWorkloadIdentities() {
        for (String id : List.of("native-core", "native-domain")) {
            var session = session(id); var client = client(session, id);
            when(client.isImplicitFlowEnabled()).thenReturn(true);
            assertThrows(NativeRefusal.class, () -> workload(session, id, "admit"));
        }
    }

    @Test void optionalGrantsMustBeAbsentOrExactlyDisabled() {
        for (String id : List.of("native-core", "native-domain")) {
            var session = session(id); var client = client(session, id);
            for (String attribute : List.of("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
                    "standard.token.exchange.enabled", "oauth2.jwt.authorization.grant.enabled")) {
                for (String value : List.of("true", "", "FALSE", " true ")) {
                    when(client.getAttribute(attribute)).thenReturn(value);
                    assertThrows(NativeRefusal.class, () -> workload(session, id, "admit"), attribute + "=" + value);
                }
                when(client.getAttribute(attribute)).thenReturn("false");
                assertDoesNotThrow(() -> workload(session, id, "admit"));
                when(client.getAttribute(attribute)).thenReturn(null);
                assertDoesNotThrow(() -> workload(session, id, "admit"));
            }
        }
    }

    private KeycloakSession session(String id) {
        var session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        var client = mock(ClientModel.class);
        when(session.clients().getClientByClientId(session.getContext().getRealm(), id)).thenReturn(client);
        when(client.isEnabled()).thenReturn(true); when(client.validateSecret("secret")).thenReturn(true);
        return session;
    }
    private ClientModel client(KeycloakSession session, String id) {
        return session.clients().getClientByClientId(session.getContext().getRealm(), id);
    }
    private void workload(KeycloakSession session, String id, String route) throws Throwable {
        var method = NativeRpcServiceImpl.class.getDeclaredMethod("workload", KeycloakSession.class, NativeProfile.class, String.class, String.class);
        method.setAccessible(true);
        String header = "Basic " + Base64.getEncoder().encodeToString((id + ":secret").getBytes(StandardCharsets.UTF_8));
        try { method.invoke(null, session, profile, header, route); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }
}
