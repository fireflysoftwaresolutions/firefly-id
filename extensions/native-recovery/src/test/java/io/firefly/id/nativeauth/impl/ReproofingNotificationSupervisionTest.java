package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingNotificationSupervisionTest {
    @Test void dedicatedClientCanOnlyDispatchAndReadStatus() {
        var session = session("notifications");
        assertDoesNotThrow(() -> ReproofingRpcImpl.workload(session, basic("notifications"), "dispatch"));
        assertDoesNotThrow(() -> ReproofingRpcImpl.workload(session, basic("notifications"), "notification-status"));
        for (String route : List.of("prepare", "admit", "journal", "unknown"))
            assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic("notifications"), route));
    }
    @Test void dedicatedConfigurationRemovesCoreAndDomainNotificationAuthority() {
        var session = session("notifications");
        for (String id : List.of("core", "domain")) for (String route : List.of("dispatch", "notification-status"))
            assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic(id), route));
        assertDoesNotThrow(() -> ReproofingRpcImpl.workload(session, basic("core"), "journal"));
        assertDoesNotThrow(() -> ReproofingRpcImpl.workload(session, basic("domain"), "prepare"));
    }
    @Test void legacyCoreRetainsOnlyDispatchWithoutDedicatedConfiguration() {
        var session = session(null);
        assertDoesNotThrow(() -> ReproofingRpcImpl.workload(session, basic("core"), "dispatch"));
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic("core"), "notification-status"));
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic("domain"), "notification-status"));
    }
    @Test void mixedOrBlankDedicatedClientFailsClosed() {
        for (String id : List.of("core", "domain", "", " notifications ")) {
            var session = session(id);
            assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic("core"), "dispatch"));
        }
    }
    @Test void dedicatedClientKeepsEveryOrdinaryGrantDisabledAndFreshLookup() {
        var session = session("notifications"); var realm = session.getContext().getRealm();
        var client = session.getProvider(ClientProvider.class).getClientByClientId(realm, "notifications");
        for (String attribute : List.of("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled", "standard.token.exchange.enabled", "oauth2.jwt.authorization.grant.enabled")) {
            when(client.getAttribute(attribute)).thenReturn("true");
            assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic("notifications"), "dispatch"));
            when(client.getAttribute(attribute)).thenReturn("false");
        }
        when(client.isServiceAccountsEnabled()).thenReturn(true);
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, basic("notifications"), "notification-status"));
        verify(session.getProvider(ClientProvider.class), atLeastOnce()).getClientById(realm, "notifications-row");
    }
    @Test void dispatchBodyDefaultsToTenAndAcceptsOnlyIntegerOneThroughTen() throws Exception {
        var method = dispatchParser();
        assertEquals(10, method.invoke(null, "{}"));
        assertEquals(1, method.invoke(null, "{\"limit\":1}"));
        assertEquals(10, method.invoke(null, "{\"limit\":10}"));
        for (String body : List.of("", "null", "[]", "1", "{\"limit\":null}", "{\"limit\":0}", "{\"limit\":11}", "{\"limit\":-1}", "{\"limit\":1.0}", "{\"limit\":\"1\"}", "{\"limit\":true}", "{\"limit\":1,\"limit\":2}", "{\"approved\":true}", "{} {}", "{\"limit\":999999999999999999999}"))
            assertThrows(java.lang.reflect.InvocationTargetException.class, () -> method.invoke(null, body), body);
    }
    @Test void statusBodyIsExactlyEmptyObject() throws Exception {
        var method = ReproofingResourceImpl.class.getDeclaredMethod("statusBody", String.class);
        assertDoesNotThrow(() -> method.invoke(null, "{}"));
        for (String body : List.of("", "null", "[]", "{\"limit\":1}", "{} {}"))
            assertThrows(java.lang.reflect.InvocationTargetException.class, () -> method.invoke(null, body));
    }
    @Test void aggregateWireUsesOneRealmFilteredDatabaseSnapshotWithoutEntityReadsOrMutation() throws Exception {
        var session = session("notifications"); var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        var query = mock(Query.class, RETURNS_SELF);
        when(em.createNativeQuery(anyString())).thenAnswer(call -> {
            String sql = call.getArgument(0);
            assertTrue(sql.contains("current_timestamp")); assertTrue(sql.contains("n.realm_id = :realm"));
            assertTrue(sql.contains("n.status is null")); assertTrue(sql.contains("not in ('PENDING','SENDING','DELIVERED','FAILED')"));
            assertTrue(sql.contains("n.attempts > 0")); assertTrue(sql.contains("n.next_attempt_at <= snapshot.now"));
            assertFalse(sql.contains("subject")); assertFalse(sql.contains("destination")); assertFalse(sql.contains("lease_token"));
            return query;
        });
        when(query.getSingleResult()).thenReturn(new Object[]{1700000000123L, 3L, 2L, 1L, 5L, 6L, 2L, 4L, 9L});
        Class<?> type = Class.forName("io.firefly.id.nativeauth.impl.ReproofingNotificationStatusImpl");
        Object snapshot = type.getDeclaredMethod("read", KeycloakSession.class).invoke(null, session);
        var json = ReproofingWireImpl.JSON.readTree(ReproofingWireImpl.json(snapshot));
        var names = new HashSet<String>(); json.fieldNames().forEachRemaining(names::add);
        assertEquals(Set.of("observedAt", "pending", "sending", "retrying", "delivered", "failed", "invalid", "due", "oldestDueDelaySeconds"), names);
        assertEquals("2023-11-14T22:13:20.123Z", json.get("observedAt").asText());
        assertEquals(3L, json.get("pending").asLong()); assertEquals(2L, json.get("invalid").asLong()); assertEquals(9L, json.get("oldestDueDelaySeconds").asLong());
        verify(query).setParameter("realm", "realm"); verify(em, times(1)).createNativeQuery(anyString());
        verify(query, never()).executeUpdate(); verify(em, never()).createQuery(anyString(), eq(ReproofingNotificationImpl.class));
    }
    private java.lang.reflect.Method dispatchParser() throws Exception { return ReproofingResourceImpl.class.getDeclaredMethod("dispatchLimit", String.class); }
    private String basic(String id) { return "Basic " + Base64.getEncoder().encodeToString((id + ":secret").getBytes(StandardCharsets.UTF_8)); }
    private KeycloakSession session(String dedicated) {
        var session = mock(KeycloakSession.class); var context = mock(KeycloakContext.class); var realm = mock(RealmModel.class);
        when(session.getContext()).thenReturn(context); when(context.getRealm()).thenReturn(realm); when(realm.getId()).thenReturn("realm"); when(realm.getName()).thenReturn("customers");
        var attributes = new HashMap<>(Map.of("enabled", "true", "population", "HUMAN", "allowed-origin", "https://id.test", "issuer", "https://id.test/realms/customers", "core-workload-client-id", "core", "domain-workload-client-id", "domain", "ttl-seconds", "600"));
        if (dedicated != null) attributes.put("notification-workload-client-id", dedicated);
        when(realm.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.getArgument(0, String.class).replace("firefly.reproofing.", "")));
        var clients = mock(ClientProvider.class); when(session.getProvider(ClientProvider.class)).thenReturn(clients);
        var em = mock(EntityManager.class); var jpa = mock(JpaConnectionProvider.class); when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa); when(jpa.getEntityManager()).thenReturn(em);
        for (String id : List.of("core", "domain", "notifications")) {
            var client = mock(ClientModel.class); when(client.getId()).thenReturn(id + "-row"); when(client.isEnabled()).thenReturn(true); when(client.validateSecret("secret")).thenReturn(true);
            var entity = new org.keycloak.models.jpa.entities.ClientEntity(); entity.setId(id + "-row"); when(em.find(org.keycloak.models.jpa.entities.ClientEntity.class, id + "-row")).thenReturn(entity);
            when(clients.getClientByClientId(realm, id)).thenReturn(client); when(clients.getClientById(realm, id + "-row")).thenReturn(client);
        }
        return session;
    }
}
