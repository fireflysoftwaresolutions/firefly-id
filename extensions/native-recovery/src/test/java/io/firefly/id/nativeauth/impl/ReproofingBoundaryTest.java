package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.ReproofingContracts.*;
import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingBoundaryTest {
    @Test void missingFeatureAndWorkforceConfigurationDeny() {
        RealmModel realm = mock(RealmModel.class); when(realm.getName()).thenReturn("customers");
        assertThrows(RuntimeException.class, () -> new ReproofingConfigImpl(realm));
        when(realm.getAttribute("firefly.reproofing.enabled")).thenReturn("true"); when(realm.getAttribute("firefly.reproofing.population")).thenReturn("STAFF");
        assertThrows(RuntimeException.class, () -> new ReproofingConfigImpl(realm));
    }
    @Test void obsoleteDeliveryWorkerCannotUndoCommittedDelivery() {
        var notification = new ReproofingNotificationImpl(); notification.status = "SENDING"; notification.leaseToken = "new-attempt";
        assertFalse(ReproofingDispatcherImpl.owns(notification, "old-attempt"));
        assertTrue(ReproofingDispatcherImpl.owns(notification, "new-attempt"));
        notification.status = "DELIVERED";
        assertFalse(ReproofingDispatcherImpl.owns(notification, "new-attempt"));
    }
    @Test void domainWorkloadCannotReadJournalOrDispatchNotifications() {
        var session = mock(KeycloakSession.class); var context = mock(KeycloakContext.class); var realm = realm(); when(session.getContext()).thenReturn(context); when(context.getRealm()).thenReturn(realm);
        String header = "Basic " + Base64.getEncoder().encodeToString("domain-owner:secret".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, header, "journal"));
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, header, "dispatch"));
    }
    @Test void privateWorkloadWithOrdinaryGrantEnabledIsRejected() {
        var session = mock(KeycloakSession.class); var context = mock(KeycloakContext.class); var realm = realm(); var clients = mock(ClientProvider.class); var client = mock(ClientModel.class);
        when(session.getContext()).thenReturn(context); when(context.getRealm()).thenReturn(realm); when(session.clients()).thenReturn(clients); rawClient(session, realm, clients, client);
        when(client.isEnabled()).thenReturn(true); when(client.isStandardFlowEnabled()).thenReturn(true); when(client.validateSecret("secret")).thenReturn(true);
        String header = "Basic " + Base64.getEncoder().encodeToString("core-owner:secret".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, header, "admit"));
    }
    @Test void redactedObjectsNeverExposeEnrollmentOrAuthorization() {
        Binding binding = new Binding("issuer", "realm", "tenant", "private-subject", UUID.randomUUID(), "HUMAN", "CREDENTIAL_REPLACEMENT", "epoch", "revision", "private-nonce");
        assertFalse(binding.toString().contains("private-subject"));
        var view = new ReproofingEngineImpl.View("private-id", "private-csrf", "ENROLL", "https://private-provider", "private-secret", false, false, null);
        assertFalse(view.toString().contains("private"));
        assertFalse(new Journey(null, "private-provider").toString().contains("private"));
    }
    @Test void boundedFrameworkDecodedFormPreservesValuesAndRefusesDuplicatesOrUnexpectedFields() {
        var fields = new jakarta.ws.rs.core.MultivaluedHashMap<String, String>(); fields.add("csrf", "a+b c");
        assertEquals("a+b c", ReproofingResourceImpl.form(fields, 128).get("csrf"));
        fields.add("csrf", "duplicate"); assertThrows(RuntimeException.class, () -> ReproofingResourceImpl.form(fields, 128)); fields.remove("csrf");
        fields.add("approved", "true"); assertThrows(RuntimeException.class, () -> ReproofingResourceImpl.form(fields, 128)); fields.remove("approved");
        fields.add("password", "x".repeat(16384)); assertThrows(RuntimeException.class, () -> ReproofingResourceImpl.form(fields, 16384));
    }
    @Test void privateDeviceGrantClientIsRejected() { grantAttributeRefused("oauth2.device.authorization.grant.enabled"); }
    @Test void privateCibaGrantClientIsRejected() { grantAttributeRefused("oidc.ciba.grant.enabled"); }
    @Test void privateStandardTokenExchangeClientIsRejected() { grantAttributeRefused("standard.token.exchange.enabled"); }
    @Test void privateJwtAuthorizationGrantClientIsRejected() { grantAttributeRefused("oauth2.jwt.authorization.grant.enabled"); }
    private void grantAttributeRefused(String attribute) {
        var session = mock(KeycloakSession.class); var context = mock(KeycloakContext.class); var realm = realm(); var clients = mock(ClientProvider.class); var client = mock(ClientModel.class);
        when(session.getContext()).thenReturn(context); when(context.getRealm()).thenReturn(realm); when(session.clients()).thenReturn(clients); rawClient(session, realm, clients, client);
        when(client.isEnabled()).thenReturn(true); when(client.validateSecret("secret")).thenReturn(true);
        String header = "Basic " + Base64.getEncoder().encodeToString("core-owner:secret".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertDoesNotThrow(() -> ReproofingRpcImpl.workload(session, header, "admit"));
        when(client.getAttribute(attribute)).thenReturn("true");
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, header, "admit"));
    }
    @Test void expiredFinalNotificationLeaseBecomesFailedWithoutAnotherAttemptOrLateResurrection() throws Exception {
        var notification = new ReproofingNotificationImpl(); notification.status = "SENDING"; notification.leaseToken = "last-lease"; notification.nextAttemptAt = 1000; notification.attempts = 8;
        java.lang.reflect.Method expire;
        try { expire = ReproofingDispatcherImpl.class.getDeclaredMethod("expireFinalLease", ReproofingNotificationImpl.class, long.class); }
        catch (NoSuchMethodException missing) { fail("Missing durable terminal transition for an expired last delivery lease"); return; }
        assertEquals(false, expire.invoke(null, notification, 999L)); assertEquals("SENDING", notification.status);
        assertEquals(true, expire.invoke(null, notification, 1000L)); assertEquals("FAILED", notification.status); assertEquals(8, notification.attempts);
        assertFalse(ReproofingDispatcherImpl.owns(notification, "last-lease"));
        notification.status = "DELIVERED"; assertEquals(false, expire.invoke(null, notification, 2000L)); assertEquals("DELIVERED", notification.status);
        notification.status = "SENDING"; notification.leaseToken = "newer-lease"; notification.nextAttemptAt = 3000L;
        assertEquals(false, expire.invoke(null, notification, 2000L)); assertEquals("newer-lease", notification.leaseToken);
    }
    private void rawClient(KeycloakSession session, RealmModel realm, ClientProvider clients, ClientModel client) {
        var em = mock(jakarta.persistence.EntityManager.class); var jpa = mock(org.keycloak.connections.jpa.JpaConnectionProvider.class);
        when(session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class)).thenReturn(jpa); when(jpa.getEntityManager()).thenReturn(em); when(session.getProvider(ClientProvider.class)).thenReturn(clients);
        when(client.getId()).thenReturn("client-row"); var entity = new org.keycloak.models.jpa.entities.ClientEntity(); entity.setId("client-row");
        when(em.find(org.keycloak.models.jpa.entities.ClientEntity.class,"client-row")).thenReturn(entity);
        when(clients.getClientByClientId(realm,"core-owner")).thenReturn(client); when(clients.getClientById(realm,"client-row")).thenReturn(client);
    }
    private RealmModel realm() {
        var realm = mock(RealmModel.class); when(realm.getName()).thenReturn("customers");
        Map<String, String> attributes = Map.of("enabled", "true", "population", "HUMAN", "allowed-origin", "https://id.test", "issuer", "https://id.test/realms/customers", "core-workload-client-id", "core-owner", "domain-workload-client-id", "domain-owner", "ttl-seconds", "600");
        when(realm.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.getArgument(0, String.class).replace("firefly.reproofing.", "")));
        return realm;
    }
}
