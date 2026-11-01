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
        when(session.getContext()).thenReturn(context); when(context.getRealm()).thenReturn(realm); when(session.clients()).thenReturn(clients); when(clients.getClientByClientId(realm, "core-owner")).thenReturn(client);
        when(client.isEnabled()).thenReturn(true); when(client.isStandardFlowEnabled()).thenReturn(true); when(client.validateSecret("secret")).thenReturn(true);
        String header = "Basic " + Base64.getEncoder().encodeToString("core-owner:secret".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThrows(RuntimeException.class, () -> ReproofingRpcImpl.workload(session, header, "admit"));
    }
    @Test void redactedObjectsNeverExposeEnrollmentOrAuthorization() {
        Binding binding = new Binding("issuer", "realm", "tenant", "private-subject", UUID.randomUUID(), "HUMAN", "CREDENTIAL_REPLACEMENT", "epoch", "revision", "private-nonce");
        assertFalse(binding.toString().contains("private-subject"));
        var view = new ReproofingEngineImpl.View("private-id", "private-csrf", "ENROLL", "https://private-provider", "private-secret", false, false);
        assertFalse(view.toString().contains("private"));
        assertFalse(new Journey(null, "private-provider").toString().contains("private"));
    }
    @Test void formRejectsOversizeDuplicateAndUnexpectedFieldsBeforeParsingCredentials() {
        java.util.function.Function<String, java.io.InputStream> input = text -> new java.io.ByteArrayInputStream(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals("a+b c", ReproofingResourceImpl.form(input.apply("csrf=a%2Bb+c")).get("csrf"));
        assertThrows(RuntimeException.class, () -> ReproofingResourceImpl.form(input.apply("csrf=a&csrf=b")));
        assertThrows(RuntimeException.class, () -> ReproofingResourceImpl.form(input.apply("approved=true")));
        assertThrows(RuntimeException.class, () -> ReproofingResourceImpl.form(input.apply("password=" + "x".repeat(16384))));
    }
    private RealmModel realm() {
        var realm = mock(RealmModel.class); when(realm.getName()).thenReturn("customers");
        Map<String, String> attributes = Map.of("enabled", "true", "population", "HUMAN", "allowed-origin", "https://id.test", "issuer", "https://id.test/realms/customers", "core-workload-client-id", "core-owner", "domain-workload-client-id", "domain-owner", "ttl-seconds", "600");
        when(realm.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.getArgument(0, String.class).replace("firefly.reproofing.", "")));
        return realm;
    }
}
