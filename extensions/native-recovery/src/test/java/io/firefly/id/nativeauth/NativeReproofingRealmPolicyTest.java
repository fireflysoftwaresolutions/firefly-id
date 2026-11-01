package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.admin.*;
import org.keycloak.models.KeycloakSession;
import jakarta.persistence.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeReproofingRealmPolicyTest {
    @Test @SuppressWarnings({"rawtypes","unchecked"})
    void globalRoleGroupClientAndRealmChangesFenceAndAuditOriginalAdministrativeEvent() throws Exception {
        Class policy;
        try { policy=Class.forName("io.firefly.id.nativeauth.impl.ReproofingRealmPolicyEntityImpl"); }
        catch(ClassNotFoundException missing) { fail("Missing durable realm authorization policy fence"); return; }
        for(String path:new String[]{"roles/customer-role/composites","groups/customer-group/role-mappings/realm","clients/administration-client",""}) {
            var session=mock(KeycloakSession.class,RETURNS_DEEP_STUBS); when(session.getContext().getRealm().getId()).thenReturn("realm");
            var em=mock(EntityManager.class); var jpa=mock(JpaConnectionProvider.class); when(jpa.getEntityManager()).thenReturn(em); doReturn(jpa).when(session).getProvider(JpaConnectionProvider.class);
            Object row=policy.getConstructor().newInstance(); policy.getField("id").set(row,"realm"); policy.getField("revision").setLong(row,4L);
            when(em.find(policy,"realm")).thenReturn(row); when(em.find(policy,"realm",LockModeType.PESSIMISTIC_WRITE)).thenReturn(row);
            var event=new AdminEvent(); event.setId("original-global-admin-event"); event.setOperationType(OperationType.UPDATE); event.setResourcePath(path);
            var actor=new AuthDetails(); actor.setRealmId("admin-realm"); actor.setUserId("admin-subject"); actor.setClientId("admin-client"); event.setAuthDetails(actor);
            new NativeInvalidationFactoryImpl().create(session).onEvent(event,false);
            assertEquals(5L,policy.getField("revision").getLong(row));
            verify(em).persist(argThat(value -> value instanceof NativeAudit audit && "REPROOFING_REALM_POLICY_INVALIDATED".equals(audit.eventType) && "original-global-admin-event".equals(audit.adminEventId) && "admin-subject".equals(audit.actorSubject)));
        }
    }
}
