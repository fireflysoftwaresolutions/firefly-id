package io.firefly.id.nativeauth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.UserEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class NativeInvalidationDeletionTest {
    @Test void untrackedServiceOrFederatedUpdatesDoNotRequireALocalUser() {
        KeycloakSession session = session(); EntityManager em = em(session);
        AdminEvent event = new AdminEvent(); event.setResourcePath("users/service-or-federated"); event.setOperationType(OperationType.UPDATE);
        new NativeInvalidationFactoryImpl().create(session).onEvent(event, false);
        verify(em, never()).find(eq(UserEntity.class), any(), any(LockModeType.class));
        verify(session.getTransactionManager(), never()).setRollbackOnly();
    }

    @Test void adminDeletionTombstonesTrackedStateWithoutResurrectingOrVetoingUser() {
        KeycloakSession session = session(); NativeState state = tracked(session);
        AdminEvent event = new AdminEvent(); event.setResourcePath("users/deleted"); event.setOperationType(OperationType.DELETE);
        new NativeInvalidationFactoryImpl().create(session).onEvent(event, false);
        removed(session, state);
    }

    @Test void accountDeletionTombstonesTrackedStateWithoutSurvivingUserEntity() {
        KeycloakSession session = session(); NativeState state = tracked(session);
        Event event = new Event(); event.setType(EventType.DELETE_ACCOUNT); event.setUserId("deleted");
        new NativeInvalidationFactoryImpl().create(session).onEvent(event);
        removed(session, state);
    }

    private static KeycloakSession session() {
        KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        when(session.getContext().getRealm().getId()).thenReturn("realm");
        when(session.getContext().getRealm().getAttribute("firefly.native-recovery.population")).thenReturn("HUMAN");
        EntityManager manager = mock(EntityManager.class);
        JpaConnectionProvider provider = mock(JpaConnectionProvider.class);
        when(provider.getEntityManager()).thenReturn(manager);
        doReturn(provider).when(session).getProvider(JpaConnectionProvider.class);
        return session;
    }
    private static EntityManager em(KeycloakSession session) { return session.getProvider(JpaConnectionProvider.class).getEntityManager(); }
    private static NativeState tracked(KeycloakSession session) {
        NativeState state = new NativeState(); state.generation = "retained-generation";
        when(em(session).find(eq(NativeState.class), anyString())).thenReturn(state);
        when(em(session).find(eq(NativeState.class), anyString(), eq(LockModeType.PESSIMISTIC_WRITE))).thenReturn(state);
        return state;
    }
    private static void removed(KeycloakSession session, NativeState state) {
        assertTrue(state.hold && state.pinHeld); assertTrue(state.pinRevokedAt > 0);
        verify(em(session), never()).find(eq(UserEntity.class), any(), any(LockModeType.class));
        verify(em(session)).persist(argThat(value -> value instanceof NativeAudit audit && "IDENTITY_REMOVED".equals(audit.eventType)));
        verify(session.getTransactionManager(), never()).setRollbackOnly();
    }
}
