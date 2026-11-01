package io.firefly.id.nativeauth;

import io.firefly.id.nativeauth.impl.ReproofingStateImpl;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.admin.*;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.storage.UserStoragePrivateUtil;
import jakarta.persistence.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class NativeReproofingInvalidationTest {
    @Test void enabledReproofingOnlyUserJoinsParentLockAndDurableInvalidationWithoutLegacyState() throws Exception {
        var session = session(); var em = em(session); var state = state(em); var user = mock(UserModel.class); var users = mock(UserProvider.class); var realm = session.getContext().getRealm();
        when(user.getId()).thenReturn("customer"); when(users.getUserById(realm,"customer")).thenReturn(user);
        UserEntity entity = new UserEntity(); entity.setId("customer"); entity.setRealmId("realm"); when(em.find(UserEntity.class,"customer",LockModeType.PESSIMISTIC_WRITE)).thenReturn(entity);
        try (var local = mockStatic(UserStoragePrivateUtil.class)) {
            local.when(() -> UserStoragePrivateUtil.userLocalStorage(session)).thenReturn(users);
            new NativeInvalidationFactoryImpl().create(session).onEvent(event(OperationType.UPDATE), false);
        }
        verify(em).find(UserEntity.class,"customer",LockModeType.PESSIMISTIC_WRITE);
        assertEquals(1L, invalidation(state));
        assertEquals("stable-epoch", state.epoch); assertEquals(2,state.failures);
        verify(em).persist(argThat(value -> value instanceof NativeAudit audit && "REPROOFING_INVALIDATED_ADMINISTRATIVE".equals(audit.eventType)
                && "original-admin-event".equals(audit.adminEventId) && "admin-subject".equals(audit.actorSubject) && "admin-client".equals(audit.actorClientId)));
        verify(em, never()).persist(argThat(value -> value instanceof NativeState));
        verify(session.getTransactionManager(), never()).setRollbackOnly();
    }
    @Test void reproofingOnlyDeletionInvalidatesWithoutRequiringDeletedUserOrClearingBudget() throws Exception {
        var session = session(); var em = em(session); var state = state(em);
        new NativeInvalidationFactoryImpl().create(session).onEvent(event(OperationType.DELETE),false);
        assertEquals(1L,invalidation(state));
        assertEquals("stable-epoch",state.epoch); assertEquals(2,state.failures);
        verify(em,never()).find(eq(UserEntity.class),any(),any(LockModeType.class));
        verify(session.getTransactionManager(),never()).setRollbackOnly();
    }
    private long invalidation(ReproofingStateImpl state) throws Exception {
        try { return state.getClass().getField("invalidationVersion").getLong(state); }
        catch (NoSuchFieldException missing) { fail("Missing durable recovery invalidation stamp"); return -1; }
    }
    private KeycloakSession session() {
        var session = mock(KeycloakSession.class,RETURNS_DEEP_STUBS); when(session.getContext().getRealm().getId()).thenReturn("realm");
        when(session.getContext().getRealm().getAttribute("firefly.reproofing.enabled")).thenReturn("true");
        var em=mock(EntityManager.class); var jpa=mock(JpaConnectionProvider.class); when(jpa.getEntityManager()).thenReturn(em); doReturn(jpa).when(session).getProvider(JpaConnectionProvider.class); return session;
    }
    private EntityManager em(KeycloakSession session) { return session.getProvider(JpaConnectionProvider.class).getEntityManager(); }
    private ReproofingStateImpl state(EntityManager em) {
        var state = new ReproofingStateImpl(); state.id=NativeSecurity.digest("realm\ncustomer"); state.subject="customer"; state.realmId="realm"; state.epoch="stable-epoch"; state.failures=2;
        when(em.find(ReproofingStateImpl.class,state.id)).thenReturn(state); when(em.find(ReproofingStateImpl.class,state.id,LockModeType.PESSIMISTIC_WRITE)).thenReturn(state); return state;
    }
    private AdminEvent event(OperationType type) {
        var event=new AdminEvent(); event.setId("original-admin-event"); event.setResourcePath("users/customer"); event.setOperationType(type);
        var actor=new AuthDetails(); actor.setRealmId("admin-realm"); actor.setUserId("admin-subject"); actor.setClientId("admin-client"); event.setAuthDetails(actor); return event;
    }
}
