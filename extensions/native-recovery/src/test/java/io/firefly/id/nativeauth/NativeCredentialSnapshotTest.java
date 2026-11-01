package io.firefly.id.nativeauth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeCredentialSnapshotTest {
    @Test void finalSnapshotLocksAndRefreshesCredentialMaterialInsteadOfTrustingStaleDto() {
        KeycloakSession session = mock(KeycloakSession.class); EntityManager em = mock(EntityManager.class);
        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class); when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa); when(jpa.getEntityManager()).thenReturn(em);
        UserModel user = mock(UserModel.class); when(user.getId()).thenReturn("subject");
        SubjectCredentialManager manager = mock(SubjectCredentialManager.class); when(user.credentialManager()).thenReturn(manager);
        CredentialModel stale = new CredentialModel(); stale.setId("credential"); stale.setType("password"); stale.setSecretData("stale");
        when(manager.getStoredCredentialsStream()).thenReturn(Stream.of(stale));
        UserEntity owner = new UserEntity(); owner.setId("subject");
        CredentialEntity current = new CredentialEntity(); current.setId("credential"); current.setUser(owner); current.setType("password"); current.setSecretData("current"); current.setCredentialData("algorithm");
        when(em.find(CredentialEntity.class, "credential", LockModeType.PESSIMISTIC_WRITE)).thenReturn(current);
        String revision = new NativeStoreImpl(session).revision(user, true);
        verify(em).refresh(current, LockModeType.PESSIMISTIC_WRITE);
        assertEquals(NativeSecurityImpl.digest("credential\npassword\nnull\nalgorithm\ncurrent\n"), revision);
    }
    @Test void administrativeSnapshotDoesNotRefreshAwayPendingCredentialChanges() {
        KeycloakSession session = mock(KeycloakSession.class); EntityManager em = mock(EntityManager.class);
        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class); when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa); when(jpa.getEntityManager()).thenReturn(em);
        UserModel user = mock(UserModel.class); when(user.getId()).thenReturn("subject");
        SubjectCredentialManager manager = mock(SubjectCredentialManager.class); when(user.credentialManager()).thenReturn(manager);
        CredentialModel model = new CredentialModel(); model.setId("credential"); model.setType("password"); when(manager.getStoredCredentialsStream()).thenReturn(Stream.of(model));
        UserEntity owner = new UserEntity(); owner.setId("subject"); CredentialEntity entity = new CredentialEntity(); entity.setUser(owner); entity.setId("credential"); entity.setType("password"); entity.setSecretData("pending-change");
        when(em.find(CredentialEntity.class, "credential", LockModeType.PESSIMISTIC_WRITE)).thenReturn(entity);
        new NativeStoreImpl(session).revision(user, false);
        verify(em, never()).refresh(any(), any(LockModeType.class));
    }
}
