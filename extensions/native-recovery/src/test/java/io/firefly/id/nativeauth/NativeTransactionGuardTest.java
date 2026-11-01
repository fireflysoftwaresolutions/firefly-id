package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import jakarta.transaction.TransactionManager;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;
import org.mockito.ArgumentCaptor;

class NativeTransactionGuardTest {
    @Test void administrativeVetoMarksActualJtaEvenWhenCallerExplicitlyCommitsOuterManager() throws Exception {
        var session = mock(KeycloakSession.class); var outer = mock(KeycloakTransactionManager.class);
        var lookup = mock(JtaTransactionManagerLookup.class); var actual = mock(TransactionManager.class);
        when(session.getTransactionManager()).thenReturn(outer); when(session.getProvider(JtaTransactionManagerLookup.class)).thenReturn(lookup);
        when(lookup.getTransactionManager()).thenReturn(actual);
        NativeInvalidationFactoryImpl.veto(session);
        // Admin UserResource explicitly commits: the actual JTA marker must survive ignoring outer flag.
        outer.commit(); verify(actual).setRollbackOnly(); verify(outer).setRollbackOnly();
    }
    @Test void absentJtaLookupInstallsMandatoryPrepareFailureRatherThanTrustingListenerThrow() {
        var session = mock(KeycloakSession.class); var outer = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(outer);
        NativeInvalidationFactoryImpl.veto(session);
        var guard = ArgumentCaptor.forClass(KeycloakTransaction.class); verify(outer).enlistPrepare(guard.capture());
        guard.getValue().begin(); assertThrows(NativeRefusal.class, () -> guard.getValue().commit());
    }
    @Test void missingActualDomainGatewayCannotBeSilentlyQualified() {
        NativeCeremonyGateway.Factory factory = session -> { throw new AssertionError("not admitted"); };
        assertFalse(factory.isQualified());
        NativeSupportAuthorization.Factory support = session -> { throw new AssertionError("not admitted"); };
        assertFalse(support.isQualified());
    }
}
