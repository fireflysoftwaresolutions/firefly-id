package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import static org.junit.jupiter.api.Assertions.*;

class NativeAdministrativePinTest {
    private NativeState state() {
        var state = new NativeState(); state.subject = "customer"; state.pinCredentialId = "pin-credential";
        state.pinGeneration = "original-pin-generation"; state.generation = "account-lock-generation";
        state.bootstrapAttempts = 2; state.knowledgeAttempts = 1; state.possessionAttempts = 2;
        state.pinFailures = 2; state.pinReserved = 1; return state;
    }
    private AdminEvent event() {
        var event = new AdminEvent(); event.setId("authoritative-admin-event"); event.setOperationType(OperationType.ACTION);
        event.setResourcePath("users/customer/credentials/pin-credential");
        var actor = new AuthDetails(); actor.setRealmId("administrator-realm"); actor.setUserId("administrator-subject");
        actor.setClientId("actual-client-row-id"); event.setAuthDetails(actor); return event;
    }
    @Test void privilegedRevocationRetiresPinWithoutResettingAccountOrAttemptBudgets() {
        var state = state(); state.locked = true; state.credentialRevision = "unchanged-password-and-otp";
        assertTrue(NativeInvalidationFactoryImpl.revokePin(state, event(), 123456));
        assertNull(state.pinCredentialId); assertEquals(123456, state.pinRevokedAt); assertTrue(state.pinHeld);
        assertNotEquals("original-pin-generation", state.pinGeneration); assertEquals("account-lock-generation", state.generation);
        assertEquals(2, state.bootstrapAttempts); assertEquals(1, state.knowledgeAttempts); assertEquals(2, state.possessionAttempts);
        assertEquals(2, state.pinFailures); assertEquals(1, state.pinReserved); assertTrue(state.locked);
        assertFalse(state.hold); assertEquals("unchanged-password-and-otp", state.credentialRevision);
    }
    @Test void labelMoveAndOtherCredentialsCannotBecomeAdministrativePinRevocation() {
        for (String path : new String[]{"users/customer/credentials/password", "users/other/credentials/pin-credential",
                "users/customer/credentials/pin-credential/userLabel", "users/customer/credentials/pin-credential/moveToFirst"}) {
            var state = state(); var event = event(); event.setResourcePath(path);
            assertFalse(NativeInvalidationFactoryImpl.revokePin(state, event, 123456));
            assertEquals("pin-credential", state.pinCredentialId); assertEquals(0, state.pinRevokedAt);
        }
        var state = state(); var event = event(); event.setOperationType(OperationType.UPDATE);
        assertFalse(NativeInvalidationFactoryImpl.revokePin(state, event, 123456));
    }
    @Test void missingAuthoritativeActorOrEventCannotMutateThePin() {
        for (int missing = 0; missing < 4; missing++) {
            var state = state(); var event = event();
            if (missing == 0) event.setId(null);
            if (missing == 1) event.getAuthDetails().setRealmId(null);
            if (missing == 2) event.getAuthDetails().setUserId(null);
            if (missing == 3) event.getAuthDetails().setClientId(null);
            assertThrows(NativeRefusal.class, () -> NativeInvalidationFactoryImpl.revokePin(state, event, 123456));
            assertEquals("pin-credential", state.pinCredentialId); assertEquals("original-pin-generation", state.pinGeneration);
        }
    }
}
