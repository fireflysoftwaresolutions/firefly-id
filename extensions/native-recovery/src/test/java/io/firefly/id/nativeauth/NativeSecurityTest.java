package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class NativeSecurityTest {
    @Test void pinRejectsSequencesRepetitionAndNonNumericInput() {
        for (String pin : new String[]{"12345678", "87654321", "11111111", "12121212", "1234567", "12a45678"})
            assertThrows(NativeRefusal.class, () -> NativeSecurity.requirePin(pin));
        assertDoesNotThrow(() -> NativeSecurity.requirePin("40592817"));
    }
    @Test void csrfTokensAreUnpredictableAndComparedWithoutPlaintextPersistence() {
        String token = NativeSecurity.randomToken();
        assertNotEquals(token, NativeSecurity.randomToken());
        assertTrue(NativeSecurity.matches(token, NativeSecurity.digest(token)));
        assertFalse(NativeSecurity.matches("other", NativeSecurity.digest(token)));
    }
    @Test void originsRequireExactHttpsOriginAndRejectSuffixConfusion() {
        assertDoesNotThrow(() -> NativeSecurity.requireOrigin("https://identity.example", "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurity.requireOrigin("https://identity.example.evil", "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurity.requireOrigin(null, "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurity.requireOrigin("null", "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurity.requireOrigin("http://identity.example", "http://identity.example"));
    }
    @Test void secretBearingRecordsAreAlwaysRedacted() {
        var binding = new NativeContracts.Binding("issuer", "tenant", "client", null, "subject", "issuer", "realm", "subject", "HUMAN", NativeContracts.PURPOSE, "generation");
        assertFalse(binding.toString().contains("subject"));
        var rpc = new NativeContracts.Rpc("signed-secret", binding, null, null, null, null, null, "opaque-proof", null, null, "CONSUME");
        assertFalse(rpc.toString().contains("signed-secret"));
    }
}
