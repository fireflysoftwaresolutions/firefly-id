package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class NativeSecurityTest {
    @Test void pinRejectsSequencesRepetitionAndNonNumericInput() {
        for (String pin : new String[]{"12345678", "87654321", "11111111", "12121212", "1234567", "12a45678"})
            assertThrows(NativeRefusal.class, () -> NativeSecurityImpl.requirePin(pin));
        assertDoesNotThrow(() -> NativeSecurityImpl.requirePin("40592817"));
    }
    @Test void csrfTokensAreUnpredictableAndComparedWithoutPlaintextPersistence() {
        String token = NativeSecurityImpl.randomToken();
        assertNotEquals(token, NativeSecurityImpl.randomToken());
        assertTrue(NativeSecurityImpl.matches(token, NativeSecurityImpl.digest(token)));
        assertFalse(NativeSecurityImpl.matches("other", NativeSecurityImpl.digest(token)));
    }
    @Test void originsRequireExactHttpsOriginAndRejectSuffixConfusion() {
        assertDoesNotThrow(() -> NativeSecurityImpl.requireOrigin("https://identity.example", "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurityImpl.requireOrigin("https://identity.example.evil", "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurityImpl.requireOrigin(null, "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurityImpl.requireOrigin("null", "https://identity.example"));
        assertThrows(NativeRefusal.class, () -> NativeSecurityImpl.requireOrigin("http://identity.example", "http://identity.example"));
    }
    @Test void secretBearingRecordsAreAlwaysRedacted() {
        var binding = new NativeContracts.Binding("issuer", "tenant", "client", null, "subject", "issuer", "realm", "subject", "HUMAN", NativeContracts.PURPOSE, "generation");
        assertFalse(binding.toString().contains("subject"));
        var rpc = new NativeContracts.Rpc("signed-secret", binding, null, null, null, null, null, "opaque-proof", null, null, "CONSUME");
        assertFalse(rpc.toString().contains("signed-secret"));
    }
}
