package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class NativePinProtectionTest {
    @Test void keyedInputBindsRealmAndOpaqueSubjectBeforeSlowHashing() {
        byte[] key = new byte[32]; Arrays.fill(key, (byte) 7);
        String original = NativePinProtection.hmac(key, "realm-a", "subject-a", "40592817");
        assertNotEquals(original, NativePinProtection.hmac(key, "realm-b", "subject-a", "40592817"));
        assertNotEquals(original, NativePinProtection.hmac(key, "realm-a", "subject-b", "40592817"));
        assertFalse(original.contains("40592817"));
    }
    @Test void shortPepperIsRejected() {
        assertThrows(NativeRefusal.class, () -> NativePinProtection.hmac(new byte[31], "realm", "subject", "40592817"));
    }
}
