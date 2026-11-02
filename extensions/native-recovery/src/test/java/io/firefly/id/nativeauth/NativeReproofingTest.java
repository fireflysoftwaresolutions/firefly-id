package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.lang.reflect.InvocationTargetException;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class NativeReproofingTest {
    private Class<?> implementation(String simple) {
        try { return Class.forName("io.firefly.id.nativeauth.impl." + simple); }
        catch (ClassNotFoundException missing) { fail("Missing independent credential replacement mechanism: " + simple); return null; }
    }
    @Test void enabledAndPermanentAuthenticationLockHaveIndependentAdmission() throws Exception {
        var method = implementation("ReproofingPolicyImpl").getMethod("eligible", boolean.class, boolean.class, boolean.class, boolean.class, String.class, Set.class);
        assertEquals(true, method.invoke(null, true, false, false, true, null, Set.of("password", "otp")));
        assertEquals(true, method.invoke(null, false, true, false, true, "permanentLockout", Set.of("password", "otp")));
        assertEquals(false, method.invoke(null, false, false, false, true, "admin", Set.of("password", "otp")));
        assertEquals(false, method.invoke(null, true, false, true, true, null, Set.of("password", "otp")));
        assertEquals(false, method.invoke(null, true, false, false, true, null, Set.of("password", "webauthn")));
        assertEquals(false, method.invoke(null, true, false, false, false, null, Set.of("password", "otp")));
    }
    @Test void pendingSecretIsAuthenticatedEncryptedAndBoundToCeremony() throws Exception {
        Class<?> type = implementation("ReproofingCryptoImpl");
        byte[] key = new byte[32]; java.util.Arrays.fill(key, (byte) 9);
        var seal = type.getMethod("seal", byte[].class, String.class, String.class);
        var open = type.getMethod("open", byte[].class, String.class, String.class);
        String ciphertext = (String) seal.invoke(null, key, "ceremony-a", "JBSWY3DPEHPK3PXP");
        assertFalse(ciphertext.contains("JBSWY3DPEHPK3PXP"));
        assertEquals("JBSWY3DPEHPK3PXP", open.invoke(null, key, "ceremony-a", ciphertext));
        assertThrows(InvocationTargetException.class, () -> open.invoke(null, key, "ceremony-b", ciphertext));
        assertThrows(InvocationTargetException.class, () -> seal.invoke(null, new byte[16], "ceremony-a", "secret"));
    }
    @Test void replacementTotpRequiresFreshCodeForNewSecret() throws Exception {
        var code = implementation("ReproofingCryptoImpl").getMethod("totp", String.class, long.class, int.class, int.class, String.class);
        assertEquals("94287082", code.invoke(null, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59000L, 30, 8, "HmacSHA1"));
        assertNotEquals(code.invoke(null, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59000L, 30, 8, "HmacSHA1"), code.invoke(null, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 89000L, 30, 8, "HmacSHA1"));
    }
}
