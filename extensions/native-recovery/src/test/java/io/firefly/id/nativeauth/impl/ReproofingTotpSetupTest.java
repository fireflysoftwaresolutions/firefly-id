package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import org.keycloak.models.OTPPolicy;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingTotpSetupTest {
    @Test void enrollmentSettingsMatchDefaultAndNondefaultActualRealmPolicies() throws Exception {
        java.lang.reflect.Method settings;
        try { settings=ReproofingPolicyImpl.class.getMethod("totpSetup",OTPPolicy.class); }
        catch (NoSuchMethodException missing) { fail("Missing actual realm authenticator setup settings"); return; }
        for (Object[] example : new Object[][]{{"HmacSHA1",6,30,"SHA-1"},{"HmacSHA256",8,60,"SHA-256"},{"HmacSHA512",8,120,"SHA-512"}}) {
            var policy=mock(OTPPolicy.class); when(policy.getType()).thenReturn("totp"); when(policy.getLookAheadWindow()).thenReturn(1);
            when(policy.getAlgorithm()).thenReturn((String)example[0]); when(policy.getDigits()).thenReturn((int)example[1]); when(policy.getPeriod()).thenReturn((int)example[2]);
            Object value=settings.invoke(null,policy);
            assertEquals(example[3],value.getClass().getMethod("algorithm").invoke(value));
            assertEquals(example[1],value.getClass().getMethod("digits").invoke(value));
            assertEquals(example[2],value.getClass().getMethod("period").invoke(value));
        }
    }
}
