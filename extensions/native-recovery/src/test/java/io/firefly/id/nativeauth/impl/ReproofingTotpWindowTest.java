package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import static org.junit.jupiter.api.Assertions.*;

class ReproofingTotpWindowTest {
    private Method validator() {
        try { return ReproofingCryptoImpl.class.getMethod("validTotp", String.class, long.class, int.class, int.class, String.class, int.class, String.class); }
        catch (NoSuchMethodException missing) { fail("Missing realm TOTP clock-tolerance policy"); return null; }
    }
    private boolean valid(Method validator, String secret, long now, int window, String code) throws Exception {
        return (boolean) validator.invoke(null, secret, now, 30, 8, "HmacSHA1", window, code);
    }
    @Test void honorsExactConfiguredPreviousAndFollowingIntervalsWithoutExtendingTheWindow() throws Exception {
        Method validator=validator(); String secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; long now=1700000000000L;
        String current=ReproofingCryptoImpl.totp(secret,now,30,8,"HmacSHA1");
        String previous=ReproofingCryptoImpl.totp(secret,now-30000,30,8,"HmacSHA1");
        String next=ReproofingCryptoImpl.totp(secret,now+30000,30,8,"HmacSHA1");
        assertTrue(valid(validator,secret,now,0,current));
        assertFalse(valid(validator,secret,now,0,previous)); assertFalse(valid(validator,secret,now,0,next));
        assertTrue(valid(validator,secret,now,1,previous)); assertTrue(valid(validator,secret,now,1,current)); assertTrue(valid(validator,secret,now,1,next));
        assertFalse(valid(validator,secret,now,1,ReproofingCryptoImpl.totp(secret,now-60000,30,8,"HmacSHA1")));
        assertFalse(valid(validator,secret,now,1,ReproofingCryptoImpl.totp(secret,now+60000,30,8,"HmacSHA1")));
    }
    @Test void unsupportedPolicyIsRefusedRatherThanSilentlyIgnoringItsConfiguredWindow() throws Exception {
        Method validator=validator(); String secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; long now=1700000000000L;
        assertThrows(InvocationTargetException.class,()->valid(validator,secret,now,-1,"12345678"));
        assertThrows(InvocationTargetException.class,()->valid(validator,secret,now,11,"12345678"));
        assertThrows(InvocationTargetException.class,()->validator.invoke(null,secret,now,301,8,"HmacSHA1",1,"12345678"));
        assertThrows(InvocationTargetException.class,()->validator.invoke(null,secret,now,30,9,"HmacSHA1",1,"12345678"));
        assertThrows(InvocationTargetException.class,()->validator.invoke(null,secret,now,30,8,"HmacMD5",1,"12345678"));
    }
}
