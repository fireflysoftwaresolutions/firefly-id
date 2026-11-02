package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import org.keycloak.models.PasswordPolicy;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingPasswordHintTest {
    @Test void hintUsesOnlyActualPositiveBoundedIntegerLengthPolicy() throws Exception {
        java.lang.reflect.Method minimum;
        try { minimum=ReproofingPolicyImpl.class.getMethod("passwordMinimum",PasswordPolicy.class); }
        catch (NoSuchMethodException missing) { fail("Missing actual realm password length hint"); return; }
        var policy=mock(PasswordPolicy.class); doReturn(18).when(policy).getPolicyConfig("length"); assertEquals(18,minimum.invoke(null,policy));
        for(Object value:new Object[]{null,0,-1,1025,"14",true}) { doReturn(value).when(policy).getPolicyConfig("length"); assertNull(minimum.invoke(null,policy)); }
    }
}
