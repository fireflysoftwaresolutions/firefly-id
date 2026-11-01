package io.firefly.id.nativeauth.impl;

import java.util.Set;
import org.keycloak.models.PasswordPolicy;

public final class ReproofingPolicyImpl {
    private ReproofingPolicyImpl() { }
    public static Integer passwordMinimum(PasswordPolicy policy) {
        if (policy == null) return null;
        Object value = policy.getPolicyConfig("length");
        return value instanceof Integer minimum && minimum > 0 && minimum <= 1024 ? minimum : null;
    }
    public static boolean eligible(boolean enabled, boolean capturedLock, boolean hold, boolean localCustomer,
            String disabledReason, Set<String> credentialTypes) {
        return localCustomer && !hold && credentialTypes != null && credentialTypes.contains("password")
                && Set.of("password", "password-history", "otp", "firefly-support-pin").containsAll(credentialTypes)
                && ((enabled && disabledReason == null) || (!enabled && capturedLock && "permanentLockout".equals(disabledReason)));
    }
}
