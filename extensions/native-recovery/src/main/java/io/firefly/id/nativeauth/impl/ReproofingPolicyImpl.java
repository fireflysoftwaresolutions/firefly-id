package io.firefly.id.nativeauth.impl;

import java.util.Set;

public final class ReproofingPolicyImpl {
    private ReproofingPolicyImpl() { }
    public static boolean eligible(boolean enabled, boolean capturedLock, boolean hold, boolean localCustomer,
            String disabledReason, Set<String> credentialTypes) {
        return localCustomer && !hold && credentialTypes != null && credentialTypes.contains("password")
                && Set.of("password", "password-history", "otp", "firefly-support-pin").containsAll(credentialTypes)
                && ((enabled && disabledReason == null) || (!enabled && capturedLock && "permanentLockout".equals(disabledReason)));
    }
}
