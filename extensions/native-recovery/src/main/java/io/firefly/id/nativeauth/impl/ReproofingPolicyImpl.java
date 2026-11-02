package io.firefly.id.nativeauth.impl;

import java.util.Set;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.OTPPolicy;

public final class ReproofingPolicyImpl {
    private ReproofingPolicyImpl() { }
    public record TotpSetup(String algorithm, int digits, int period) { }
    public static TotpSetup totpSetup(OTPPolicy policy) {
        ReproofingCryptoImpl.requireTotpPolicy(policy);
        String algorithm = switch (policy.getAlgorithm()) {
            case "HmacSHA1" -> "SHA-1";
            case "HmacSHA256" -> "SHA-256";
            case "HmacSHA512" -> "SHA-512";
            default -> throw new IllegalStateException("Unsupported authenticator policy");
        };
        return new TotpSetup(algorithm, policy.getDigits(), policy.getPeriod());
    }
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
