package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import java.time.Instant;

/** Pending support-owner integration. Knowledge proof alone grants no customer delegation. */
public interface NativeSupportAuthorization {
    record Grant(String nonce, String targetIssuer, String realm, String subject, String tenant,
            String customerLink, String staffIssuer, String staffSubject, String caseId, String callId,
            String permittedAction, String purpose, Instant expiresAt) {
        @Override public String toString() { return "SupportGrant[REDACTED]"; }
    }
    /** Must verify current STAFF actor, approval, owner case/call, target, tenant and narrow purpose. */
    Grant authorize(String signedSupportContext);
    interface Factory {
        default boolean isQualified() { return false; }
        NativeSupportAuthorization create(KeycloakSession session);
    }
}
