package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import java.time.Instant;

/** Native knowledge-evidence boundary; closed until a genuine support owner is installed and qualified. */
public interface NativeSupportAuthorization {
    record Grant(String nonce, String targetIssuer, String realm, String subject, String tenant,
            String customerLink, String staffIssuer, String staffSubject, String caseId, String callId,
            String permittedAction, String purpose, Instant expiresAt) {
        @Override public String toString() { return "SupportGrant[REDACTED]"; }
    }
    /**
     * Must independently verify current STAFF actor, employment/delegation, approvals, genuine case/call,
     * target and tenant. The only admitted action is VERIFY_SUPPORT_PIN with TELEPHONE_SUPPORT_KNOWLEDGE.
     * Rechecks must return the exact original grant (including nonce and expiry), or refuse; they must
     * not mint a replacement grant. Expiry has at most 120 seconds remaining when admitted.
     */
    Grant authorize(String signedSupportContext);
    interface Factory {
        default boolean isQualified() { return false; }
        NativeSupportAuthorization create(KeycloakSession session);
    }
}
