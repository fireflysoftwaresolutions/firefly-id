package io.firefly.id.nativeauth;

import java.time.Instant;
import java.util.UUID;

/** Product-private protocol. No credential value belongs in these records. */
public final class NativeContracts {
    private NativeContracts() { }
    public static final String EXTENSION = "firefly-recovery";
    public static final String PURPOSE = "PERMANENT_AUTHENTICATION_UNLOCK";
    public static final String PROVIDER = "firefly-keycloak-native-v1";
    public record Binding(String issuer, String tenant, String clientId, String delegatingClientId,
            String actorSubject, String targetIssuer, String targetRealm, String targetSubject,
            String population, String purpose, String lockGeneration) {
        @Override public String toString() { return "Binding[REDACTED]"; }
    }
    public record ChallengeReference(UUID operationId, UUID challengeId, String providerChallengeId, String category, Instant expiresAt) { }
    public record Started(UUID operationId, UUID knowledgeChallengeId, UUID possessionChallengeId) { }
    public record Reservation(UUID operationId, UUID challengeId, UUID reservationId, String providerChallengeId, String category, Instant expiresAt) { }
    public record Authorization(UUID operationId, UUID executionId, Binding binding, Instant expiresAt) {
        @Override public String toString() { return "Authorization[REDACTED]"; }
    }
    public record Rpc(String actorAssertion, Binding binding, UUID operationId, UUID challengeId,
            UUID reservationId, String providerChallengeId, String category, String attestation,
            UUID executionId, String outcome, String action) {
        @Override public String toString() { return "Rpc[REDACTED]"; }
    }
    public record Admission(Binding binding, String ownerLinkId, String identityLinkAttestationId,
            String lockAttestationId, Instant validUntil, String action) { }
    public record Issued(UUID operationId, UUID reservationId, Binding binding, String category,
            String providerId, String enrollmentId, String independenceId, String providerChallengeId,
            Instant expiresAt, String maskedDestination) { }
    public record Proof(UUID operationId, UUID challengeId, UUID reservationId, Binding binding,
            String category, String providerId, String enrollmentId, String independenceId,
            String providerChallengeId, boolean accepted, String attestationId, Instant expiresAt) { }
    public record Execution(Binding binding, UUID executionId, String outcome) { }
    public record AuditReceipt(UUID auditId, Instant committedAt) { }
    public record PinStatus(String status, Instant createdAt, Instant replacedAt, Instant revokedAt) { }
}
