package io.firefly.id.nativeauth;

import java.time.Instant;
import java.util.UUID;

/** Independent customer proofing wire. Local credentials never appear in these records. */
public interface ReproofingContracts {
    String PURPOSE = "CREDENTIAL_REPLACEMENT";
    record Binding(String issuer, String realm, String tenant, String subject, UUID partyId, String population,
            String purpose, String generation, String credentialRevision, String nonce) {
        @Override public String toString() { return "ReproofingBinding[REDACTED]"; }
    }
    record Authorization(UUID caseId, UUID authorizationId, UUID executionId, Binding binding, String evidenceDigest, String policyId, Instant expiresAt) {
        @Override public String toString() { return "ReproofingAuthorization[REDACTED]"; }
    }
    record Case(UUID caseId, Binding binding, String status, String providerId, String policyId, UUID providerStartId,
            String providerSessionId, Instant expiresAt, Authorization authorization) {
        @Override public String toString() { return "ReproofingCase[REDACTED]"; }
    }
    record Journey(Case value, String verificationUrl) { }
    record NativeRequest(Binding binding, UUID caseId, UUID executionId) {
        @Override public String toString() { return "ReproofingNativeRequest[REDACTED]"; }
    }
    record Admission(Binding binding, boolean eligible, Instant expiresAt) { }
    record Execution(UUID caseId, UUID executionId, Binding binding, String outcome, Instant committedAt) { }
}
