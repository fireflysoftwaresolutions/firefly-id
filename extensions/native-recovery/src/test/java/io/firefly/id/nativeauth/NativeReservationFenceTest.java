package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class NativeReservationFenceTest {
    private final UUID operation = UUID.randomUUID(), challenge = UUID.randomUUID(), reservation = UUID.randomUUID();
    private NativeCeremony ceremony() {
        var c = new NativeCeremony(); c.id = "ceremony"; c.realmId = "realm"; c.subject = "subject"; c.generation = "generation"; return c;
    }
    private NativeState state() { var state = new NativeState(); state.generation = "generation"; state.credentialRevision = "revision"; return state; }
    private NativeContracts.Reservation reservation() { return new NativeContracts.Reservation(operation, challenge, reservation, "provider-challenge", "POSSESSION", Instant.now().plusSeconds(60)); }
    private NativeAttestation proof() {
        var proof = new NativeAttestation(); proof.id = "opaque-negative"; proof.ceremonyId = "ceremony"; proof.realmId = "realm"; proof.subject = "subject";
        proof.generation = "generation"; proof.credentialRevision = "revision"; proof.operationId = operation.toString(); proof.challengeId = challenge.toString();
        proof.reservationId = reservation.toString(); proof.providerChallengeId = "provider-challenge"; proof.category = "POSSESSION"; proof.credentialId = "credential";
        proof.expiresAt = System.currentTimeMillis() + 60000; proof.completed = true; proof.verified = false; return proof;
    }
    @Test void completedNegativeReusesExactOpaqueResultWithoutAnotherVerificationDecision() {
        var prepared = NativeReservationFence.reuse(proof(), ceremony(), state(), reservation(), "credential");
        assertEquals("opaque-negative", prepared.attestationId()); assertFalse(prepared.verify());
    }
    @Test void completedPositiveAlsoReusesResultWithoutRecheckingSecret() {
        var proof = proof(); proof.verified = true;
        assertFalse(NativeReservationFence.reuse(proof, ceremony(), state(), reservation(), "credential").verify());
    }
    @Test void pendingReservationCannotAllocateAnotherCredentialCheck() {
        var proof = proof(); proof.completed = false;
        assertThrows(NativeRefusal.class, () -> NativeReservationFence.reuse(proof, ceremony(), state(), reservation(), "credential"));
    }
    @Test void challengeProviderReferenceCredentialAndGenerationSubstitutionAreRejected() {
        var proof = proof(); proof.challengeId = UUID.randomUUID().toString(); final var otherChallenge = proof;
        assertThrows(NativeRefusal.class, () -> NativeReservationFence.reuse(otherChallenge, ceremony(), state(), reservation(), "credential"));
        proof = proof(); proof.providerChallengeId = "other"; final var otherProvider = proof;
        assertThrows(NativeRefusal.class, () -> NativeReservationFence.reuse(otherProvider, ceremony(), state(), reservation(), "credential"));
        proof = proof(); proof.generation = "other"; final var otherGeneration = proof;
        assertThrows(NativeRefusal.class, () -> NativeReservationFence.reuse(otherGeneration, ceremony(), state(), reservation(), "credential"));
        assertThrows(NativeRefusal.class, () -> NativeReservationFence.reuse(proof(), ceremony(), state(), reservation(), "other-credential"));
    }
}
