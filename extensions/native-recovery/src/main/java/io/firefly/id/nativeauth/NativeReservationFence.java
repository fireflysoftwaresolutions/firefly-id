package io.firefly.id.nativeauth;

import static io.firefly.id.nativeauth.NativeSecurity.*;

/** A committed reservation never permits a second native secret check, including after a crash. */
final class NativeReservationFence {
    record Prepared(String attestationId, boolean verify) { }
    static Prepared reuse(NativeAttestation proof, NativeCeremony ceremony, NativeState state,
            NativeContracts.Reservation reservation, String credentialId) {
        require(proof != null && proof.completed && proof.expiresAt > System.currentTimeMillis()
                && ceremony.id.equals(proof.ceremonyId) && ceremony.realmId.equals(proof.realmId)
                && ceremony.subject.equals(proof.subject) && ceremony.generation.equals(proof.generation)
                && state.generation.equals(proof.generation) && state.credentialRevision.equals(proof.credentialRevision)
                && reservation.operationId().toString().equals(proof.operationId)
                && reservation.challengeId().toString().equals(proof.challengeId)
                && reservation.reservationId().toString().equals(proof.reservationId)
                && reservation.providerChallengeId().equals(proof.providerChallengeId)
                && reservation.category().equals(proof.category) && credentialId.equals(proof.credentialId));
        return new Prepared(proof.id, false);
    }
}
