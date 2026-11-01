package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.*;

class NativeSupportEvidenceTest {
    private static final Instant NOW = Instant.parse("2026-11-01T12:00:00Z");
    private static final String ISSUER = "https://id.example/realms/customers";
    private NativeSupportAuthorization.Grant grant() {
        return new NativeSupportAuthorization.Grant("nonce", ISSUER, "customers", "customer", "tenant", "customer-link",
                "https://id.example/realms/staff", "operator", "case", "call", "VERIFY_SUPPORT_PIN",
                "TELEPHONE_SUPPORT_KNOWLEDGE", NOW.plusSeconds(120));
    }
    private NativeSupportAuthorization.Grant change(int index, Object value) {
        var g = grant(); Object[] fields = {g.nonce(), g.targetIssuer(), g.realm(), g.subject(), g.tenant(), g.customerLink(),
                g.staffIssuer(), g.staffSubject(), g.caseId(), g.callId(), g.permittedAction(), g.purpose(), g.expiresAt()};
        fields[index] = value;
        return new NativeSupportAuthorization.Grant((String) fields[0], (String) fields[1], (String) fields[2], (String) fields[3],
                (String) fields[4], (String) fields[5], (String) fields[6], (String) fields[7], (String) fields[8], (String) fields[9],
                (String) fields[10], (String) fields[11], (Instant) fields[12]);
    }
    private void validate(NativeSupportAuthorization.Grant grant) { NativeSupportEvidenceImpl.validate(grant, ISSUER, "customers", NOW); }
    private NativeState state() {
        var state = new NativeState(); state.realmId = "realm-id"; state.subject = "customer";
        state.pinGeneration = "generation"; state.pinCredentialId = "credential"; state.pinKeyVersion = "v1";
        state.knowledgeAttempts = 2; state.possessionAttempts = 1; return state;
    }
    private NativeSupportProof proof() { return NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state(), NOW); }
    @Test void currentExactPurposeWithAtMost120SecondsRemainingIsAccepted() {
        assertDoesNotThrow(() -> validate(grant()));
        assertDoesNotThrow(() -> validate(change(12, NOW.plusNanos(1))));
        for (Instant expiry : new Instant[]{NOW, NOW.minusSeconds(1), NOW.plusSeconds(120).plusNanos(1)})
            assertThrows(NativeRefusal.class, () -> validate(change(12, expiry)));
    }
    @Test void everyGrantFieldMustBeBoundedAndNonblank() {
        for (int index = 0; index < 12; index++) {
            final int field = index;
            for (String bad : new String[]{null, "", " ", " value ", "x".repeat(1025), "bad\nvalue"})
                assertThrows(NativeRefusal.class, () -> validate(change(field, bad)));
        }
        assertThrows(NativeRefusal.class, () -> validate(change(12, null)));
        assertThrows(NativeRefusal.class, () -> validate(null));
    }
    @Test void exactFieldSizeLimitsAreEnforced() {
        assertDoesNotThrow(() -> validate(change(0, "n".repeat(512))));
        assertDoesNotThrow(() -> validate(change(3, "s".repeat(128))));
        assertThrows(NativeRefusal.class, () -> validate(change(0, "n".repeat(513))));
        assertThrows(NativeRefusal.class, () -> validate(change(3, "s".repeat(129))));
        assertThrows(NativeRefusal.class, () -> validate(change(8, "c".repeat(513))));
    }
    @Test void wrongTargetsActionsPurposeAndUnsafeOrCustomerStaffIssuersAreRefused() {
        for (int index : new int[]{1, 2, 10, 11}) {
            final int field = index; assertThrows(NativeRefusal.class, () -> validate(change(field, "other")));
        }
        for (String issuer : new String[]{ISSUER, "https://ID.example:443/realms/customers/", "https://id.example/realms/other/%2e%2e/customers", "http://staff.example/realm",
                "https://user@staff.example/realm", "https://staff.example/realm?q=x", "https://staff.example/realm#x", "https:///realm"})
            assertThrows(NativeRefusal.class, () -> validate(change(6, issuer)));
    }
    @Test void replayIdentityIgnoresMutableGrantFieldsIncludingCustomerAndExpiry() {
        String nonce = NativeSupportEvidenceImpl.nonceDigest("realm-id", ISSUER, grant().nonce());
        for (int index : new int[]{3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
            var altered = change(index, index == 12 ? NOW.plusSeconds(60) : "other");
            assertEquals(nonce, NativeSupportEvidenceImpl.nonceDigest("realm-id", ISSUER, altered.nonce()));
            assertNotEquals(NativeSupportEvidenceImpl.grantDigest(grant()), NativeSupportEvidenceImpl.grantDigest(altered));
        }
        assertNotEquals(nonce, NativeSupportEvidenceImpl.nonceDigest("other-realm", ISSUER, grant().nonce()));
        assertNotEquals(nonce, NativeSupportEvidenceImpl.nonceDigest("realm-id", ISSUER, "other-nonce"));
    }
    @Test void reservationAndFailedChecksPreserveOtherBudgetsAndThreeFailuresHoldWithoutTimer() {
        var state = state();
        for (int attempt = 0; attempt < 3; attempt++) {
            var proof = NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW);
            assertEquals(attempt, state.pinFailures); assertEquals(1, state.pinReserved);
            NativeSupportEvidenceImpl.complete(proof, state, false);
            assertEquals("REJECTED", proof.status); assertFalse(proof.verified); assertEquals(attempt + 1, state.pinFailures);
            assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.complete(proof, state, true));
        }
        assertTrue(state.pinHeld); assertEquals(0, state.pinReserved);
        assertEquals(2, state.knowledgeAttempts); assertEquals(1, state.possessionAttempts);
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW));
    }
    @Test void inconsistentRetainedCountersFailClosedWithoutMutation() {
        var state = state(); state.pinFailures = 2; state.pinReserved = 2;
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.requireActive(state));
        assertEquals(2, state.pinFailures); assertEquals(2, state.pinReserved);
    }
    @Test void pendingReservationsExhaustAdmissionWithoutRefundOrExtraFailure() {
        var state = state();
        for (int i = 0; i < 3; i++) NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW);
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW));
        assertEquals(3, state.pinReserved); assertEquals(0, state.pinFailures); assertFalse(state.pinHeld);
    }
    @Test void acceptedProofCanBeConsumedExactlyOnceWithAttributionAndWithoutChangingBudgets() {
        var state = state(); var proof = NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW);
        NativeSupportEvidenceImpl.complete(proof, state, true);
        NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, true, "tenant", "customer-link", NOW);
        assertEquals("CONSUMED", proof.status); assertEquals(NOW.toEpochMilli(), proof.consumedAt);
        assertEquals("operator", proof.staffSubject); assertEquals(grant().staffIssuer(), proof.staffIssuer);
        assertEquals("case", proof.caseId); assertEquals("call", proof.callId); assertEquals("tenant", proof.tenant);
        assertEquals("customer-link", proof.customerLink); assertEquals("VERIFY_SUPPORT_PIN", proof.permittedAction);
        assertEquals(0, state.pinFailures); assertEquals(0, state.pinReserved);
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, true, "tenant", "customer-link", NOW));
    }
    @Test void wrongGrantsOrLegacyRowsNeverBecomeConsumable() {
        var state = state(); var proof = NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW);
        NativeSupportEvidenceImpl.complete(proof, state, true);
        for (int index : new int[]{0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
            var altered = change(index, index == 12 ? NOW.plusSeconds(60) : "other");
            assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, altered, "realm-id", state, true, "tenant", "customer-link", NOW));
            assertEquals("VERIFIED", proof.status);
        }
        for (Consumer<NativeSupportProof> invalidate : java.util.List.<Consumer<NativeSupportProof>>of(
                p -> p.status = null, p -> p.nonceDigest = null, p -> p.nonceDigest = "altered", p -> p.grantDigest = null, p -> p.staffIssuer = null,
                p -> p.pinCredentialId = null, p -> p.pinKeyVersion = null, p -> p.verified = false)) {
            var legacy = proof(); legacy.status = "VERIFIED"; legacy.verified = true; invalidate.accept(legacy);
            assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(legacy, grant(), "realm-id", state, true, "tenant", "customer-link", NOW));
        }
    }
    @Test void rotationRevocationExpiryHoldsAndTargetChangesInvalidateWithoutRefunds() {
        for (Consumer<NativeState> invalidate : java.util.List.<Consumer<NativeState>>of(
                s -> s.pinGeneration = "rotated", s -> s.pinCredentialId = null, s -> s.pinCredentialId = "replaced",
                s -> s.pinKeyVersion = "rotated", s -> s.pinRevokedAt = 1, s -> s.pinHeld = true,
                s -> s.locked = true, s -> s.hold = true, s -> s.pinFailures = 3)) {
            var state = state(); var proof = NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW);
            NativeSupportEvidenceImpl.complete(proof, state, true); state.pinReserved = 1; invalidate.accept(state);
            assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, true, "tenant", "customer-link", NOW));
            assertEquals(1, state.pinReserved); assertEquals("VERIFIED", proof.status);
        }
        var state = state(); var proof = NativeSupportEvidenceImpl.reserve(grant(), "realm-id", state, NOW);
        NativeSupportEvidenceImpl.complete(proof, state, true);
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, false, "tenant", "customer-link", NOW));
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "other-realm", state, true, "tenant", "customer-link", NOW));
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, true, "other", "customer-link", NOW));
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, true, "tenant", "other", NOW));
        assertThrows(NativeRefusal.class, () -> NativeSupportEvidenceImpl.consume(proof, grant(), "realm-id", state, true, "tenant", "customer-link", NOW.plusSeconds(120)));
    }
}
