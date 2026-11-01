package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static org.junit.jupiter.api.Assertions.*;

class NativeExecutionReconciliationTest {
    private final Binding binding = new Binding("https://identity.test/realms/customers", "opaque-tenant", "ceremony-client", null,
            "opaque-subject", "https://identity.test/realms/customers", "customers", "opaque-subject", "HUMAN", PURPOSE, "original-generation");
    private final Authorization receipt = new Authorization(UUID.randomUUID(), UUID.randomUUID(), binding,
            Instant.ofEpochSecond(Instant.now().getEpochSecond() - 60, 123456789));
    private NativeCeremony ceremony() {
        var c = new NativeCeremony(); c.id = "original-ceremony"; c.realmId = "realm-id"; c.subject = binding.actorSubject();
        c.generation = binding.lockGeneration(); c.operationId = receipt.operationId().toString(); c.bindingJson = NativeActor.json(binding);
        c.expiresAt = System.currentTimeMillis() + 60000; return c;
    }
    private NativeExecution journal() { return NativeExecution.committed(ceremony(), receipt, "SUCCEEDED", System.currentTimeMillis()); }
    @Test void journalReconstructsExactReceiptIncludingNanosecondsAfterReceiptExpiry() {
        var journal = journal();
        assertEquals(receipt, journal.authorization(ceremony()));
        assertTrue(journal.reserveRecording(ceremony(), System.currentTimeMillis()));
        assertEquals(receipt, journal.authorization(ceremony()));
    }
    @Test void callbackOutageKeepsSameReceiptAndHasDurableBoundedRetryBudget() {
        var journal = journal(); var c = ceremony();
        for (int i = 0; i < 3; i++) {
            assertTrue(journal.reserveRecording(c, System.currentTimeMillis()));
            assertEquals(receipt, journal.authorization(c));
        }
        assertFalse(journal.reserveRecording(c, System.currentTimeMillis()));
        assertEquals(3, journal.recordAttempts); assertFalse(journal.recorded);
    }
    @Test void acknowledgedJournalCannotAllocateAnotherCallback() {
        var journal = journal(); journal.recorded = true;
        assertFalse(journal.reserveRecording(ceremony(), System.currentTimeMillis()));
        assertEquals(0, journal.recordAttempts);
    }
    @Test void expiredOriginalCeremonyCannotMintMoreAuditAdmissionTime() {
        var journal = journal(); var c = ceremony(); c.expiresAt = System.currentTimeMillis() - 1;
        assertThrows(NativeRefusal.class, () -> journal.reserveRecording(c, System.currentTimeMillis()));
        assertEquals(0, journal.recordAttempts);
    }
    @Test void anotherCeremonyOperationBindingOrExpiryCannotReplaceCommittedReceipt() {
        var journal = journal(); var c = ceremony(); c.id = "another-ceremony";
        final var otherCeremony = c; assertThrows(NativeRefusal.class, () -> journal.authorization(otherCeremony));
        c = ceremony(); c.operationId = UUID.randomUUID().toString(); final var otherOperation = c;
        assertThrows(NativeRefusal.class, () -> journal.authorization(otherOperation));
        c = ceremony(); c.bindingJson = NativeActor.json(new Binding(binding.issuer(), "another-tenant", binding.clientId(), null,
                binding.actorSubject(), binding.targetIssuer(), binding.targetRealm(), binding.targetSubject(), binding.population(), PURPOSE, binding.lockGeneration()));
        final var otherBinding = c; assertThrows(NativeRefusal.class, () -> journal.authorization(otherBinding));
        assertThrows(NativeRefusal.class, () -> journal.requireAuthorization(ceremony(),
                new Authorization(receipt.operationId(), receipt.executionId(), binding, receipt.expiresAt().plusNanos(1))));
    }
    @Test void reloadOrLanguageChangePreservesAdmittedProgressWithoutStartingAnotherOperation() {
        assertEquals(NativeEngine.TOTP, NativeEngine.resumedStage("ADMITTED", true, false));
        assertEquals(NativeEngine.TOTP, NativeEngine.resumedStage("PROCESSING", true, false));
        assertEquals(NativeEngine.TOTP, NativeEngine.resumedStage("TOTP", true, false));
        assertEquals(NativeEngine.PASSWORD, NativeEngine.resumedStage("PASSWORD", false, false));
    }
    @Test void committedJournalAlwaysResumesCompleteEvenAfterInterruptedCallbackPost() {
        assertEquals(NativeEngine.COMPLETE, NativeEngine.resumedStage("PROCESSING", true, true));
        assertEquals(NativeEngine.COMPLETE, NativeEngine.resumedStage("TOTP", true, true));
        assertEquals(NativeEngine.COMPLETE, NativeEngine.resumedStage("COMPLETE", true, true));
    }
    @Test void expiredUncommittedCeremonyCannotAdvanceThroughFeedback() {
        var c = ceremony(); c.expiresAt = System.currentTimeMillis() - 1; c.stage = "PROCESSING";
        assertThrows(NativeRefusal.class, () -> NativeEngine.stage(c, null, NativeEngine.TOTP, true, System.currentTimeMillis()));
        assertEquals("PROCESSING", c.stage); assertFalse(c.failed);
    }
    @Test void expiryAfterCommitAllowsResultPresentationWithoutRenewingAuditAuthority() {
        var c = ceremony(); var committed = NativeExecution.committed(c, receipt, "SUCCEEDED", System.currentTimeMillis());
        c.expiresAt = System.currentTimeMillis() - 1; long originalExpiry = c.expiresAt;
        NativeEngine.stage(c, committed, NativeEngine.COMPLETE, true, System.currentTimeMillis());
        assertEquals(NativeEngine.COMPLETE, c.stage); assertTrue(c.failed); assertEquals(originalExpiry, c.expiresAt);
        assertEquals(receipt, committed.authorization(c));
        assertThrows(NativeRefusal.class, () -> committed.reserveRecording(c, System.currentTimeMillis()));
        assertEquals(0, committed.recordAttempts);
    }
    @Test void expiredFeedbackRequiresTheOriginalCanonicalExecution() {
        var c = ceremony(); c.expiresAt = System.currentTimeMillis() - 1; c.stage = "PROCESSING";
        var committed = journal(); committed.ceremonyId = "different-ceremony";
        assertThrows(NativeRefusal.class, () -> NativeEngine.stage(c, committed, NativeEngine.COMPLETE, true, System.currentTimeMillis()));
        assertEquals("PROCESSING", c.stage); assertFalse(c.failed);
    }
    @Test void expiredPinFeedbackIsLimitedToTheSameOwnerAndConsumedCeremony() {
        var c = ceremony(); c.expiresAt = System.currentTimeMillis() - 1; c.stage = "PIN_SET";
        assertThrows(NativeRefusal.class, () -> NativePinResource.setFeedback(c, c.subject, true));
        c.stage = "USED";
        assertThrows(NativeRefusal.class, () -> NativePinResource.setFeedback(c, "different-subject", true));
        assertFalse(c.failed);
        NativePinResource.setFeedback(c, c.subject, true); assertTrue(c.failed);
        assertEquals("USED", c.stage); assertTrue(c.expiresAt < System.currentTimeMillis());
    }
}
