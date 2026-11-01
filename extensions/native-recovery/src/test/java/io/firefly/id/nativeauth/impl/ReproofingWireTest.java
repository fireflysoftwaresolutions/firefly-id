package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.ReproofingContracts.*;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class ReproofingWireTest {
    @Test void completeCoreWireRoundTripsExactUtcInstantsAndOpaqueBinding() {
        Instant expires = Instant.parse("2026-10-31T12:34:56.123456Z");
        UUID caseId = UUID.randomUUID(), executionId = UUID.randomUUID();
        Binding binding = new Binding("https://id.test/realms/customers", "customers", "tenant", "subject", UUID.randomUUID(), "HUMAN", "CREDENTIAL_REPLACEMENT", "stable-epoch", "complete-revision", "ceremony-nonce");
        Authorization authorization = new Authorization(caseId, UUID.randomUUID(), executionId, binding, "evidence-digest", "approved-policy", expires);
        Case value = new Case(caseId, binding, "CONSUMED", "provider", "approved-policy", UUID.randomUUID(), "provider-session", expires, authorization);
        String json = ReproofingWireImpl.json(value);
        assertTrue(json.contains("\"expiresAt\":\"2026-10-31T12:34:56.123456Z\""));
        assertEquals(value, ReproofingWireImpl.read(json, Case.class));
        var request = new NativeRequest(binding, caseId, executionId);
        assertEquals(request, ReproofingWireImpl.read(ReproofingWireImpl.json(request), NativeRequest.class));
        var admission = new Admission(binding, true, expires);
        assertEquals(admission, ReproofingWireImpl.read(ReproofingWireImpl.json(admission), Admission.class));
        var execution = new Execution(caseId, executionId, binding, "CREDENTIALS_REPLACED", expires);
        assertEquals(execution, ReproofingWireImpl.read(ReproofingWireImpl.json(execution), Execution.class));
    }
    @Test void nativeCodecRefusesUndeclaredApprovalClaims() {
        assertThrows(RuntimeException.class, () -> ReproofingWireImpl.read("{\"binding\":null,\"caseId\":null,\"executionId\":null,\"approved\":true}", NativeRequest.class));
    }
}
