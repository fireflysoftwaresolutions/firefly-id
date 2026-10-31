package io.firefly.id.nativeauth;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class NativeWireTest {
    @Test void privateRpcInstantsAreRfc3339WithoutChangingGlobalKeycloakMapper() {
        String json = NativeWire.json(new NativeContracts.AuditReceipt(UUID.randomUUID(), Instant.parse("2026-10-31T12:00:00Z")));
        assertTrue(json.contains("\"committedAt\":\"2026-10-31T12:00:00Z\""));
    }
}
