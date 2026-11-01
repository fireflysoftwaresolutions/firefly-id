package io.firefly.id.nativeauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.keycloak.util.JsonSerialization;

/** A private RPC mapper; never changes Keycloak's global JWT or REST date settings. */
final class NativeWireImpl {
    private static final ObjectMapper MAPPER = JsonSerialization.mapper.copy().disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    static String json(Object value) {
        try { return MAPPER.writeValueAsString(value); } catch (Exception error) { throw new NativeRefusal(); }
    }
}
