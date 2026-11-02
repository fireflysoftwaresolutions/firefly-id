package io.firefly.id.nativeauth.impl;

import com.fasterxml.jackson.databind.*;
import org.keycloak.util.JsonSerialization;

final class ReproofingWireImpl {
    static final ObjectMapper JSON = JsonSerialization.mapper.copy().disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS).enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    static String json(Object value) { try { return JSON.writeValueAsString(value); } catch (Exception error) { throw new IllegalStateException("Recovery unavailable"); } }
    static <T> T read(String value, Class<T> type) { try { return JSON.readValue(value, type); } catch (Exception error) { throw new IllegalStateException("Recovery unavailable"); } }
}
