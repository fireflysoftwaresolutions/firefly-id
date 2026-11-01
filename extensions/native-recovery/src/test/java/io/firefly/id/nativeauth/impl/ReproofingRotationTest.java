package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.lang.reflect.InvocationTargetException;
import static org.junit.jupiter.api.Assertions.*;

class ReproofingRotationTest {
    @TempDir Path directory;
    private Object ring(String active, Path keyDirectory, Path legacy) throws Exception {
        Class<?> type;
        try { type = Class.forName("io.firefly.id.nativeauth.impl.ReproofingKeyringImpl"); }
        catch (ClassNotFoundException missing) { fail("Missing durable versioned recovery key rotation"); return null; }
        return type.getConstructor(String.class, Path.class, Path.class).newInstance(active, keyDirectory, legacy);
    }
    private String call(Object ring, String method, String context, String value) throws Exception {
        return (String) ring.getClass().getMethod(method, String.class, String.class).invoke(ring, context, value);
    }
    private void key(String name, int value) throws Exception {
        byte[] bytes = new byte[32]; java.util.Arrays.fill(bytes, (byte) value); Path file = directory.resolve(name); Files.write(file, bytes); Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }
    @Test void rotationRetainsOldDecryptOnlyVersionAndRefusesMissingOrSubstitutedKeys() throws Exception {
        key("v1", 1); key("v2", 2); key("same-material", 1);
        Object old = ring("v1", directory, null);
        String previous = call(old, "seal", "notification:original", "private-destination");
        assertTrue(previous.startsWith("ffr1:v1:"));
        Object rotated = ring("v2", directory, null);
        assertEquals("private-destination", call(rotated, "open", "notification:original", previous));
        String next = call(rotated, "seal", "notification:next", "new-private-destination");
        assertTrue(next.startsWith("ffr1:v2:"));
        assertEquals("new-private-destination", call(rotated, "open", "notification:next", next));
        assertThrows(InvocationTargetException.class, () -> call(rotated, "open", "notification:other", previous));
        assertThrows(InvocationTargetException.class, () -> call(rotated, "open", "notification:original", previous.replace(":v1:", ":same-material:")));
        Files.move(directory.resolve("v1"), directory.resolve("retired-v1"));
        assertThrows(InvocationTargetException.class, () -> call(rotated, "open", "notification:original", previous));
        assertEquals("new-private-destination", call(rotated, "open", "notification:next", next));
    }
    @Test void legacyMountedFileIsExplicitV1AndCannotOverrideConfiguredKeyring() throws Exception {
        key("legacy", 3);
        Object legacy = ring(null, null, directory.resolve("legacy"));
        String value = call(legacy, "seal", "ceremony", "pending-secret"); assertTrue(value.startsWith("ffr1:v1:"));
        assertEquals("pending-secret", call(legacy, "open", "ceremony", value));
        assertThrows(InvocationTargetException.class, () -> ring("v2", directory, directory.resolve("legacy")));
        assertThrows(InvocationTargetException.class, () -> call(legacy, "open", "ceremony", value.replace(":v1:", ":v2:")));
    }
}
