package io.firefly.id.nativeauth.impl;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import static io.firefly.id.nativeauth.NativeSecurity.require;

/** Active encryption version plus explicitly retained decrypt-only mounted versions. */
public final class ReproofingKeyringImpl {
    private final String active;
    private final Path directory;
    private final Path legacy;
    public ReproofingKeyringImpl(String active, Path directory, Path legacy) {
        if (active == null) {
            require(directory == null && legacy != null); this.active = "v1"; this.directory = null; this.legacy = legacy;
        } else {
            version(active); require(directory != null && legacy == null);
            try { require(!Files.isSymbolicLink(directory) && Files.isDirectory(directory)); this.directory = directory.toRealPath(); }
            catch (Exception error) { throw refused(); }
            this.active = active; this.legacy = null;
        }
    }
    static ReproofingKeyringImpl configured() {
        String active = System.getenv("FIREFLY_REPROOFING_ACTIVE_KEY"), directory = System.getenv("FIREFLY_REPROOFING_KEYS_DIR"), legacy = System.getenv("FIREFLY_REPROOFING_ENROLLMENT_KEY_FILE");
        return new ReproofingKeyringImpl(active, directory == null ? null : Path.of(directory), legacy == null ? null : Path.of(legacy));
    }
    void requireActive() { byte[] key = read(active); Arrays.fill(key, (byte) 0); }
    public String seal(String context, String value) {
        byte[] key = read(active);
        try { return ReproofingCryptoImpl.seal(key, active, context, value); }
        finally { Arrays.fill(key, (byte) 0); }
    }
    public String open(String context, String value) {
        String version = ReproofingCryptoImpl.version(value); byte[] key = read(version);
        try { return ReproofingCryptoImpl.open(key, version, context, value); }
        finally { Arrays.fill(key, (byte) 0); }
    }
    private byte[] read(String version) {
        version(version);
        try {
            require(legacy == null || "v1".equals(version)); Path path = legacy == null ? directory.resolve(version) : legacy;
            require(!Files.isSymbolicLink(path) && Files.isRegularFile(path) && Files.size(path) == 32);
            if (directory != null) require(path.toRealPath().getParent().equals(directory));
            var permissions = Files.getPosixFilePermissions(path);
            require(!permissions.contains(PosixFilePermission.GROUP_READ) && !permissions.contains(PosixFilePermission.GROUP_WRITE)
                    && !permissions.contains(PosixFilePermission.OTHERS_READ) && !permissions.contains(PosixFilePermission.OTHERS_WRITE));
            byte[] key = Files.readAllBytes(path); require(key.length == 32); return key;
        } catch (Exception error) { throw refused(); }
    }
    static void version(String value) { require(value != null && value.matches("[A-Za-z0-9_-]{1,64}")); }
    private static IllegalStateException refused() { return new IllegalStateException("Recovery unavailable"); }
    @Override public String toString() { return "ReproofingKeyring[REDACTED]"; }
}
