package io.firefly.id.nativeauth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

/** External versioned pepper is never persisted in the identity database or credential metadata. */
final class NativePinProtection {
    static String activeVersion() { String version = System.getenv("FIREFLY_SUPPORT_PIN_ACTIVE_KEY"); require(version != null && version.matches("[A-Za-z0-9_-]{1,64}")); return version; }
    static String keyed(String realm, String subject, String pin, String version) {
        requirePin(pin); require(version != null && version.matches("[A-Za-z0-9_-]{1,64}"));
        if (!version.equals(activeVersion())) {
            String until = System.getenv("FIREFLY_SUPPORT_PIN_VERIFY_UNTIL_" + version);
            try { require(until != null && Instant.parse(until).isAfter(Instant.now())); } catch (Exception error) { throw new NativeRefusal(); }
        }
        byte[] key = null;
        try {
            String configured = System.getenv("FIREFLY_SUPPORT_PIN_KEYS_DIR"); require(configured != null);
            Path directory = Path.of(configured).toRealPath(); Path path = directory.resolve(version);
            require(!Files.isSymbolicLink(path) && path.toRealPath().getParent().equals(directory));
            var permissions = Files.getPosixFilePermissions(path);
            require(!permissions.contains(PosixFilePermission.GROUP_READ) && !permissions.contains(PosixFilePermission.GROUP_WRITE)
                    && !permissions.contains(PosixFilePermission.OTHERS_READ) && !permissions.contains(PosixFilePermission.OTHERS_WRITE));
            key = Files.readAllBytes(path); require(key.length >= 32 && key.length <= 4096);
            return hmac(key, realm, subject, pin);
        } catch (Exception error) { throw new NativeRefusal(); }
        finally { if (key != null) Arrays.fill(key, (byte) 0); }
    }
    static String hmac(byte[] key, String realm, String subject, String pin) {
        try {
            require(key != null && key.length >= 32);
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal((realm + "\u0000" + subject + "\u0000" + pin).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception error) { throw new NativeRefusal(); }
    }
}
