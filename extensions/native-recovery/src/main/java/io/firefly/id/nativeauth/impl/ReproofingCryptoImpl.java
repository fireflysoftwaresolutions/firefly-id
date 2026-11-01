package io.firefly.id.nativeauth.impl;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.*;
import static io.firefly.id.nativeauth.NativeSecurity.require;

public final class ReproofingCryptoImpl {
    private static final SecureRandom RANDOM = new SecureRandom();
    private ReproofingCryptoImpl() { }
    static byte[] key() {
        try {
            String configured = System.getenv("FIREFLY_REPROOFING_ENROLLMENT_KEY_FILE"); require(configured != null);
            Path path = Path.of(configured); require(!Files.isSymbolicLink(path));
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            require(!permissions.contains(PosixFilePermission.GROUP_READ) && !permissions.contains(PosixFilePermission.GROUP_WRITE)
                    && !permissions.contains(PosixFilePermission.OTHERS_READ) && !permissions.contains(PosixFilePermission.OTHERS_WRITE));
            byte[] value = Files.readAllBytes(path); require(value.length == 32); return value;
        } catch (Exception error) { throw refused(); }
    }
    public static String seal(byte[] key, String context, String secret) {
        try {
            require(key != null && key.length == 32); byte[] nonce = new byte[12]; RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8)); byte[] value = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + value.length).put(nonce).put(value).array());
        } catch (Exception error) { throw refused(); }
    }
    public static String open(byte[] key, String context, String encrypted) {
        try {
            require(key != null && key.length == 32); byte[] value = Base64.getDecoder().decode(encrypted); require(value.length > 28 && value.length < 4096);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, Arrays.copyOfRange(value, 0, 12)));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8)); return new String(cipher.doFinal(Arrays.copyOfRange(value, 12, value.length)), StandardCharsets.UTF_8);
        } catch (Exception error) { throw refused(); }
    }
    static String secret() { byte[] value = new byte[20]; RANDOM.nextBytes(value); return base32(value); }
    private static String base32(byte[] bytes) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; StringBuilder value = new StringBuilder(); int bits = 0, buffer = 0;
        for (byte b : bytes) { buffer = (buffer << 8) | (b & 255); bits += 8; while (bits >= 5) { bits -= 5; value.append(alphabet.charAt((buffer >> bits) & 31)); } }
        if (bits > 0) value.append(alphabet.charAt((buffer << (5 - bits)) & 31)); return value.toString();
    }
    public static String totp(String secret, long now, int period, int digits, String algorithm) {
        try {
            require(period > 0 && digits >= 6 && digits <= 8 && Set.of("HmacSHA1", "HmacSHA256", "HmacSHA512").contains(algorithm));
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream(); int buffer = 0, bits = 0;
            for (char c : secret.toCharArray()) { int n = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c); require(n >= 0); buffer = (buffer << 5) | n; bits += 5; if (bits >= 8) { bits -= 8; bytes.write((buffer >> bits) & 255); } }
            byte[] key = bytes.toByteArray(); Mac mac = Mac.getInstance(algorithm); mac.init(new SecretKeySpec(key, algorithm));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(now / (period * 1000L)).array()); Arrays.fill(key, (byte) 0);
            int offset = hash[hash.length - 1] & 15; int binary = ByteBuffer.wrap(hash, offset, 4).getInt() & 0x7fffffff;
            return String.format(Locale.ROOT, "%0" + digits + "d", binary % (long) Math.pow(10, digits));
        } catch (Exception error) { throw refused(); }
    }
    private static IllegalStateException refused() { return new IllegalStateException("Recovery unavailable"); }
}
