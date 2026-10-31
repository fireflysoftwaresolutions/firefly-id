package io.firefly.id.nativeauth;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public final class NativeSecurity {
    private static final SecureRandom RANDOM = new SecureRandom();
    private NativeSecurity() { }
    public static String randomToken() { byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    public static String digest(String value) {
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception exception) { throw new NativeRefusal(); }
    }
    public static boolean matches(String value, String digest) {
        return value != null && digest != null && MessageDigest.isEqual(digest(value).getBytes(StandardCharsets.US_ASCII), digest.getBytes(StandardCharsets.US_ASCII));
    }
    public static void require(boolean condition) { if (!condition) throw new NativeRefusal(); }
    public static void requireOrigin(String supplied, String trusted) {
        try { URI uri = URI.create(trusted); require("https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null && uri.getRawQuery() == null && uri.getRawFragment() == null && (uri.getPath().isEmpty() || "/".equals(uri.getPath())) && trusted.equals(supplied)); }
        catch (Exception exception) { throw new NativeRefusal(); }
    }
    public static void requirePin(String pin) {
        require(pin != null && pin.matches("[0-9]{8}"));
        require(!pin.matches("([0-9])\\1{7}") && !pin.substring(0, 4).equals(pin.substring(4))
                && !(pin.substring(0, 2).repeat(4).equals(pin)));
        String ascending = "01234567890123456789", descending = "98765432109876543210";
        require(!ascending.contains(pin) && !descending.contains(pin));
    }
}
