package io.firefly.id.nativeauth;

/** Deliberately carries no secret, provider exception or target details. */
public final class NativeRefusal extends RuntimeException {
    public NativeRefusal() { super("Recovery is unavailable or cannot be completed"); }
}
