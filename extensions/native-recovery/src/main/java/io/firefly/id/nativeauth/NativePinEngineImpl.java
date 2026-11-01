package io.firefly.id.nativeauth;

import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.managers.BruteForceProtector;
import java.time.Instant;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

/** PIN is a native knowledge credential. It never authorizes login, recovery or business operations. */
final class NativePinEngineImpl {
    private static final String TYPE = "firefly-support-pin";
    private final KeycloakSession request;
    NativePinEngineImpl(KeycloakSession request) { this.request = request; }
    PinStatus status(String subject) {
        return NativePhases.run(request, session -> {
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(subject, true); store.requireSelfService(user);
            require(user.isEnabled() && "HUMAN".equals(NativeProfile.of(session.getContext().getRealm()).population()));
            NativeState state;
            try { state = store.state(subject, false); } catch (NativeRefusal absent) { return new PinStatus("ABSENT", null, null, null); }
            return new PinStatus(state.pinCredentialId == null || state.pinRevokedAt > 0 ? "ABSENT" : (state.pinHeld || state.pinFailures + state.pinReserved >= 3) ? "LOCKED" : "ACTIVE",
                    instant(state.pinCreatedAt), instant(state.pinReplacedAt), instant(state.pinRevokedAt));
        });
    }
    boolean replace(String subject, String password, String otp, String pin, String confirmation, boolean revoke) {
        if (!revoke) { requirePin(pin); require(pin.equals(confirmation)); }
        return NativePhases.run(request, session -> {
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(subject, true); store.requireSelfService(user);
            require(user.isEnabled() && "HUMAN".equals(NativeProfile.of(session.getContext().getRealm()).population()));
            NativeState state = store.state(subject, true);
            require(!state.locked && !state.hold && !session.getContext().getRealm().getOTPPolicy().isCodeReusable());
            CredentialModel totp = user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .filter(c -> OTPCredentialModel.TOTP.equals(OTPCredentialModel.createFromCredentialModel(c).getOTPCredentialData().getSubType()))
                    .findFirst().orElseThrow(NativeRefusal::new);
            boolean valid = NativeEngineImpl.passwordValid(session, user, password)
                    && otp != null && NativeCredentials.totp(session, user, totp.getId(), otp);
            if (!valid) {
                session.getProvider(BruteForceProtector.class).failedLogin(session.getContext().getRealm(), user,
                        request.getContext().getConnection(), request.getContext().getUri(), java.util.Set.of("password", OTPCredentialModel.TYPE));
                store.audit(subject, "PIN_STEP_UP_REFUSED", null); return false;
            }
            if (state.pinCredentialId != null) user.credentialManager().removeStoredCredentialById(state.pinCredentialId);
            state.pinGeneration = UUID.randomUUID().toString(); state.pinFailures = 0; state.pinReserved = 0; state.pinHeld = false;
            long now = System.currentTimeMillis();
            if (revoke) {
                state.pinCredentialId = null; state.pinRevokedAt = now; store.invalidateCache(user);
                store.audit(subject, "PIN_REVOKED", state.pinGeneration); return true;
            }
            String version = NativePinProtection.activeVersion();
            String keyed = NativePinProtection.keyed(session.getContext().getRealm().getId(), subject, pin, version);
            PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class, "argon2"); require(hash != null);
            PasswordCredentialModel credential = hash.encodedCredential(keyed, 5); credential.setType(TYPE); credential.setCreatedDate(now);
            var stored = user.credentialManager().createStoredCredential(credential);
            state.pinCredentialId = stored.getId(); state.pinKeyVersion = version; state.pinRevokedAt = 0;
            if (state.pinCreatedAt == 0) state.pinCreatedAt = now; else state.pinReplacedAt = now;
            store.invalidateCache(user); store.audit(subject, "PIN_REPLACED", state.pinGeneration); return true;
        });
    }
    private static Instant instant(long value) { return value == 0 ? null : Instant.ofEpochMilli(value); }
}
