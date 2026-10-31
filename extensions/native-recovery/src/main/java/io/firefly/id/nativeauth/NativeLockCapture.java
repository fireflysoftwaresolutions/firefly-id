package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class NativeLockCapture {
    static final String TRANSITION = "firefly.native.enabled-before-failure.";
    static void capture(KeycloakSession session, String subject) {
        NativeProfile.of(session.getContext().getRealm());
        if (!Boolean.TRUE.equals(session.getAttribute(TRANSITION + subject))) return;
        NativeStore store = new NativeStore(session);
        var user = store.local(subject, false);
        require(!user.isEnabled() && "permanentLockout".equals(user.getFirstAttribute(org.keycloak.models.UserModel.DISABLED_REASON)));
        NativeState state = store.state(subject, true);
        if (state.locked) return;
        state.generation = UUID.randomUUID().toString(); state.locked = true; state.lockedAt = System.currentTimeMillis();
        state.credentialRevision = store.revision(user); state.bootstrapAttempts = 0; state.knowledgeAttempts = 0; state.possessionAttempts = 0;
        store.audit(subject, "PERMANENT_LOCK_CAPTURED", state.generation);
    }
}
