package io.firefly.id.nativeauth;

import org.keycloak.Config;
import org.keycloak.events.*;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.*;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import java.util.Set;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeSecurity.digest;
import static io.firefly.id.nativeauth.NativeSecurity.require;

/** Mandatory global listener; native material checks remain necessary for eventless internal writes. */
public final class NativeInvalidationFactory implements EventListenerProviderFactory {
    @Override public String getId() { return "firefly-native-recovery-invalidation"; }
    static boolean revokePin(NativeState state, AdminEvent event, long now) {
        if (event == null || event.getResourcePath() == null || event.getOperationType() != OperationType.ACTION || state.pinCredentialId == null) return false;
        String[] path = event.getResourcePath().split("/");
        if (path.length != 4 || !"users".equals(path[0]) || !"credentials".equals(path[2])
                || !path[1].equals(state.subject) || !path[3].equals(state.pinCredentialId)) return false;
        var actor = event.getAuthDetails(); require(actor != null);
        NativeStore.auditValue(actor.getRealmId()); NativeStore.auditValue(actor.getUserId());
        NativeStore.auditValue(actor.getClientId()); NativeStore.auditValue(event.getId());
        state.pinCredentialId = null; state.pinRevokedAt = now; state.pinHeld = true; state.pinGeneration = UUID.randomUUID().toString();
        return true;
    }
    @Override public boolean isGlobal() { return true; }
    static void veto(KeycloakSession session) {
        try {
            var lookup = session.getProvider(JtaTransactionManagerLookup.class);
            if (lookup == null || lookup.getTransactionManager() == null) throw new NativeRefusal();
            lookup.getTransactionManager().setRollbackOnly();
        } catch (Exception error) {
            session.getTransactionManager().enlistPrepare(new AbstractKeycloakTransaction() {
                @Override protected void commitImpl() { throw new NativeRefusal(); }
                @Override protected void rollbackImpl() { }
            });
        }
        session.getTransactionManager().setRollbackOnly();
    }
    @Override public EventListenerProvider create(KeycloakSession session) { return new EventListenerProvider() {
        private void invalidate(String subject, boolean admin, boolean deleted, AdminEvent event) {
            if (subject == null || session.getContext().getRealm().getAttribute("firefly.native-recovery.population") == null) return;
            try {
                NativeStore store = new NativeStore(session);
                String stateId = digest(session.getContext().getRealm().getId() + "\n" + subject);
                if (store.em.find(NativeState.class, stateId) == null) return;
                if (deleted) {
                    NativeState removed = store.state(subject, false);
                    removed.hold = true; removed.pinHeld = true; removed.pinRevokedAt = System.currentTimeMillis();
                    store.audit(subject, "IDENTITY_REMOVED", removed.generation);
                    return;
                }
                var user = store.local(subject, false);
                NativeState state;
                try { state = store.state(subject, false); } catch (NativeRefusal missing) { return; }
                if (admin && state.locked && user.isEnabled()) { veto(session); return; }
                if (admin && revokePin(state, event, System.currentTimeMillis())) {
                    store.auditAdmin(subject, "PIN_REVOKED_ADMINISTRATIVE", state.pinGeneration, event); return;
                }
                if (state.locked) { state.hold = true; store.audit(subject, "RECOVERY_HOLD", state.generation); }
                state.credentialRevision = store.revision(user, false);
                if (state.pinCredentialId != null) { state.pinHeld = true; store.audit(subject, "PIN_INVALIDATED", state.pinGeneration); }
            } catch (Exception error) { veto(session); }
        }
        @Override public void onEvent(Event event) {
            if (event.getError() == null && Set.of("UPDATE_PROFILE", "UPDATE_CREDENTIAL", "REMOVE_CREDENTIAL", "UPDATE_PASSWORD", "UPDATE_TOTP", "REMOVE_TOTP", "DELETE_ACCOUNT").contains(event.getType().name())) invalidate(event.getUserId(), false, event.getType() == EventType.DELETE_ACCOUNT, null);
        }
        @Override public void onEvent(AdminEvent event, boolean includeRepresentation) {
            if (event.getError() != null || event.getResourcePath() == null) return;
            String[] path = event.getResourcePath().split("/");
            if (path.length >= 2 && "users".equals(path[0])) invalidate(path[1], true,
                    path.length == 2 && event.getOperationType() == OperationType.DELETE, event);
            else if (session.getContext().getRealm().getAttribute("firefly.native-recovery.population") != null
                    && event.getResourcePath().startsWith("attack-detection/brute-force")) veto(session);
        }
        @Override public void close() { }
    }; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
