package io.firefly.id.nativeauth;

import org.keycloak.Config;
import org.keycloak.events.*;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.*;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import java.util.Set;

/** Mandatory global listener; native material checks remain necessary for eventless internal writes. */
public final class NativeInvalidationFactory implements EventListenerProviderFactory {
    @Override public String getId() { return "firefly-native-recovery-invalidation"; }
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
        private void invalidate(String subject, boolean admin) {
            if (subject == null || session.getContext().getRealm().getAttribute("firefly.native-recovery.population") == null) return;
            try {
                NativeStore store = new NativeStore(session); var user = store.local(subject, false);
                NativeState state;
                try { state = store.state(subject, false); } catch (NativeRefusal missing) { return; }
                if (admin && state.locked && user.isEnabled()) { veto(session); return; }
                if (state.locked) { state.hold = true; store.audit(subject, "RECOVERY_HOLD", state.generation); }
                state.credentialRevision = store.revision(user, false);
                if (state.pinCredentialId != null) { state.pinHeld = true; store.audit(subject, "PIN_INVALIDATED", state.pinGeneration); }
            } catch (Exception error) { veto(session); }
        }
        @Override public void onEvent(Event event) {
            if (event.getError() == null && Set.of("UPDATE_PROFILE", "UPDATE_CREDENTIAL", "REMOVE_CREDENTIAL", "UPDATE_PASSWORD", "UPDATE_TOTP", "REMOVE_TOTP", "DELETE_ACCOUNT").contains(event.getType().name())) invalidate(event.getUserId(), false);
        }
        @Override public void onEvent(AdminEvent event, boolean includeRepresentation) {
            if (event.getError() != null || event.getResourcePath() == null) return;
            String[] path = event.getResourcePath().split("/");
            if (path.length >= 2 && "users".equals(path[0])) invalidate(path[1], true);
            else if (session.getContext().getRealm().getAttribute("firefly.native-recovery.population") != null
                    && event.getResourcePath().startsWith("attack-detection/brute-force")) veto(session);
        }
        @Override public void close() { }
    }; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
