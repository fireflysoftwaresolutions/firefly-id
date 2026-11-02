package io.firefly.id.nativeauth;

import org.keycloak.Config;
import io.firefly.id.nativeauth.impl.ReproofingStateImpl;
import io.firefly.id.nativeauth.impl.ReproofingRealmPolicyImpl;
import jakarta.persistence.LockModeType;
import org.keycloak.events.*;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.*;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import java.util.Set;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeSecurityImpl.digest;
import static io.firefly.id.nativeauth.NativeSecurityImpl.require;

/** Mandatory global listener; native material checks remain necessary for eventless internal writes. */
public final class NativeInvalidationFactoryImpl implements EventListenerProviderFactory {
    @Override public String getId() { return "firefly-native-recovery-invalidation"; }
    static boolean revokePin(NativeState state, AdminEvent event, long now) {
        if (event == null || event.getResourcePath() == null || event.getOperationType() != OperationType.ACTION || state.pinCredentialId == null) return false;
        String[] path = event.getResourcePath().split("/");
        if (path.length != 4 || !"users".equals(path[0]) || !"credentials".equals(path[2])
                || !path[1].equals(state.subject) || !path[3].equals(state.pinCredentialId)) return false;
        var actor = event.getAuthDetails(); require(actor != null);
        NativeStoreImpl.auditValue(actor.getRealmId()); NativeStoreImpl.auditValue(actor.getUserId());
        NativeStoreImpl.auditValue(actor.getClientId()); NativeStoreImpl.auditValue(event.getId());
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
        private void invalidate(String subject, boolean admin, boolean deleted, AdminEvent event, String selfEventId) {
            if (subject == null) return;
            try {
                NativeStoreImpl store = new NativeStoreImpl(session);
                String stateId = digest(session.getContext().getRealm().getId() + "\n" + subject);
                boolean nativeTracked = store.em.find(NativeState.class, stateId) != null;
                boolean reproofingTracked = store.em.find(ReproofingStateImpl.class, stateId) != null;
                if (!nativeTracked && !reproofingTracked) return;
                if (deleted) {
                    ReproofingRealmPolicyImpl.lock(session);
                    if (reproofingTracked) invalidateReproofing(store, stateId, subject, admin, event, selfEventId);
                    if (!nativeTracked) return;
                    NativeState removed = store.state(subject, false);
                    removed.hold = true; removed.pinHeld = true; removed.pinRevokedAt = System.currentTimeMillis();
                    store.audit(subject, "IDENTITY_REMOVED", removed.generation);
                    return;
                }
                var user = store.local(subject, false);
                ReproofingRealmPolicyImpl.lock(session);
                if (reproofingTracked) invalidateReproofing(store, stateId, subject, admin, event, selfEventId);
                if (!nativeTracked) return;
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
        private void invalidateReproofing(NativeStoreImpl store, String stateId, String subject, boolean admin, AdminEvent event, String selfEventId) {
            var state = store.em.find(ReproofingStateImpl.class, stateId, LockModeType.PESSIMISTIC_WRITE); require(state != null);
            state.invalidationVersion = Math.addExact(state.invalidationVersion, 1L);
            if (admin) store.auditAdmin(subject, "REPROOFING_INVALIDATED_ADMINISTRATIVE", state.epoch, event);
            else store.audit(subject, "REPROOFING_INVALIDATED_SELF_SERVICE", selfEventId == null ? state.epoch : selfEventId);
        }
        private void invalidateRealmPolicy(AdminEvent event) {
            var policy = ReproofingRealmPolicyImpl.lock(session);
            if (policy == null) return;
            policy.revision = Math.addExact(policy.revision, 1L);
            new NativeStoreImpl(session).auditAdmin(null, "REPROOFING_REALM_POLICY_INVALIDATED", Long.toString(policy.revision), event);
        }
        @Override public void onEvent(Event event) {
            if (event.getError() == null && Set.of("UPDATE_PROFILE", "UPDATE_CREDENTIAL", "REMOVE_CREDENTIAL", "UPDATE_PASSWORD", "UPDATE_TOTP", "REMOVE_TOTP", "DELETE_ACCOUNT").contains(event.getType().name())) invalidate(event.getUserId(), false, event.getType() == EventType.DELETE_ACCOUNT, null, event.getId());
        }
        @Override public void onEvent(AdminEvent event, boolean includeRepresentation) {
            if (event.getError() != null || event.getResourcePath() == null) return;
            String[] path = event.getResourcePath().split("/");
            if (path.length >= 2 && "users".equals(path[0])) invalidate(path[1], true,
                    path.length == 2 && event.getOperationType() == OperationType.DELETE, event, null);
            else if (session.getContext().getRealm().getAttribute("firefly.native-recovery.population") != null
                    && event.getResourcePath().startsWith("attack-detection/brute-force")) veto(session);
            else { try { invalidateRealmPolicy(event); } catch (Exception error) { veto(session); } }
        }
        @Override public void close() { }
    }; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
