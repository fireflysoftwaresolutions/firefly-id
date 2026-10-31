package io.firefly.id.nativeauth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.CredentialEntity;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStoragePrivateUtil;
import java.util.Comparator;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class NativeStore {
    final KeycloakSession session;
    final EntityManager em;
    NativeStore(KeycloakSession session) { this.session = session; this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager(); }
    UserModel local(String subject, boolean refresh) {
        require(subject != null && StorageId.isLocalStorage(subject));
        var realm = session.getContext().getRealm();
        UserEntity entity = em.find(UserEntity.class, subject, LockModeType.PESSIMISTIC_WRITE);
        require(entity != null && realm.getId().equals(entity.getRealmId()) && entity.getFederationLink() == null && entity.getServiceAccountClientLink() == null);
        String refreshKey = "firefly.native.user-refreshed." + subject;
        if (refresh && !Boolean.TRUE.equals(session.getAttribute(refreshKey))) {
            em.refresh(entity, LockModeType.PESSIMISTIC_WRITE); session.setAttribute(refreshKey, true);
        }
        UserModel user = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, subject);
        require(user != null && !user.isFederated() && !user.isServiceAccount());
        return user;
    }
    NativeState state(String subject, boolean create) {
        String id = digest(session.getContext().getRealm().getId() + "\n" + subject);
        NativeState state = em.find(NativeState.class, id, LockModeType.PESSIMISTIC_WRITE);
        if (state == null && create) {
            state = new NativeState(); state.id = id; state.realmId = session.getContext().getRealm().getId(); state.subject = subject; em.persist(state);
        }
        require(state != null); return state;
    }
    String revision(UserModel user) { return revision(user, true); }
    String revision(UserModel user, boolean refresh) {
        StringBuilder value = new StringBuilder();
        var credentials = user.credentialManager().getStoredCredentialsStream().filter(c -> "password".equals(c.getType()) || "otp".equals(c.getType()))
                .sorted(Comparator.comparing(CredentialModel::getId)).toList();
        for (CredentialModel credential : credentials) {
            CredentialEntity current = em.find(CredentialEntity.class, credential.getId(), LockModeType.PESSIMISTIC_WRITE);
            require(current != null && current.getUser().getId().equals(user.getId()));
            if (refresh) em.refresh(current, LockModeType.PESSIMISTIC_WRITE);
            value.append(current.getId()).append('\n').append(current.getType()).append('\n').append(current.getCreatedDate()).append('\n')
                    .append(current.getCredentialData()).append('\n').append(current.getSecretData()).append('\n');
        }
        return digest(value.toString());
    }
    void invalidateCache(UserModel user) {
        var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
        if (cache != null) cache.evict(session.getContext().getRealm(), user);
    }
    void audit(String subject, String event, String reference) {
        NativeAudit audit = new NativeAudit(); audit.id = UUID.randomUUID().toString(); audit.realmId = session.getContext().getRealm().getId();
        audit.subject = subject; audit.eventType = event; audit.referenceId = reference; audit.occurredAt = System.currentTimeMillis(); em.persist(audit);
    }
    NativeCeremony ceremony(String id) {
        require(id != null && id.length() <= 64);
        NativeCeremony ceremony = em.find(NativeCeremony.class, id, LockModeType.PESSIMISTIC_WRITE);
        require(ceremony != null && ceremony.realmId.equals(session.getContext().getRealm().getId()) && ceremony.expiresAt > System.currentTimeMillis());
        return ceremony;
    }
    boolean isAdministrator(UserModel user) {
        var admin = session.clients().getClientByClientId(session.getContext().getRealm(), "realm-management");
        return admin != null && admin.getRolesStream().anyMatch(user::hasRole);
    }
    void requireSelfService(UserModel user) { require(!isAdministrator(user)); }
    void eligible(NativeState state, UserModel user) {
        requireSelfService(user);
        require(state.locked && !state.hold && !user.isEnabled() && state.generation != null
                && "permanentLockout".equals(user.getFirstAttribute(UserModel.DISABLED_REASON))
                && state.credentialRevision.equals(revision(user)));
    }
}
