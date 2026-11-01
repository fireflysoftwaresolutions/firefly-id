package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.*;
import static io.firefly.id.nativeauth.NativeSecurity.require;

/** Handled AdminREST commits and native recovery share this database fence. */
public final class ReproofingRealmPolicyImpl {
    private ReproofingRealmPolicyImpl() { }
    private static EntityManager em(KeycloakSession session) { return session.getProvider(JpaConnectionProvider.class).getEntityManager(); }
    public static ReproofingRealmPolicyEntityImpl lock(KeycloakSession session) {
        return em(session).find(ReproofingRealmPolicyEntityImpl.class, session.getContext().getRealm().getId(), LockModeType.PESSIMISTIC_WRITE);
    }
    static void initialize(KeycloakSession session) {
        String realm = session.getContext().getRealm().getId();
        em(session).createNativeQuery("insert into ff_reproofing_realm_policy (id, revision) values (:realm, 0) on conflict (id) do nothing").setParameter("realm", realm).executeUpdate();
        require(lock(session) != null);
    }
    static RealmModel freshRealm(KeycloakSession session) {
        String realmId = session.getContext().getRealm().getId(); var em = em(session);
        // Detach the old parent and refresh its reloaded attribute rows: the request may have waited behind an administrative commit.
        var previous = em.find(RealmEntity.class, realmId); require(previous != null); em.detach(previous);
        var provider = session.getProvider(RealmProvider.class); require(provider != null);
        RealmModel realm = provider.getRealm(realmId); require(realm != null);
        var current = em.find(RealmEntity.class, realmId); require(current != null);
        current.getAttributes().forEach(em::refresh);
        session.getContext().setRealm(realm); return realm;
    }
    static ClientModel freshClient(KeycloakSession session, RealmModel realm, String id) {
        var provider = session.getProvider(ClientProvider.class); require(provider != null);
        ClientModel found = provider.getClientByClientId(realm, id);
        if (found == null) return null;
        var em = em(session); var current = em.find(ClientEntity.class, found.getId()); require(current != null); em.detach(current);
        ClientModel client = provider.getClientById(realm, found.getId()); require(client != null);
        current = em.find(ClientEntity.class, client.getId()); require(current != null); current.getAttributes().forEach(em::refresh);
        return client;
    }
}
