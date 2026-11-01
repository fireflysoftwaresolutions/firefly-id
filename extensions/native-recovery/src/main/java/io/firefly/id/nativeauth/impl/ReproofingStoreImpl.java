package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.*;
import org.keycloak.storage.UserStoragePrivateUtil;
import org.keycloak.storage.StorageId;
import io.firefly.id.nativeauth.NativeState;
import io.firefly.id.nativeauth.ReproofingContracts.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import static io.firefly.id.nativeauth.NativeSecurityImpl.*;

final class ReproofingStoreImpl {
    final KeycloakSession session;
    final EntityManager em;
    ReproofingConfigImpl config;
    ReproofingStoreImpl(KeycloakSession session) { this.session = session; this.config = new ReproofingConfigImpl(session.getContext().getRealm()); em = session.getProvider(JpaConnectionProvider.class).getEntityManager(); }
    long now() { return ((Number) em.createNativeQuery("select cast(extract(epoch from clock_timestamp()) * 1000 as bigint)").getSingleResult()).longValue(); }
    ReproofingCeremonyImpl ceremony(String id, boolean live) {
        require(id != null && id.length() <= 128);
        var c = em.find(ReproofingCeremonyImpl.class, id, LockModeType.PESSIMISTIC_WRITE);
        require(c != null && c.realmId.equals(config.realm.getId()));
        if (live) require(c.expiresAt > now()); return c;
    }
    UserModel local(String subject) {
        require(subject != null && StorageId.isLocalStorage(subject));
        UserEntity entity = em.find(UserEntity.class, subject, LockModeType.PESSIMISTIC_WRITE);
        require(entity != null && config.realm.getId().equals(entity.getRealmId())); em.refresh(entity, LockModeType.PESSIMISTIC_WRITE);
        require(entity.getFederationLink() == null && entity.getServiceAccountClientLink() == null);
        require(ReproofingRealmPolicyImpl.lock(session) != null);
        config = new ReproofingConfigImpl(ReproofingRealmPolicyImpl.freshRealm(session));
        var users = UserStoragePrivateUtil.userLocalStorage(session);
        UserModel user = users.getUserById(config.realm, subject);
        require(user != null && !user.isFederated() && !user.isServiceAccount() && users.getFederatedIdentitiesStream(config.realm, user).findAny().isEmpty());
        return user;
    }
    NativeState nativeState(UserModel user) { return em.find(NativeState.class, digest(config.realm.getId() + "\n" + user.getId()), LockModeType.PESSIMISTIC_WRITE); }
    ReproofingStateImpl state(UserModel user, boolean create) {
        String id = digest(config.realm.getId() + "\n" + user.getId());
        var state = em.find(ReproofingStateImpl.class, id, LockModeType.PESSIMISTIC_WRITE);
        if (state == null && create) { state = new ReproofingStateImpl(); state.id = id; state.realmId = config.realm.getId(); state.subject = user.getId(); state.epoch = UUID.randomUUID().toString(); em.persist(state); }
        require(state != null); return state;
    }
    boolean eligible(UserModel user, NativeState nativeState) {
        ReproofingCryptoImpl.requireTotpPolicy(config.realm.getOTPPolicy());
        boolean customer = !administrator(user)
                && user.isEmailVerified() && user.getEmail() != null && user.getEmail().length() <= 512
                && config.value("tenant").equals(single(user, config.value("tenant-attribute")))
                && user.credentialManager().getStoredCredentialsByTypeStream("password").count() == 1;
        Set<String> types = user.credentialManager().getStoredCredentialsStream().map(CredentialModel::getType).collect(Collectors.toSet());
        return ReproofingPolicyImpl.eligible(user.isEnabled(), nativeState != null && nativeState.locked,
                nativeState != null && nativeState.hold, customer, user.getFirstAttribute(UserModel.DISABLED_REASON), types);
    }
    String revision(UserModel user, NativeState nativeState) {
        List<Object> credentials = new ArrayList<>();
        for (CredentialModel credential : user.credentialManager().getStoredCredentialsStream().sorted(Comparator.comparing(CredentialModel::getId)).toList()) {
            var value = em.find(CredentialEntity.class, credential.getId(), LockModeType.PESSIMISTIC_WRITE);
            require(value != null && value.getUser().getId().equals(user.getId())); em.refresh(value, LockModeType.PESSIMISTIC_WRITE);
            credentials.add(Arrays.asList(value.getId(), value.getType(), value.getCreatedDate(), value.getCredentialData(), value.getSecretData(), value.getUserLabel()));
        }
        var otp = config.realm.getOTPPolicy();
        var recovery = em.find(ReproofingStateImpl.class, digest(config.realm.getId() + "\n" + user.getId()), LockModeType.PESSIMISTIC_WRITE);
        var policyFence = ReproofingRealmPolicyImpl.lock(session); require(policyFence != null);
        return digest(ReproofingWireImpl.json(Arrays.asList(policyFence.revision, recovery == null ? 0L : recovery.invalidationVersion, credentials, user.getEmail(), user.isEmailVerified(), user.isEnabled(),
                user.getFirstAttribute(UserModel.DISABLED_REASON), single(user, config.value("tenant-attribute")), single(user, config.value("link-attribute")),
                effectiveRoles(user), user.getRequiredActionsStream().sorted().toList(), session.users().getNotBeforeOfUser(config.realm, user),
                nativeState == null ? null : Arrays.asList(nativeState.hold, nativeState.locked, nativeState.generation, nativeState.pinCredentialId, nativeState.pinKeyVersion, nativeState.pinGeneration, nativeState.pinHeld, nativeState.pinRevokedAt, nativeState.pinCreatedAt, nativeState.pinReplacedAt, nativeState.pinFailures, nativeState.pinReserved),
                config.realm.getPasswordPolicy().toString(), otp.getAlgorithm(), otp.getDigits(), otp.getPeriod(), otp.getType())));
    }
    void initializePolicy() { ReproofingRealmPolicyImpl.initialize(session); config = new ReproofingConfigImpl(ReproofingRealmPolicyImpl.freshRealm(session)); }
    void decoyPolicy() { require(ReproofingRealmPolicyImpl.lock(session) != null); config = new ReproofingConfigImpl(ReproofingRealmPolicyImpl.freshRealm(session)); }
    private static final String EFFECTIVE_ROLES = """
            with recursive user_groups(id) as (
              select m.group_id from user_group_membership m join keycloak_group g on g.id=m.group_id where m.user_id=:subject and g.realm_id=:realm
              union select p.id from keycloak_group g join user_groups u on g.id=u.id join keycloak_group p on p.id=g.parent_group where p.realm_id=:realm
            ), assigned(id) as (
              select m.role_id from user_role_mapping m join keycloak_role r on r.id=m.role_id where m.user_id=:subject and r.realm_id=:realm
              union select m.role_id from group_role_mapping m join keycloak_role r on r.id=m.role_id where m.group_id in (select id from user_groups) and r.realm_id=:realm
            ), effective(id) as (
              select id from assigned
              union select c.child_role from composite_role c join effective e on c.composite=e.id join keycloak_role r on r.id=c.child_role where r.realm_id=:realm
            )
            """;
    private jakarta.persistence.Query roles(UserModel user, String suffix) { return em.createNativeQuery(EFFECTIVE_ROLES + suffix).setParameter("subject", user.getId()).setParameter("realm", config.realm.getId()); }
    private boolean administrator(UserModel user) {
        return ((Number) roles(user, "select count(*) from effective e join keycloak_role r on r.id=e.id join client c on c.id=r.client where c.client_id='realm-management' and c.realm_id=:realm").getSingleResult()).longValue() != 0;
    }
    private java.util.List<String> effectiveRoles(UserModel user) {
        return roles(user, "select id from effective order by id").getResultList().stream().map(Object::toString).toList();
    }
    static String single(UserModel user, String attribute) { var values = user.getAttributeStream(attribute).toList(); require(values.size() == 1 && values.get(0) != null && !values.get(0).isBlank() && values.get(0).length() <= 512); return values.get(0); }
    Binding binding(ReproofingCeremonyImpl c) { return ReproofingWireImpl.read(c.bindingJson, Binding.class); }
    void current(ReproofingCeremonyImpl c, UserModel user) {
        Binding b = binding(c); var nativeState = nativeState(user); var state = state(user, false);
        require(eligible(user, nativeState) && state.failures < 3 && state.epoch.equals(b.generation())
                && b.issuer().equals(config.value("issuer")) && b.realm().equals(config.realm.getName()) && b.tenant().equals(config.value("tenant"))
                && b.partyId().toString().equals(single(user, config.value("link-attribute"))) && b.credentialRevision().equals(revision(user, nativeState)));
    }
    void evict(UserModel user) { var cache = session.getProvider(org.keycloak.models.cache.UserCache.class); if (cache != null) cache.evict(config.realm, user); }
    Execution execution(ReproofingExecutionImpl journal) { return new Execution(UUID.fromString(journal.caseId), UUID.fromString(journal.id), ReproofingWireImpl.read(journal.bindingJson, Binding.class), "CREDENTIALS_REPLACED", Instant.ofEpochMilli(journal.committedAt)); }
}
