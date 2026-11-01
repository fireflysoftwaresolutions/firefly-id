package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.NativePhases;
import io.firefly.id.nativeauth.ReproofingContracts.*;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class ReproofingEngineImpl {
    record View(String id, String csrf, String stage, String verificationUrl, String secret, boolean failed, boolean recordPending) { @Override public String toString() { return "ReproofingView[REDACTED]"; } }
    private final KeycloakSession request;
    ReproofingEngineImpl(KeycloakSession request) { this.request = request; }
    View create() {
        ReproofingKeyringImpl.configured().requireActive();
        return NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = new ReproofingCeremonyImpl(); c.id = randomToken(); c.realmId = store.config.realm.getId();
            String csrf = randomToken(); c.csrfDigest = digest(csrf); c.stage = "IDENTIFY"; c.expiresAt = store.now() + store.config.ttl() * 1000L;
            store.em.persist(c); return new View(c.id, csrf, c.stage, null, null, false, false);
        });
    }
    View resume(String id) {
        return NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, false); var journal = journal(store, c);
            if (journal != null) c.stage = "COMPLETE"; else require(c.expiresAt > store.now());
            String csrf = randomToken(); c.csrfDigest = digest(csrf); String secret = null;
            if ("ENROLL".equals(c.stage)) { var user = store.local(c.subject); store.current(c, user); require(authorization(c).expiresAt().toEpochMilli() > store.now()); secret = open(c.id, c.encryptedTotp); }
            return new View(c.id, csrf, c.stage, c.verificationUrl, secret, c.failed, journal != null && !journal.recorded && journal.recordAttempts < 8);
        });
    }
    String csrf(String id, String token) {
        return NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, false);
            require(token != null && token.length() <= 128 && matches(token, c.csrfDigest));
            require("COMPLETE".equals(c.stage) && journal(store, c) != null || c.expiresAt > store.now());
            c.csrfDigest = digest(randomToken()); c.failed = false; return c.stage;
        });
    }
    void identify(String id, String username) {
        require(username != null && !username.isBlank() && username.length() <= 254);
        Binding binding = NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, true);
            if (c.bindingJson != null) return store.binding(c);
            UserModel user = null;
            try {
                var found = KeycloakModelUtils.findUserByNameOrEmail(child, store.config.realm, username.strip());
                if (found != null) { user = store.local(found.getId()); if (!store.eligible(user, store.nativeState(user))) user = null; }
            } catch (RuntimeException ineligible) { user = null; }
            Binding b;
            if (user != null) {
                var state = store.state(user, true); var ns = store.nativeState(user);
                b = new Binding(store.config.value("issuer"), store.config.realm.getName(), store.config.value("tenant"), user.getId(),
                        UUID.fromString(ReproofingStoreImpl.single(user, store.config.value("link-attribute"))), "HUMAN", "CREDENTIAL_REPLACEMENT", state.epoch, store.revision(user, ns), c.id);
                c.subject = user.getId(); c.notificationDestination = seal(c.id + ":email", user.getEmail());
            } else {
                b = new Binding(store.config.value("issuer"), store.config.realm.getName(), store.config.value("tenant"), UUID.randomUUID().toString(), UUID.randomUUID(),
                        "HUMAN", "CREDENTIAL_REPLACEMENT", UUID.randomUUID().toString(), randomToken(), c.id);
            }
            c.bindingJson = ReproofingWireImpl.json(b); c.stage = "VERIFY"; return b;
        });
        // Independent proofing uses the same provider journey for eligible, held, ambiguous and decoy bindings.
        start(id, binding);
    }
    private void start(String id, Binding binding) {
        var journey = gateway().begin(binding);
        NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, true); var value = journey.value();
            require(binding.equals(store.binding(c)) && value.expiresAt().toEpochMilli() <= c.expiresAt && value.expiresAt().toEpochMilli() > store.now());
            require(c.caseId == null || c.caseId.equals(value.caseId().toString())); c.caseId = value.caseId().toString(); c.verificationUrl = journey.verificationUrl(); return null;
        });
    }
    void confirm(String id) {
        Binding unstarted = NativePhases.run(request, child -> { var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, true); return c.caseId == null ? store.binding(c) : null; });
        if (unstarted != null) { start(id, unstarted); return; }
        var pending = NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, true); require(c.caseId != null); return new NativeRequest(store.binding(c), UUID.fromString(c.caseId), null);
        });
        Case value = gateway().confirm(pending.caseId(), pending.binding());
        require(value.authorization() != null && "VERIFIED".equals(value.status()));
        NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, true); var user = store.local(c.subject); store.current(c, user);
            Authorization auth = value.authorization(); require(auth.expiresAt().toEpochMilli() > store.now() && auth.expiresAt().toEpochMilli() <= c.expiresAt && pending.binding().equals(auth.binding()) && c.caseId.equals(auth.caseId().toString()));
            if (c.authorizationJson != null) require(authorization(c).equals(auth)); else c.authorizationJson = ReproofingWireImpl.json(auth);
            if (c.encryptedTotp == null) c.encryptedTotp = seal(c.id, ReproofingCryptoImpl.secret());
            c.stage = "ENROLL"; return null;
        });
    }
    boolean replace(String id, String password, String confirmation, String otp) {
        require(password != null && password.length() <= 1024 && password.equals(confirmation) && otp != null && otp.matches("[0-9]{6,8}"));
        Authorization auth = NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, true); require("ENROLL".equals(c.stage));
            var existing = journal(store, c); if (existing != null) return ReproofingWireImpl.read(existing.authorizationJson, Authorization.class);
            var user = store.local(c.subject); store.current(c, user); Authorization value = authorization(c);
            require(value.expiresAt().toEpochMilli() > store.now()); passwordPolicy(child, store, user, password);
            if (!otpValid(store, c, otp)) { store.state(user, false).failures++; c.failed = true; return null; }
            return value;
        });
        if (auth == null) return false;
        // Remote consume/verification completes before the user/state lock and native credential transaction.
        gateway().consume(auth); gateway().verify(auth);
        NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, false);
            var existing = journal(store, c);
            if (existing != null) { require(existing.id.equals(auth.executionId().toString()) && existing.authorizationJson.equals(ReproofingWireImpl.json(auth))); return null; }
            var user = store.local(c.subject); store.current(c, user); long now = store.now();
            require(c.expiresAt > now && auth.expiresAt().toEpochMilli() > now && auth.equals(authorization(c)) && otpValid(store, c, otp));
            passwordPolicy(child, store, user, password);
            String secret = open(c.id, c.encryptedTotp); var policy = store.config.realm.getOTPPolicy(); require(OTPCredentialModel.TOTP.equals(policy.getType()));
            require(user.credentialManager().updateCredential(UserCredentialModel.password(password)));
            user.credentialManager().getStoredCredentialsStream().filter(v -> Set.of("otp", "firefly-support-pin").contains(v.getType())).map(org.keycloak.credential.CredentialModel::getId).toList().forEach(user.credentialManager()::removeStoredCredentialById);
            var replacementOtp = user.credentialManager().createStoredCredential(OTPCredentialModel.createTOTP(secret, policy.getDigits(), policy.getPeriod(), policy.getAlgorithm(), "base32"));
            require(replacementOtp != null && user.credentialManager().isValid(new UserCredentialModel(replacementOtp.getId(), OTPCredentialModel.TYPE, otp)));
            var ns = store.nativeState(user);
            if (ns != null) { ns.locked = false; ns.generation = UUID.randomUUID().toString(); ns.pinCredentialId = null; ns.pinGeneration = UUID.randomUUID().toString(); ns.pinRevokedAt = now; ns.pinHeld = true; }
            if (ns != null) ns.credentialRevision = NativePhases.credentialRevision(child, user);
            user.removeAttribute(UserModel.DISABLED_REASON); user.setEnabled(true);
            child.loginFailures().removeUserLoginFailure(store.config.realm, user.getId());
            child.sessions().getOfflineUserSessionsStream(store.config.realm, user).toList().forEach(s -> child.sessions().removeOfflineUserSession(store.config.realm, s));
            child.sessions().removeUserSessions(store.config.realm, user);
            child.users().setNotBeforeForUser(store.config.realm, user, (int) (now / 1000L));
            var state = store.state(user, false); state.epoch = UUID.randomUUID().toString(); state.failures = 0;
            var execution = new ReproofingExecutionImpl(); execution.id = auth.executionId().toString(); execution.realmId = c.realmId; execution.ceremonyId = c.id;
            execution.caseId = c.caseId; execution.authorizationId = auth.authorizationId().toString(); execution.bindingJson = c.bindingJson; execution.authorizationJson = c.authorizationJson; execution.committedAt = now; store.em.persist(execution);
            var notification = new ReproofingNotificationImpl(); notification.id = execution.id; notification.realmId = c.realmId; notification.subject = c.subject;
            String destination = open(c.id + ":email", c.notificationDestination); notification.destinationEncrypted = seal("notification:" + notification.id, destination); notification.destinationDigest = digest(destination);
            notification.createdAt = now; notification.nextAttemptAt = now; notification.status = "PENDING"; store.em.persist(notification);
            c.encryptedTotp = null; c.notificationDestination = null; c.stage = "COMPLETE"; store.evict(user); return null;
        });
        return true;
    }
    void reconcile(String id) {
        Authorization value = NativePhases.run(request, child -> {
            var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, false); var journal = journal(store, c); require(journal != null);
            if (journal.recorded || journal.recordAttempts >= 8) return null; journal.recordAttempts++; return ReproofingWireImpl.read(journal.authorizationJson, Authorization.class);
        });
        if (value == null) return;
        gateway().record(value);
        NativePhases.run(request, child -> { var store = new ReproofingStoreImpl(child); var c = store.ceremony(id, false); var journal = journal(store, c); require(journal != null && journal.id.equals(value.executionId().toString())); journal.recorded = true; return null; });
    }
    void failed(String id) { NativePhases.run(request, child -> { var store = new ReproofingStoreImpl(child); store.ceremony(id, false).failed = true; return null; }); }
    private ReproofingGatewayImpl gateway() { return new ReproofingGatewayImpl(new ReproofingConfigImpl(request.getContext().getRealm())); }
    static ReproofingExecutionImpl journal(ReproofingStoreImpl store, ReproofingCeremonyImpl c) {
        var values = store.em.createQuery("select e from ReproofingExecutionImpl e where e.ceremonyId = :id", ReproofingExecutionImpl.class).setParameter("id", c.id).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList(); require(values.size() <= 1); return values.isEmpty() ? null : values.get(0);
    }
    private static Authorization authorization(ReproofingCeremonyImpl c) { return ReproofingWireImpl.read(c.authorizationJson, Authorization.class); }
    private static void passwordPolicy(KeycloakSession child, ReproofingStoreImpl store, UserModel user, String password) { var policy = child.getProvider(PasswordPolicyManagerProvider.class); require(policy != null && policy.validate(store.config.realm, user, password) == null); }
    private static boolean otpValid(ReproofingStoreImpl store, ReproofingCeremonyImpl c, String code) {
        var policy = store.config.realm.getOTPPolicy(); require(OTPCredentialModel.TOTP.equals(policy.getType()) && !policy.isCodeReusable());
        return java.security.MessageDigest.isEqual(ReproofingCryptoImpl.totp(open(c.id, c.encryptedTotp), store.now(), policy.getPeriod(), policy.getDigits(), policy.getAlgorithm()).getBytes(java.nio.charset.StandardCharsets.US_ASCII), code.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }
    static String seal(String context, String value) { return ReproofingKeyringImpl.configured().seal(context, value); }
    static String open(String context, String value) { return ReproofingKeyringImpl.configured().open(context, value); }
}
