package io.firefly.id.nativeauth;

import jakarta.persistence.LockModeType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import java.time.Instant;
import java.util.ServiceLoader;
import static io.firefly.id.nativeauth.NativeSecurityImpl.*;

/** Native-only entry point. It has no public HTTP route until the real support owner is qualified. */
public final class NativeSupportPinServiceImpl {
    public record VerificationReference(String reference, Instant expiresAt) {
        @Override public String toString() { return "SupportVerificationReference[REDACTED]"; }
    }
    private final KeycloakSession request;
    public NativeSupportPinServiceImpl(KeycloakSession request) { this.request = request; }
    NativeSupportAuthorization authority(String signedSupportContext) {
        require(signedSupportContext != null && !signedSupportContext.isBlank() && signedSupportContext.length() <= 16384);
        // External owner loading and current-authorization checks never run under native row locks.
        if (request.getTransactionManager().isActive()) { require(!request.getTransactionManager().getRollbackOnly()); request.getTransactionManager().commit(); }
        var factories = ServiceLoader.load(NativeSupportAuthorization.Factory.class, getClass().getClassLoader()).stream()
                .map(ServiceLoader.Provider::get).filter(NativeSupportAuthorization.Factory::isQualified).toList();
        require(factories.size() == 1);
        var authority = factories.get(0).create(request); require(authority != null); return authority;
    }
    private static NativeProfile validate(KeycloakSession session, NativeSupportAuthorization.Grant grant, Instant now) {
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm()); require("HUMAN".equals(profile.population()));
        NativeSupportEvidenceImpl.validate(grant, profile.issuer(), session.getContext().getRealm().getName(), now); return profile;
    }
    private static PasswordCredentialModel credential(UserModel user, NativeState state) {
        var stored = user.credentialManager().getStoredCredentialById(state.pinCredentialId);
        require(stored != null && "firefly-support-pin".equals(stored.getType()));
        var credential = PasswordCredentialModel.createFromCredentialModel(stored);
        require("argon2".equals(credential.getPasswordCredentialData().getAlgorithm())); return credential;
    }
    public VerificationReference verify(String signedSupportContext, String pin) {
        requirePin(pin);
        var authority = authority(signedSupportContext);
        NativeSupportAuthorization.Grant grant = authority.authorize(signedSupportContext);
        String proofId = NativePhasesImpl.run(request, session -> {
            Instant now = Instant.now(); NativeProfile profile = validate(session, grant, now);
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(grant.subject(), true); store.requireSelfService(user);
            var state = store.state(grant.subject(), false);
            require(user.isEnabled() && profile.tenant(user).equals(grant.tenant()) && profile.link(user).equals(grant.customerLink()));
            NativeSupportEvidenceImpl.requireActive(state); credential(user, state);
            var proof = NativeSupportEvidenceImpl.reserve(grant, session.getContext().getRealm().getId(), state, Instant.now());
            // The database uniqueness constraint fences same-nonce races even across different customers.
            store.em.persist(proof); store.em.flush();
            store.auditSupport(proof, "SUPPORT_PIN_RESERVED"); return proof.id;
        });
        require(grant.equals(authority.authorize(signedSupportContext)));
        boolean valid = NativePhasesImpl.run(request, session -> {
            Instant now = Instant.now(); NativeProfile profile = validate(session, grant, now);
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(grant.subject(), true); store.requireSelfService(user);
            var state = store.state(grant.subject(), false);
            var proof = store.em.find(NativeSupportProof.class, proofId, LockModeType.PESSIMISTIC_WRITE);
            NativeSupportEvidenceImpl.requireLive(proof, grant, session.getContext().getRealm().getId(), state,
                    user.isEnabled(), profile.tenant(user), profile.link(user), Instant.now());
            require("RESERVED".equals(proof.status) && state.pinReserved > 0);
            String keyed = NativePinProtectionImpl.keyed(proof.realmId, proof.subject, pin, state.pinKeyVersion);
            var credential = credential(user, state);
            PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class, "argon2"); require(hash != null);
            boolean accepted = hash.verify(keyed, credential);
            require(grant.expiresAt().isAfter(Instant.now()));
            NativeSupportEvidenceImpl.complete(proof, state, accepted);
            store.auditSupport(proof, accepted ? "SUPPORT_PIN_ACCEPTED" : "SUPPORT_PIN_REFUSED"); return accepted;
        });
        require(valid); return new VerificationReference(proofId, grant.expiresAt());
    }
    /** Consumes knowledge evidence only; it never authorizes a customer token or business operation. */
    public void consume(String signedSupportContext, String reference) {
        require(reference != null && !reference.isBlank() && reference.length() <= 128);
        var grant = authority(signedSupportContext).authorize(signedSupportContext);
        NativePhasesImpl.run(request, session -> {
            Instant now = Instant.now(); NativeProfile profile = validate(session, grant, now);
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(grant.subject(), true); store.requireSelfService(user);
            var state = store.state(grant.subject(), false);
            var proof = store.em.find(NativeSupportProof.class, reference, LockModeType.PESSIMISTIC_WRITE);
            NativeSupportEvidenceImpl.requireActive(state); credential(user, state);
            NativeSupportEvidenceImpl.consume(proof, grant, session.getContext().getRealm().getId(), state,
                    user.isEnabled(), profile.tenant(user), profile.link(user), Instant.now());
            store.auditSupport(proof, "SUPPORT_PIN_CONSUMED"); return null;
        });
    }
}
