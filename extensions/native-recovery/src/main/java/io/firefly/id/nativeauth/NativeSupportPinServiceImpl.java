package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import java.time.Instant;
import java.util.ServiceLoader;
import static io.firefly.id.nativeauth.NativeSecurity.*;

/** Native-only entry point. It has no public HTTP route until the real support owner is qualified. */
public final class NativeSupportPinServiceImpl {
    public record VerificationReference(String reference, Instant expiresAt) {
        @Override public String toString() { return "SupportVerificationReference[REDACTED]"; }
    }
    private final KeycloakSession request;
    public NativeSupportPinServiceImpl(KeycloakSession request) { this.request = request; }
    public VerificationReference verify(String signedSupportContext, String pin) {
        requirePin(pin); require(signedSupportContext != null && signedSupportContext.length() <= 16384);
        var factories = ServiceLoader.load(NativeSupportAuthorization.Factory.class, getClass().getClassLoader()).stream()
                .map(ServiceLoader.Provider::get).filter(NativeSupportAuthorization.Factory::isQualified).toList();
        require(factories.size() == 1);
        // Support owner admission may call other services; it runs before any native row lock.
        if (request.getTransactionManager().isActive()) { require(!request.getTransactionManager().getRollbackOnly()); request.getTransactionManager().commit(); }
        var authority = factories.get(0).create(request); require(authority != null);
        NativeSupportAuthorization.Grant grant = authority.authorize(signedSupportContext);
        require(grant != null && "TELEPHONE_SUPPORT_KNOWLEDGE".equals(grant.purpose()) && grant.expiresAt() != null
                && grant.expiresAt().isAfter(Instant.now()) && grant.expiresAt().isBefore(Instant.now().plusSeconds(121))
                && grant.nonce() != null && grant.staffIssuer() != null && grant.staffSubject() != null
                && grant.caseId() != null && grant.callId() != null && grant.permittedAction() != null);
        String proofId = NativePhases.run(request, session -> {
            NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            require("HUMAN".equals(profile.population()) && profile.issuer().equals(grant.targetIssuer()) && session.getContext().getRealm().getName().equals(grant.realm()));
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(grant.subject(), true); store.requireSelfService(user); var state = store.state(grant.subject(), false);
            require(user.isEnabled() && profile.tenant(user).equals(grant.tenant()) && profile.link(user).equals(grant.customerLink())
                    && !state.locked && !state.hold && !state.pinHeld && state.pinCredentialId != null && state.pinFailures + state.pinReserved < 3 && state.pinRevokedAt == 0);
            NativeSupportProof proof = new NativeSupportProof(); proof.id = randomToken(); proof.grantDigest = digest(NativeActor.json(grant));
            proof.realmId = session.getContext().getRealm().getId(); proof.subject = user.getId(); proof.pinGeneration = state.pinGeneration;
            proof.expiresAt = grant.expiresAt().toEpochMilli(); store.em.persist(proof); state.pinReserved++;
            store.audit(user.getId(), "SUPPORT_PIN_RESERVED", proof.id); return proof.id;
        });
        require(grant.equals(authority.authorize(signedSupportContext)));
        boolean valid = NativePhases.run(request, session -> {
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(grant.subject(), true); store.requireSelfService(user); var state = store.state(grant.subject(), false);
            var proof = store.em.find(NativeSupportProof.class, proofId);
            NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            require(user.isEnabled() && !state.locked && !state.hold && profile.tenant(user).equals(grant.tenant())
                    && profile.link(user).equals(grant.customerLink()) && grant.expiresAt().isAfter(Instant.now()));
            require(proof != null && !proof.verified && proof.expiresAt > System.currentTimeMillis() && state.pinGeneration.equals(proof.pinGeneration)
                    && !state.pinHeld && state.pinFailures < 3 && state.pinReserved > 0 && state.pinCredentialId != null && state.pinRevokedAt == 0);
            String keyed = NativePinProtection.keyed(proof.realmId, proof.subject, pin, state.pinKeyVersion);
            var stored = user.credentialManager().getStoredCredentialById(state.pinCredentialId); require(stored != null);
            var credential = PasswordCredentialModel.createFromCredentialModel(stored);
            PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class, "argon2"); require(hash != null);
            boolean accepted = hash.verify(keyed, credential); proof.verified = accepted; state.pinReserved--;
            if (!accepted) { state.pinFailures++; if (state.pinFailures == 3) state.pinHeld = true; }
            store.audit(user.getId(), accepted ? "SUPPORT_PIN_ACCEPTED" : "SUPPORT_PIN_REFUSED", proof.id); return accepted;
        });
        require(valid); return new VerificationReference(proofId, grant.expiresAt());
    }
}
