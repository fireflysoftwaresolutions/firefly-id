package io.firefly.id.nativeauth;

import jakarta.persistence.LockModeType;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class NativeEngine {
    static final String PASSWORD = "PASSWORD", TOTP = "TOTP", COMPLETE = "COMPLETE";
    record View(String ceremonyId, String csrf, String stage) { }
    record Prepared(String assertion, Binding binding) { }
    private final KeycloakSession request;
    NativeEngine(KeycloakSession request) { this.request = request; }
    View create() {
        String csrf = randomToken();
        return NativePhases.run(request, session -> {
            NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            NativeCeremony ceremony = new NativeCeremony(); ceremony.id = randomToken(); ceremony.realmId = session.getContext().getRealm().getId();
            ceremony.csrfDigest = digest(csrf); ceremony.stage = PASSWORD; ceremony.expiresAt = System.currentTimeMillis() + profile.ttlSeconds() * 1000L;
            new NativeStore(session).em.persist(ceremony); return new View(ceremony.id, csrf, PASSWORD);
        });
    }
    View resume(String id) {
        String csrf = randomToken();
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id);
            c.stage = resumedStage(c.stage, c.bindingJson != null, journal(store, c) != null);
            c.csrfDigest = digest(csrf); return new View(c.id, csrf, c.stage);
        });
    }
    static String resumedStage(String stage, boolean admitted, boolean committed) {
        if (committed) return COMPLETE;
        if ("PROCESSING".equals(stage)) return admitted ? TOTP : PASSWORD;
        if ("ADMITTED".equals(stage)) return TOTP;
        require(PASSWORD.equals(stage) || TOTP.equals(stage) || COMPLETE.equals(stage)); return stage;
    }
    record CompletedFactor(Reservation reservation, String attestation) { }
    CompletedFactor completedPossession(String id) {
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id);
            var user = store.local(c.subject, true); var state = store.state(c.subject, false); store.eligible(state, user);
            var proofs = store.em.createQuery("select p from NativeAttestation p where p.ceremonyId = :ceremony and p.category = 'POSSESSION' and p.verified = true and p.completed = true", NativeAttestation.class)
                    .setParameter("ceremony", c.id).getResultList();
            return proofs.stream().filter(proof -> live(proof, state)).findFirst().map(proof -> new CompletedFactor(
                    new Reservation(UUID.fromString(proof.operationId), UUID.fromString(proof.challengeId), UUID.fromString(proof.reservationId),
                            proof.providerChallengeId, proof.category, Instant.ofEpochMilli(proof.expiresAt)), proof.id)).orElse(null);
        });
    }
    View consumeCsrf(String id, String csrf, String expected) {
        String next = randomToken();
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony ceremony = store.ceremony(id);
            require(matches(csrf, ceremony.csrfDigest) && expected.equals(ceremony.stage));
            ceremony.csrfDigest = digest(next); ceremony.stage = "PROCESSING";
            return new View(ceremony.id, next, expected);
        });
    }
    /** Bootstrap charges a durable generation budget; it supplies admission, not factor evidence. */
    Prepared bootstrap(String id, String username, String password) {
        String subject = NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony ceremony = store.ceremony(id);
            try {
            UserModel found;
            try { found = KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), username.trim()); }
            catch (ModelDuplicateException ambiguous) { store.audit(null, "BOOTSTRAP_REJECTED", ceremony.id); return null; }
            if (found == null) { store.audit(null, "BOOTSTRAP_REJECTED", ceremony.id); return null; }
            UserModel user = store.local(found.getId(), true); NativeState state = store.state(user.getId(), false); store.eligible(state, user);
            require(state.bootstrapAttempts < 3); state.bootstrapAttempts++; store.audit(user.getId(), "BOOTSTRAP_RESERVED", ceremony.id);
            ceremony.subject = user.getId(); ceremony.generation = state.generation;
            return user.getId();
            } catch (NativeRefusal ineligible) { store.audit(null, "BOOTSTRAP_REJECTED", ceremony.id); return null; }
        });
        if (subject == null) { dummyPassword(password); return null; }
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony ceremony = store.ceremony(id);
            var user = store.local(subject, true); NativeState state = store.state(subject, false); store.eligible(state, user);
            require(state.generation.equals(ceremony.generation));
            if (!passwordValid(session, user, password)) { store.audit(subject, "BOOTSTRAP_REJECTED", ceremony.id); return null; }
            NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            ceremony.ownerLink = profile.link(user);
            ceremony.bindingJson = NativeActor.json(new Binding(profile.issuer(), profile.tenant(user), profile.clientId(), null,
                    subject, profile.issuer(), session.getContext().getRealm().getName(), subject, profile.population(), PURPOSE, state.generation));
            ceremony.stage = "ADMITTED"; store.audit(subject, "BOOTSTRAP_ADMITTED", ceremony.id);
            return new Prepared(NativeActor.sign(session, ceremony), NativeActor.binding(ceremony));
        });
    }
    void started(String id, Started started) {
        NativePhases.run(request, session -> {
            NativeCeremony c = new NativeStore(session).ceremony(id);
            require(started != null && started.operationId() != null && started.knowledgeChallengeId() != null && started.possessionChallengeId() != null);
            c.operationId = started.operationId().toString(); c.knowledgeChallengeId = started.knowledgeChallengeId().toString(); c.possessionChallengeId = started.possessionChallengeId().toString(); return null;
        });
    }
    Prepared prepared(String id) {
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id);
            if (c.subject == null || c.bindingJson == null) return null;
            var user = store.local(c.subject, true); NativeState state = store.state(c.subject, false); store.eligible(state, user);
            require(c.generation.equals(state.generation)); currentOwner(session, c, user); return new Prepared(NativeActor.sign(session, c), NativeActor.binding(c));
        });
    }
    Started started(String id) {
        return NativePhases.run(request, session -> {
            var c = new NativeStore(session).ceremony(id);
            require(c.operationId != null); return new Started(UUID.fromString(c.operationId), UUID.fromString(c.knowledgeChallengeId), UUID.fromString(c.possessionChallengeId));
        });
    }
    String attest(String id, Reservation reservation, String secret) {
        NativeReservationFence.Prepared prepared = NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id);
            var user = store.local(c.subject, true); var state = store.state(c.subject, false); store.eligible(state, user); currentOwner(session, c, user);
            require(reservation != null && reservation.operationId().toString().equals(c.operationId)
                    && reservation.expiresAt().isAfter(Instant.now()) && reservation.reservationId() != null
                    && reservation.providerChallengeId() != null && reservation.providerChallengeId().length() <= 512);
            boolean knowledge = "KNOWLEDGE".equals(reservation.category());
            require(knowledge || "POSSESSION".equals(reservation.category()));
            require(reservation.challengeId().toString().equals(knowledge ? c.knowledgeChallengeId : c.possessionChallengeId));
            NativeIssuedChallenge issued = store.em.find(NativeIssuedChallenge.class, reservation.providerChallengeId());
            require(issued != null && issued.ceremonyId.equals(c.id) && issued.operationId.equals(c.operationId)
                    && issued.category.equals(reservation.category()) && issued.expiresAt > System.currentTimeMillis());
            CredentialModel credential = knowledge ? password(user) : enrolledTotp(user, state);
            require(credential.getId().equals(issued.credentialId));
            var existing = store.em.createQuery("select p from NativeAttestation p where p.reservationId = :reservation", NativeAttestation.class)
                    .setParameter("reservation", reservation.reservationId().toString()).getResultList();
            require(existing.size() <= 1);
            if (!existing.isEmpty()) return NativeReservationFence.reuse(existing.get(0), c, state, reservation, credential.getId());
            if (knowledge) { require(state.knowledgeAttempts < 3); state.knowledgeAttempts++; }
            else { require(state.possessionAttempts < 3); state.possessionAttempts++; }
            NativeAttestation proof = new NativeAttestation(); proof.id = randomToken(); proof.realmId = c.realmId; proof.subject = c.subject;
            proof.generation = state.generation; proof.credentialRevision = state.credentialRevision; proof.ceremonyId = c.id;
            proof.operationId = reservation.operationId().toString(); proof.challengeId = reservation.challengeId().toString();
            proof.reservationId = reservation.reservationId().toString(); proof.providerChallengeId = reservation.providerChallengeId();
            proof.category = reservation.category(); proof.credentialId = credential.getId();
            proof.expiresAt = Math.min(c.expiresAt, reservation.expiresAt().toEpochMilli()); store.em.persist(proof);
            store.audit(c.subject, "NATIVE_FACTOR_RESERVED", proof.id); return new NativeReservationFence.Prepared(proof.id, true);
        });
        if (!prepared.verify()) return prepared.attestationId();
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeAttestation proof = store.em.find(NativeAttestation.class, prepared.attestationId(), LockModeType.PESSIMISTIC_WRITE);
            var user = store.local(proof.subject, true); var state = store.state(proof.subject, false); store.eligible(state, user);
            require(!proof.completed && !proof.verified && proof.expiresAt > System.currentTimeMillis() && proof.generation.equals(state.generation)
                    && proof.credentialRevision.equals(store.revision(user)));
            boolean valid;
            try { valid = "KNOWLEDGE".equals(proof.category) ? passwordValid(session, user, secret)
                    : NativeCredentials.totp(session, user, proof.credentialId, secret); }
            catch (Exception verifierUnavailable) { valid = false; }
            proof.verified = valid; proof.completed = true; store.audit(user.getId(), valid ? "NATIVE_FACTOR_ACCEPTED" : "NATIVE_FACTOR_REJECTED", proof.id);
            return proof.id;
        });
    }
    View stage(String id, String next, String csrf) {
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); var c = store.ceremony(id);
            c.stage = journal(store, c) == null ? next : COMPLETE; return new View(c.id, csrf, c.stage);
        });
    }
    boolean recordPending(String id) {
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id); NativeExecution journal = journal(store, c);
            if (journal == null) return false;
            journal.authorization(c);
            return !journal.recorded && journal.recordAttempts < 3 && c.expiresAt / 1000 > System.currentTimeMillis() / 1000;
        });
    }
    private record PendingRecord(String assertion, Authorization authorization, String outcome) { }
    boolean reconcile(String id, NativeCeremonyGateway gateway) {
        PendingRecord pending = NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id); NativeExecution journal = journal(store, c);
            require(journal != null); Authorization authorization = journal.authorization(c);
            if (!journal.reserveRecording(c, System.currentTimeMillis())) return null;
            store.audit(c.subject, "NATIVE_EXECUTION_RECORD_RESERVED", journal.id);
            return new PendingRecord(NativeActor.sign(session, c), authorization, journal.outcome);
        });
        if (pending == null) return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id); NativeExecution journal = journal(store, c);
            require(journal != null); journal.authorization(c); return journal.recorded;
        });
        // This is the only external operation: the authorization is already committed and must never be consumed again.
        gateway.recordExecution(pending.assertion(), pending.authorization(), pending.outcome());
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.em.find(NativeCeremony.class, id, LockModeType.PESSIMISTIC_WRITE);
            require(c != null && c.realmId.equals(session.getContext().getRealm().getId()));
            NativeExecution journal = journal(store, c); require(journal != null); journal.requireAuthorization(c, pending.authorization());
            if (!journal.recorded) { journal.recorded = true; store.audit(c.subject, "NATIVE_EXECUTION_RECORDED", journal.id); }
            c.stage = COMPLETE; return true;
        });
    }
    private static NativeExecution journal(NativeStore store, NativeCeremony ceremony) {
        var journals = store.em.createQuery("select e from NativeExecution e where e.ceremonyId = :ceremony", NativeExecution.class)
                .setParameter("ceremony", ceremony.id).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
        require(journals.size() <= 1); return journals.isEmpty() ? null : journals.get(0);
    }
    Execution execute(String id, Authorization authorization) {
        return NativePhases.run(request, session -> {
            NativeStore store = new NativeStore(session); NativeCeremony c = store.ceremony(id);
            require(authorization != null && authorization.binding().equals(NativeActor.binding(c)) && authorization.operationId().toString().equals(c.operationId));
            var user = store.local(c.subject, true); var state = store.state(c.subject, false);
            NativeExecution existing = store.em.find(NativeExecution.class, authorization.executionId().toString(), LockModeType.PESSIMISTIC_WRITE);
            if (existing != null) { existing.requireAuthorization(c, authorization); return new Execution(authorization.binding(), authorization.executionId(), existing.outcome); }
            store.eligible(state, user); currentOwner(session, c, user); require(state.generation.equals(c.generation) && authorization.expiresAt().isAfter(Instant.now()));
            var proofs = store.em.createQuery("select p from NativeAttestation p where p.ceremonyId = :ceremony and p.operationId = :operation and p.verified = true", NativeAttestation.class)
                    .setParameter("ceremony", c.id).setParameter("operation", c.operationId).getResultList();
            require(proofs.stream().anyMatch(p -> "KNOWLEDGE".equals(p.category) && live(p, state))
                    && proofs.stream().anyMatch(p -> "POSSESSION".equals(p.category) && live(p, state)));
            session.sessions().getOfflineUserSessionsStream(session.getContext().getRealm(), user).toList()
                    .forEach(s -> session.sessions().removeOfflineUserSession(session.getContext().getRealm(), s));
            session.sessions().removeUserSessions(session.getContext().getRealm(), user);
            session.users().setNotBeforeForUser(session.getContext().getRealm(), user, org.keycloak.common.util.Time.currentTime());
            session.loginFailures().removeUserLoginFailure(session.getContext().getRealm(), user.getId());
            user.removeAttribute(UserModel.DISABLED_REASON); user.setEnabled(true); state.locked = false; store.invalidateCache(user);
            NativeExecution journal = NativeExecution.committed(c, authorization, "SUCCEEDED", System.currentTimeMillis()); store.em.persist(journal);
            store.audit(c.subject, "NATIVE_UNLOCK_COMMITTED", journal.id); c.stage = COMPLETE;
            return new Execution(authorization.binding(), authorization.executionId(), "SUCCEEDED");
        });
    }
    static void currentOwner(KeycloakSession session, NativeCeremony ceremony, UserModel user) {
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm()); Binding binding = NativeActor.binding(ceremony);
        require(profile.tenant(user).equals(binding.tenant()) && profile.link(user).equals(ceremony.ownerLink));
    }
    private static boolean live(NativeAttestation proof, NativeState state) { return proof.expiresAt > System.currentTimeMillis() && proof.generation.equals(state.generation) && proof.credentialRevision.equals(state.credentialRevision); }
    static CredentialModel password(UserModel user) { return user.credentialManager().getStoredCredentialsByTypeStream("password").findFirst().orElseThrow(NativeRefusal::new); }
    static CredentialModel enrolledTotp(UserModel user, NativeState state) {
        return user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).filter(c -> {
            var otp = OTPCredentialModel.createFromCredentialModel(c);
            return OTPCredentialModel.TOTP.equals(otp.getOTPCredentialData().getSubType()) && c.getCreatedDate() != null && c.getCreatedDate() <= state.lockedAt;
        }).findFirst().orElseThrow(NativeRefusal::new);
    }
    static boolean passwordValid(KeycloakSession session, UserModel user, String supplied) {
        require(supplied != null && supplied.length() <= 1024);
        var credential = PasswordCredentialModel.createFromCredentialModel(password(user));
        PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class, credential.getPasswordCredentialData().getAlgorithm());
        require(hash != null);
        // Native hash verification intentionally avoids the ordinary provider's deferred credential rehash.
        return hash.verify(supplied, credential);
    }
    private void dummyPassword(String supplied) {
        NativePhases.run(request, session -> { PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class, "argon2"); require(hash != null); hash.encodedCredential(supplied == null ? "" : supplied, 5); return null; });
    }
}
