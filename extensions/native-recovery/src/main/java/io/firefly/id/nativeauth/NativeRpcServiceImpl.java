package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import java.time.Instant;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class NativeRpcServiceImpl {
    private final KeycloakSession request;
    NativeRpcServiceImpl(KeycloakSession request) { this.request = request; }
    Object call(String route, Rpc rpc) {
        require(rpc != null && (rpc.actorAssertion() == null || rpc.actorAssertion().length() <= 16384)
                && (rpc.action() == null || rpc.action().length() <= 64) && (rpc.attestation() == null || rpc.attestation().length() <= 128));
        String header = request.getContext().getRequestHeaders().getHeaderString("Authorization");
        require("https".equals(request.getContext().getUri().getBaseUri().getScheme()));
        Object committed = NativePhases.run(request, session -> {
            NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            workload(session, profile, header, route);
            if ("audit".equals(route)) {
                require(Set.of("DOMAIN_BOUNDARY_ADMITTED", "DOMAIN_BOUNDARY_REFUSED").contains(rpc.action()));
                NativeStoreImpl auditStore = new NativeStoreImpl(session); String subject = null; String reference = null;
                String event = "DOMAIN_BOUNDARY_REFUSED";
                try {
                    var token = session.tokens().decode(rpc.actorAssertion(), org.keycloak.representations.AccessToken.class);
                    if (token != null && token.getOtherClaims().get("recovery_ceremony_id") instanceof String id) {
                        var known = auditStore.ceremony(id);
                        NativeActor.verify(session, rpc.actorAssertion(), NativeActor.binding(known));
                        subject = digest(known.subject); reference = digest(known.id); event = rpc.action();
                    }
                } catch (Exception invalid) { /* Unknown actors receive a durable anonymous refusal. */ }
                NativeAudit audit = new NativeAudit(); audit.id = UUID.randomUUID().toString(); audit.realmId = session.getContext().getRealm().getId();
                audit.subject = subject; audit.referenceId = reference; audit.eventType = event; audit.occurredAt = System.currentTimeMillis(); auditStore.em.persist(audit);
                return new AuditReceipt(UUID.fromString(audit.id), Instant.ofEpochMilli(audit.occurredAt));
            }
            require(rpc.binding() != null);
            boolean domain = "DOMAIN_".equals(rpc.action() == null ? "" : rpc.action().substring(0, Math.min(7, rpc.action().length())));
            String action = domain ? rpc.action().substring(7) : rpc.action();
            String workloadId = basicClientId(header);
            require(domain == workloadId.equals(profile.domainWorkloadClientId()) || !"admit".equals(route));
            NativeCeremony ceremony = NativeActor.verify(session, rpc.actorAssertion(), rpc.binding());
            NativeStoreImpl store = new NativeStoreImpl(session); var user = store.local(ceremony.subject, true);
            NativeState state = store.state(ceremony.subject, false);
            boolean recording = "RECORD_EXECUTION".equals(action);
            if (recording) require(hasJournal(store, ceremony, rpc.binding(), domain ? rpc.operationId() : null, domain));
            else { store.eligible(state, user); NativeEngineImpl.currentOwner(session, ceremony, user); require(state.generation.equals(ceremony.generation)); }
            return switch (route) {
                case "admit" -> {
                    require((domain ? Set.of("CREATE", "ISSUE_CHALLENGE", "RESERVE_VERIFICATION", "COMPLETE_VERIFICATION", "CONSUME", "VERIFY_AUTHORIZATION", "RECORD_EXECUTION") : Set.of("CREATE", "ISSUE_CHALLENGE", "VERIFY_CHALLENGE", "RESERVE_VERIFICATION", "COMPLETE_VERIFICATION", "CONSUME", "VERIFY_AUTHORIZATION", "RECORD_EXECUTION")).contains(action));
                    yield new Admission(rpc.binding(), ceremony.ownerLink,
                            "native-link:" + digest(ceremony.realmId + ":" + ceremony.subject + ":" + ceremony.ownerLink),
                            ceremony.generation, Instant.ofEpochMilli(ceremony.expiresAt), rpc.action());
                }
                case "issue" -> {
                    require(!recording && rpc.operationId() != null && rpc.reservationId() != null
                            && Set.of("KNOWLEDGE", "POSSESSION").contains(rpc.category()));
                    var existing = store.em.createQuery("select i from NativeIssuedChallenge i where i.reservationId = :reservation", NativeIssuedChallenge.class)
                            .setParameter("reservation", rpc.reservationId().toString()).getResultList();
                    NativeIssuedChallenge issued;
                    var credential = "KNOWLEDGE".equals(rpc.category()) ? NativeEngineImpl.password(user) : NativeEngineImpl.enrolledTotp(user, state);
                    if (!existing.isEmpty()) {
                        issued = existing.get(0); require(issued.ceremonyId.equals(ceremony.id) && issued.operationId.equals(rpc.operationId().toString()) && issued.category.equals(rpc.category()) && issued.credentialId.equals(credential.getId()));
                    } else {
                        issued = new NativeIssuedChallenge(); issued.id = randomToken(); issued.ceremonyId = ceremony.id;
                        issued.operationId = rpc.operationId().toString(); issued.reservationId = rpc.reservationId().toString();
                        issued.category = rpc.category(); issued.credentialId = credential.getId(); issued.expiresAt = ceremony.expiresAt;
                        store.em.persist(issued); store.audit(ceremony.subject, "NATIVE_CHALLENGE_ISSUED", issued.id);
                    }
                    require(issued.expiresAt > System.currentTimeMillis());
                    yield new Issued(rpc.operationId(), rpc.reservationId(), rpc.binding(), issued.category, PROVIDER,
                            issued.credentialId, independence(ceremony, issued.category, issued.credentialId), issued.id,
                            Instant.ofEpochMilli(issued.expiresAt), null);
                }
                case "verify" -> {
                    require(!recording && rpc.attestation() != null && rpc.attestation().length() <= 128);
                    var proof = store.em.find(NativeAttestation.class, rpc.attestation());
                    require(proof != null && proof.completed && proof.expiresAt > System.currentTimeMillis()
                            && ceremony.id.equals(proof.ceremonyId) && ceremony.generation.equals(proof.generation)
                            && state.credentialRevision.equals(proof.credentialRevision)
                            && proof.operationId.equals(rpc.operationId().toString()) && proof.challengeId.equals(rpc.challengeId().toString())
                            && proof.reservationId.equals(rpc.reservationId().toString()) && proof.providerChallengeId.equals(rpc.providerChallengeId())
                            && proof.category.equals(rpc.category()));
                    yield new Proof(rpc.operationId(), rpc.challengeId(), rpc.reservationId(), rpc.binding(), proof.category,
                            PROVIDER, proof.credentialId, independence(ceremony, proof.category, proof.credentialId), proof.providerChallengeId,
                            proof.verified, proof.id, Instant.ofEpochMilli(proof.expiresAt));
                }
                case "journal" -> {
                    require(recording && rpc.executionId() != null);
                    var journal = store.em.find(NativeExecution.class, rpc.executionId().toString());
                    require(journal != null && journal.subject.equals(ceremony.subject) && journal.realmId.equals(ceremony.realmId)
                            && journal.generation.equals(ceremony.generation) && (!domain || rpc.operationId() != null && journal.operationId.equals(rpc.operationId().toString())) && journal.bindingDigest.equals(digest(NativeActor.json(rpc.binding()))));
                    yield new Execution(rpc.binding(), rpc.executionId(), journal.outcome);
                }
                case "reject" -> {
                    UUID auditId = UUID.randomUUID(); NativeAudit audit = new NativeAudit(); audit.id = auditId.toString();
                    audit.realmId = ceremony.realmId; audit.subject = ceremony.subject; audit.eventType = "BOUNDARY_REJECTED";
                    audit.referenceId = ceremony.id; audit.occurredAt = System.currentTimeMillis(); store.em.persist(audit);
                    yield new AuditReceipt(auditId, Instant.ofEpochMilli(audit.occurredAt));
                }
                default -> throw new NativeRefusal();
            };
        });
        return committed instanceof AuditReceipt audit ? new AuditReceipt(audit.auditId(), Instant.now()) : committed;
    }
    private static String basicClientId(String header) {
        try { String value = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8); return value.substring(0, value.indexOf(':')); }
        catch (Exception error) { throw new NativeRefusal(); }
    }
    private static boolean hasJournal(NativeStoreImpl store, NativeCeremony ceremony, Binding binding, UUID operationId, boolean exactOperation) {
        if (exactOperation) require(operationId != null);
        return store.em.createQuery("select e from NativeExecution e where e.realmId = :realm and e.subject = :subject and e.generation = :generation and e.bindingDigest = :binding", NativeExecution.class)
                .setParameter("realm", ceremony.realmId).setParameter("subject", ceremony.subject).setParameter("generation", ceremony.generation)
                .setParameter("binding", digest(NativeActor.json(binding))).getResultList().stream()
                .anyMatch(journal -> !exactOperation || journal.operationId.equals(operationId.toString()));
    }
    private static String independence(NativeCeremony ceremony, String category, String credential) {
        return "native:" + digest(ceremony.realmId + ":" + ceremony.subject + ":" + category + ":" + credential);
    }
    private static void workload(KeycloakSession session, NativeProfile profile, String header, String route) {
        require(header != null && header.startsWith("Basic ") && header.length() <= 4096);
        String decoded;
        try { decoded = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8); } catch (Exception error) { throw new NativeRefusal(); }
        int colon = decoded.indexOf(':'); require(colon > 0);
        String clientId = decoded.substring(0, colon), secret = decoded.substring(colon + 1);
        require((clientId.equals(profile.coreWorkloadClientId()) && Set.of("admit", "issue", "verify", "journal", "reject").contains(route)) || (clientId.equals(profile.domainWorkloadClientId()) && Set.of("admit", "journal", "audit").contains(route)));
        var client = session.clients().getClientByClientId(session.getContext().getRealm(), clientId);
        require(client != null && client.isEnabled() && !client.isPublicClient() && !client.isStandardFlowEnabled()
                && !client.isDirectAccessGrantsEnabled() && !client.isServiceAccountsEnabled() && client.validateSecret(secret));
    }
}
