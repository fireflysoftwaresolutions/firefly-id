package io.firefly.id.nativeauth;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.credential.hash.PasswordHashProvider;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import static io.firefly.id.nativeauth.SupportQualificationOwner.*;

/** Fixed synthetic operations only: no arbitrary user, grant, PIN, SQL, URL or reference input. */
public final class SupportQualificationResource {
    private static final org.jboss.logging.Logger LOG = org.jboss.logging.Logger.getLogger(SupportQualificationResource.class);
    private final KeycloakSession request;
    private final KeycloakSessionFactory factory;
    private final Map<String, String> pins = new HashMap<>();
    private String stage = "ADMISSION";
    public SupportQualificationResource(KeycloakSession request) { this.request = request; this.factory = request.getKeycloakSessionFactory(); }
    @POST @Path("{operation}") @Produces(MediaType.APPLICATION_JSON)
    public Response execute(@HeaderParam("X-Fixture-Secret") String supplied, @PathParam("operation") String operation) {
        if (!admitted() || supplied == null || !MessageDigest.isEqual(supplied.getBytes(StandardCharsets.UTF_8),
                System.getenv("FIREFLY_SUPPORT_QUALIFICATION_SECRET").getBytes(StandardCharsets.UTF_8))
                || !"master".equals(request.getContext().getRealm().getName())) return Response.status(404).build();
        try {
            if (request.getTransactionManager().isActive()) request.getTransactionManager().commit();
            boolean historical = "historical".equals(System.getenv("FIREFLY_SUPPORT_QUALIFICATION_PHASE"));
            check(historical == "setup".equals(operation));
            stage = "OPERATION_DISPATCH";
            Map<String, Object> result = switch (operation) {
                case "setup" -> setup();
                case "admission" -> admission();
                case "legacy" -> legacy();
                case "nonce" -> nonce();
                case "budget" -> budget(false);
                case "interrupted" -> budget(true);
                case "consume" -> consumption();
                case "audit" -> audit();
                case "generation" -> invalidate(false);
                case "hold" -> invalidate(true);
                case "lost" -> lost();
                case "reconcile" -> reconcile();
                default -> throw new NativeRefusal();
            };
            return Response.ok(result).build();
        } catch (Exception failure) {
            LOG.error("Owned qualification failure at " + stage, failure);
            return Response.status(500).entity(Map.of("result", "failed", "stage", stage,
                    "sqlstates", sqlStates(failure), "source_frames", sourceFrames(failure))).build();
        }
    }
    private static List<Throwable> causes(Throwable failure) {
        var result = new ArrayList<Throwable>(); var queue = new ArrayDeque<Throwable>();
        var seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>()); queue.add(failure);
        while (!queue.isEmpty() && result.size() < 32) {
            var current = queue.removeFirst(); if (!seen.add(current)) continue; result.add(current);
            if (current.getCause() != null) queue.add(current.getCause());
            if (current instanceof java.sql.SQLException sql && sql.getNextException() != null) queue.add(sql.getNextException());
        }
        return result;
    }
    private static List<String> sqlStates(Throwable failure) {
        var states = new LinkedHashSet<String>();
        for (var cause : causes(failure)) if (cause instanceof java.sql.SQLException sql) {
            String state = sql.getSQLState();
            if (state != null && Set.of("FQ001", "23505", "23502", "23514", "42501", "42P01", "42703", "42601", "55P03", "57014").contains(state)) states.add(state);
        }
        return states.stream().limit(8).toList();
    }
    private static List<String> sourceFrames(Throwable failure) {
        var frames = new LinkedHashSet<String>();
        for (var cause : causes(failure)) for (var frame : cause.getStackTrace()) {
            if (frame.getClassName().matches("io\\.firefly\\.id\\.nativeauth\\.(Native|SupportQualification)[A-Za-z0-9_$]+")
                    && frame.getFileName() != null && frame.getFileName().matches("(Native|SupportQualification)[A-Za-z0-9_$]+\\.java")
                    && frame.getLineNumber() > 0 && frame.getMethodName().matches("[A-Za-z0-9_$<>]+")) frames.add(frame.toString());
        }
        return frames.stream().limit(8).toList();
    }
    private <T> T tx(Function<KeycloakSession, T> action) {
        return KeycloakModelUtils.runJobInTransactionWithResult(factory, session -> {
            RealmModel realm = session.realms().getRealmByName(REALM); check(realm != null);
            session.getContext().setRealm(realm); return action.apply(session);
        });
    }
    private <T> T service(Function<NativeSupportPinServiceImpl, T> action) {
        try (KeycloakSession session = factory.create()) {
            session.getTransactionManager().begin();
            session.getContext().setRealm(session.realms().getRealmByName(REALM));
            try { return action.apply(new NativeSupportPinServiceImpl(session)); }
            finally { if (session.getTransactionManager().isActive()) session.getTransactionManager().rollback(); }
        }
    }
    private Map<String, Object> passed(String scenario) { return Map.of("result", "passed", "scenario", scenario); }
    private Map<String, Object> setup() {
        stage = "SETUP_REALM_AND_HISTORICAL_ROWS";
        KeycloakModelUtils.runJobInTransactionWithResult(factory, session -> {
            check(session.realms().getRealmByName(REALM) == null);
            var realm = session.realms().createRealm(REALM, REALM); realm.setEnabled(true);
            var defaultRole = session.roles().addRealmRole(realm, "default-roles-" + REALM);
            realm.setDefaultRole(defaultRole);
            Map<String, String> attributes = Map.ofEntries(Map.entry("population", "HUMAN"), Map.entry("issuer", "https://fixture.invalid/realms/" + REALM),
                    Map.entry("allowed-origin", "https://fixture.invalid"), Map.entry("ttl-seconds", "120"), Map.entry("client-id", "fixture-self"),
                    Map.entry("tenant-attribute", "fixture-tenant"), Map.entry("link-attribute", "fixture-link"), Map.entry("domain-audience", "fixture-domain"),
                    Map.entry("core-audience", "fixture-core"), Map.entry("core-workload-client-id", "fixture-core-workload"), Map.entry("domain-workload-client-id", "fixture-domain-workload"));
            attributes.forEach((key, value) -> realm.setAttribute("firefly.native-recovery." + key, value));
            session.getContext().setRealm(realm); createUser(session, "historical-user");
            String legacySubject = createUser(session, "legacy-consume");
            var legacyUser = session.users().getUserById(realm, legacySubject);
            var legacyState = new NativeStoreImpl(session).state(legacySubject, false);
            Instant legacyExpiry = Instant.ofEpochMilli(System.currentTimeMillis() + 115000);
            legacyUser.setSingleAttribute("fixture-legacy-expires", legacyExpiry.toString());
            var legacyGrant = new NativeSupportAuthorization.Grant("legacy", "https://fixture.invalid/realms/" + REALM, REALM, legacySubject,
                    "synthetic-tenant", legacyUser.getFirstAttribute("fixture-link"), "https://workforce.invalid/realms/staff", "synthetic-operator",
                    "synthetic-case", "synthetic-call", "VERIFY_SUPPORT_PIN", "TELEPHONE_SUPPORT_KNOWLEDGE", legacyExpiry);
            stage = "SEED_HISTORICAL_PROOF_ORIGINAL_COLUMNS";
            // Historical entity lacks the additive columns; use only the historical column contract here.
            new NativeStoreImpl(session).em.createNativeQuery("INSERT INTO ff_native_support_proof (id,grant_digest,realm_id,subject,pin_generation,expires_at,verified) VALUES ('retained-proof',:grant,:realm,:subject,:generation,:expiry,true)")
                    .setParameter("grant", NativeSupportEvidenceImpl.grantDigest(legacyGrant)).setParameter("realm", realm.getId())
                    .setParameter("subject", legacySubject).setParameter("generation", legacyState.pinGeneration).setParameter("expiry", legacyExpiry.toEpochMilli()).executeUpdate();
            var user = session.users().getUserByUsername(realm, "historical-user"); var state = new NativeStoreImpl(session).state(user.getId(), false);
            state.locked = true; state.hold = true; state.pinHeld = true; state.pinFailures = 1; state.pinReserved = 1;
            state.bootstrapAttempts = 1; state.knowledgeAttempts = 2; state.possessionAttempts = 2; state.lockedAt = 123;
            state.generation = "historical-lock-generation"; state.credentialRevision = "historical-revision"; return null;
        });
        stage = "HISTORICAL_FRESH_SESSION_REALM_CACHE_READBACK";
        // The first independent read populates the realm cache; the second checks the cached model.
        for (int readback = 0; readback < 2; readback++) tx(session -> {
            var realm = session.getContext().getRealm(); var defaultRole = realm.getDefaultRole();
            check(defaultRole != null && ("default-roles-" + REALM).equals(defaultRole.getName())
                    && !defaultRole.isClientRole() && defaultRole.getCompositesStream().findAny().isEmpty());
            for (String name : List.of("historical-user", "legacy-consume")) {
                var user = session.users().getUserByUsername(realm, name);
                check(user != null && user.getRoleMappingsStream().findAny().isEmpty());
            }
            return null;
        });
        return Map.of("result", "passed", "scenario", "historical-synthetic-user-and-pin-state",
                "fresh_session_readbacks", 2, "empty_default_role", true, "synthetic_user_role_mappings", 0);
    }
    private String createUser(KeycloakSession session, String name) {
        stage = "CREATE_SYNTHETIC_USER_AND_PIN";
        var realm = session.getContext().getRealm(); check(session.users().getUserByUsername(realm, name) == null);
        var user = session.users().addUser(realm, UUID.randomUUID().toString(), name, false, false); user.setEnabled(true);
        user.setSingleAttribute("fixture-tenant", "synthetic-tenant"); user.setSingleAttribute("fixture-link", UUID.randomUUID().toString());
        String pin;
        do { pin = String.format(Locale.ROOT, "%08d", new java.security.SecureRandom().nextInt(100000000)); }
        while (!validPin(pin));
        pins.put(name, pin);
        var hash = session.getProvider(PasswordHashProvider.class, "argon2"); check(hash != null);
        var credential = hash.encodedCredential(NativePinProtectionImpl.keyed(realm.getId(), user.getId(), pin, "fixture"), 5);
        credential.setType("firefly-support-pin"); credential.setCreatedDate(System.currentTimeMillis());
        var stored = user.credentialManager().createStoredCredential(credential);
        var state = new NativeStoreImpl(session).state(user.getId(), true);
        state.pinCredentialId = stored.getId(); state.pinGeneration = UUID.randomUUID().toString(); state.pinKeyVersion = "fixture";
        state.pinCreatedAt = System.currentTimeMillis(); return user.getId();
    }
    private boolean validPin(String pin) { try { NativeSecurityImpl.requirePin(pin); return true; } catch (NativeRefusal refused) { return false; } }
    private String user(String name) { return tx(session -> createUser(session, name)); }
    private String existing(String name) { return tx(s -> s.users().getUserByUsername(s.getContext().getRealm(), name).getId()); }
    private String permit(String subject, String nonce, Gate gate, boolean interrupt) {
        return tx(session -> {
            var user = session.users().getUserById(session.getContext().getRealm(), subject);
            var grant = new NativeSupportAuthorization.Grant(nonce, "https://fixture.invalid/realms/" + REALM, REALM, subject,
                    "synthetic-tenant", user.getFirstAttribute("fixture-link"), "https://workforce.invalid/realms/staff", "synthetic-operator",
                    "synthetic-case", "synthetic-call", "VERIFY_SUPPORT_PIN", "TELEPHONE_SUPPORT_KNOWLEDGE", Instant.ofEpochMilli(System.currentTimeMillis() + 115000));
            String context = UUID.randomUUID().toString(); PERMITS.put(context, new Permit(grant, gate, interrupt)); return context;
        });
    }
    private String verify(String context, String pin) { return service(nativeService -> nativeService.verify(context, pin).reference()); }
    private void consume(String context, String reference) { service(nativeService -> { nativeService.consume(context, reference); return null; }); }
    private boolean refused(Runnable operation) { try { operation.run(); return false; } catch (RuntimeException expected) { return true; } }
    private long count(String query) { return tx(s -> ((Number) new NativeStoreImpl(s).em.createNativeQuery(query).getSingleResult()).longValue()); }
    private void sql(String query) { tx(s -> { new NativeStoreImpl(s).em.createNativeQuery(query).executeUpdate(); return null; }); }
    private String subjectSnapshot(String subject) {
        return tx(s -> new NativeStoreImpl(s).em.createNativeQuery("SELECT jsonb_build_object('state',(SELECT to_jsonb(state) FROM ff_native_state state WHERE subject='" + subject + "'),'proofs',(SELECT jsonb_agg(to_jsonb(proof) ORDER BY proof.id) FROM ff_native_support_proof proof WHERE subject='" + subject + "'))::text").getSingleResult().toString());
    }
    private NativeState state(String subject) { return tx(s -> new NativeStoreImpl(s).state(subject, false)); }
    private NativeSupportProof proof(String subject) { return tx(s -> new NativeStoreImpl(s).em.createQuery("from NativeSupportProof where subject = :subject", NativeSupportProof.class).setParameter("subject", subject).getSingleResult()); }
    private boolean waiting(int minimum, String relation) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
        while (System.nanoTime() < deadline) {
            if (count("SELECT count(*) FROM pg_stat_activity waiter WHERE waiter.datname=current_database() AND waiter.pid<>pg_backend_pid() AND waiter.wait_event_type='Lock' AND waiter.query ILIKE '%" + relation + "%' AND EXISTS (SELECT 1 FROM pg_stat_activity blocker WHERE blocker.pid=ANY(pg_blocking_pids(waiter.pid)) AND blocker.query ILIKE '%" + relation + "%')") >= minimum) return true;
            Thread.sleep(30);
        }
        return false;
    }
    private Map<String, Object> admission() {
        stage = "OWNER_ADMISSION_NEGATIVES";
        var missing = new HashMap<>(System.getenv()); missing.remove("FIREFLY_SUPPORT_QUALIFICATION_RUN");
        check(!SupportQualificationOwner.admitted(missing));
        var malformed = new HashMap<>(System.getenv()); malformed.put("FIREFLY_SUPPORT_QUALIFICATION_RUN", "../external");
        check(!SupportQualificationOwner.admitted(malformed));
        var mismatched = new HashMap<>(System.getenv()); mismatched.put("HOSTNAME", "external-identity");
        check(!SupportQualificationOwner.admitted(mismatched));
        check(new SupportQualificationOwner().isQualified());
        check(refused(() -> new SupportQualificationOwner().create(request)));
        tx(s -> { check(refused(() -> new SupportQualificationOwner().create(s).authorize("unregistered-context"))); return null; });
        return passed("master-realm-and-unregistered-grants-refused");
    }
    private Map<String, Object> legacy() {
        stage = "LEGACY_ORIGINAL_GRANT_PRECONDITIONS";
        String subject = existing("legacy-consume");
        String context = tx(s -> {
            var user = s.users().getUserById(s.getContext().getRealm(), subject);
            var grant = new NativeSupportAuthorization.Grant("legacy", "https://fixture.invalid/realms/" + REALM, REALM, subject,
                    "synthetic-tenant", user.getFirstAttribute("fixture-link"), "https://workforce.invalid/realms/staff", "synthetic-operator",
                    "synthetic-case", "synthetic-call", "VERIFY_SUPPORT_PIN", "TELEPHONE_SUPPORT_KNOWLEDGE", Instant.parse(user.getFirstAttribute("fixture-legacy-expires")));
            NativeSupportEvidenceImpl.validate(grant, NativeProfile.of(s.getContext().getRealm()).issuer(), REALM, Instant.now());
            NativeSupportEvidenceImpl.requireActive(new NativeStoreImpl(s).state(subject, false)); check(user.isEnabled());
            var proof = new NativeStoreImpl(s).em.find(NativeSupportProof.class, "retained-proof");
            check(proof.subject.equals(subject) && proof.grantDigest.equals(NativeSupportEvidenceImpl.grantDigest(grant)));
            String token = UUID.randomUUID().toString(); PERMITS.put(token, new Permit(grant, null, false)); return token;
        });
        tx(s -> { NativeSupportProof legacy = s.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager().find(NativeSupportProof.class, "retained-proof");
            check(legacy != null && legacy.nonceDigest == null && legacy.status == null && legacy.consumedAt == null); return null; });
        stage = "LEGACY_MISSING_BINDING_REFUSAL";
        String original = subjectSnapshot(subject);
        check(refused(() -> consume(context, "retained-proof")));
        stage = "LEGACY_ORIGINAL_EXPIRY_STILL_LIVE";
        tx(s -> { var grant = PERMITS.get(context).grant;
            NativeSupportEvidenceImpl.validate(grant, NativeProfile.of(s.getContext().getRealm()).issuer(), REALM, Instant.now()); return null; });
        check(original.equals(subjectSnapshot(subject)));
        check(count("SELECT count(*) FROM ff_native_support_proof WHERE id='retained-proof' AND status IS NULL AND consumed_at IS NULL") == 1);
        check(state(subject).pinReserved == 0 && state(subject).pinFailures == 0);
        check(count("SELECT count(*) FROM ff_native_audit WHERE reference_id='retained-proof'") == 0);
        return passed("legacy-proof-refused");
    }
    private Map<String, Object> nonce() throws Exception {
        String first = user("nonce-first"), second = user("nonce-second");
        String a = permit(first, "same-nonce", null, false), b = permit(second, "same-nonce", null, false);
        // AFTER INSERT keeps the winner transaction open while the second transaction waits on its nonce index.
        sql("CREATE FUNCTION fixture_nonce_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$");
        sql("CREATE TRIGGER fixture_nonce_pause AFTER INSERT ON ff_native_support_proof FOR EACH ROW EXECUTE FUNCTION fixture_nonce_pause()");
        var start = new CyclicBarrier(2); var executor = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> left = executor.submit(() -> { start.await(10, TimeUnit.SECONDS); return refused(() -> verify(a, pins.get("nonce-first"))); });
            Future<Boolean> right = executor.submit(() -> { start.await(10, TimeUnit.SECONDS); return refused(() -> verify(b, pins.get("nonce-second"))); });
            stage = "NONCE_CORRELATED_INSERT_CONTENTION";
            check(waiting(1, "ff_native_support_proof")); stage = "NONCE_SINGLE_COMMIT"; check(left.get(20, TimeUnit.SECONDS) != right.get(20, TimeUnit.SECONDS));
            check(count("SELECT count(*) FROM ff_native_support_proof WHERE subject IN ('" + first + "','" + second + "')") == 1);
            check(state(first).pinReserved + state(second).pinReserved == 0);
        } finally { executor.shutdownNow(); sql("DROP TRIGGER fixture_nonce_pause ON ff_native_support_proof"); }
        return Map.of("result", "passed", "scenario", "same-nonce-cross-customer", "observed_lock_waiters", 1);
    }
    private Map<String, Object> budget(boolean interrupted) throws Exception {
        String name = interrupted ? "interrupted" : "budget"; String subject = user(name); var gate = new Gate(3);
        var executor = Executors.newFixedThreadPool(3); var futures = new ArrayList<Future<Boolean>>();
        try {
            for (int i = 0; i < 3; i++) {
                String context = permit(subject, name + "-" + i, gate, interrupted);
                // A valid but different synthetic PIN exercises actual Argon2 rejection.
                String wrong = "59381726".equals(pins.get(name)) ? "80461937" : "59381726";
                futures.add(executor.submit(() -> refused(() -> verify(context, wrong))));
            }
            stage = "BUDGET_THREE_PENDING_RESERVATIONS";
            check(gate.reached.await(20, TimeUnit.SECONDS));
            check(state(subject).pinReserved == 3 && state(subject).pinFailures == 0);
            String fourth = permit(subject, name + "-fourth", null, false);
            stage = "BUDGET_FOURTH_REFUSAL";
            check(refused(() -> verify(fourth, pins.get(name)))); check(state(subject).pinReserved == 3);
            gate.release.countDown();
            for (var future : futures) check(future.get(20, TimeUnit.SECONDS));
            stage = "BUDGET_DURABLE_OUTCOMES";
            var state = state(subject);
            check(interrupted ? state.pinReserved == 3 && state.pinFailures == 0 && !state.pinHeld
                    : state.pinReserved == 0 && state.pinFailures == 3 && state.pinHeld);
            check(count("SELECT count(*) FROM ff_native_support_proof WHERE subject='" + subject + "' AND status='" + (interrupted ? "RESERVED" : "REJECTED") + "'") == 3);
        } finally { gate.release.countDown(); executor.shutdownNow(); }
        return Map.of("result", "passed", "scenario", name, "simultaneous_committed_reservations", 3, "fourth_refused", true);
    }
    private Map<String, Object> consumption() throws Exception {
        String subject = user("consume"); String context = permit(subject, "consume", null, false);
        String reference = verify(context, pins.get("consume")); var executor = Executors.newFixedThreadPool(3);
        var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
        try {
            Future<?> holder = executor.submit(() -> tx(s -> {
                new NativeStoreImpl(s).local(subject, true); locked.countDown();
                try { check(release.await(20, TimeUnit.SECONDS)); } catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new NativeRefusal(); }
                return null;
            }));
            check(locked.await(10, TimeUnit.SECONDS));
            Future<Boolean> a = executor.submit(() -> refused(() -> consume(context, reference)));
            Future<Boolean> b = executor.submit(() -> refused(() -> consume(context, reference)));
            stage = "CONSUME_TWO_CORRELATED_CUSTOMER_WAITERS";
            check(waiting(2, "user_entity")); stage = "CONSUME_EXACTLY_ONE_COMMIT"; release.countDown(); holder.get(10, TimeUnit.SECONDS);
            check(a.get(20, TimeUnit.SECONDS) != b.get(20, TimeUnit.SECONDS));
            check("CONSUMED".equals(proof(subject).status));
            check(count("SELECT count(*) FROM ff_native_audit WHERE reference_id='" + reference + "' AND event_type='SUPPORT_PIN_CONSUMED'") == 1);
        } finally { release.countDown(); executor.shutdownNow(); }
        return Map.of("result", "passed", "scenario", "concurrent-consumption", "observed_lock_waiters", 2, "committed_consumptions", 1);
    }
    private Map<String, Object> audit() {
        stage = "AUDIT_VERIFIED_ORIGINAL_PROOF";
        String subject = user("audit"); String context = permit(subject, "audit", null, false);
        String reference = verify(context, pins.get("audit"));
        String original = subjectSnapshot(subject);
        sql("CREATE FUNCTION fixture_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='SUPPORT_PIN_CONSUMED' AND NEW.subject='" + subject + "' THEN RAISE EXCEPTION 'Synthetic audit refusal' USING ERRCODE='FQ001'; END IF; RETURN NEW; END $$");
        sql("CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON ff_native_audit FOR EACH ROW EXECUTE FUNCTION fixture_audit_failure()");
        try {
            stage = "AUDIT_INJECTED_SQLSTATE_REQUIRED";
            boolean injected = false;
            try { consume(context, reference); }
            catch (RuntimeException failure) { if (!sqlStates(failure).contains("FQ001")) throw failure; injected = true; }
            check(injected);
            stage = "AUDIT_ORIGINAL_PROOF_AND_COUNTERS_ROLLED_BACK";
            check(original.equals(subjectSnapshot(subject))); var proof = proof(subject);
            check("VERIFIED".equals(proof.status) && proof.consumedAt == null);
            check(count("SELECT count(*) FROM ff_native_audit WHERE reference_id='" + reference + "' AND event_type='SUPPORT_PIN_CONSUMED'") == 0);
        } finally { sql("DROP TRIGGER fixture_audit_failure ON ff_native_audit"); }
        return Map.of("result", "passed", "scenario", "actual-consume-audit-failure-rollback", "audit_trigger_sqlstate", "FQ001", "original_proof_and_counters_preserved", true);
    }
    private Map<String, Object> invalidate(boolean held) throws Exception {
        String name = held ? "hold" : "generation"; String subject = user(name); var gate = new Gate(1);
        String context = permit(subject, name, gate, false); var executor = Executors.newSingleThreadExecutor();
        try {
            Future<Boolean> pending = executor.submit(() -> refused(() -> verify(context, pins.get(name))));
            stage = "INVALIDATION_PENDING_RESERVATION";
            check(gate.reached.await(15, TimeUnit.SECONDS)); check(state(subject).pinReserved == 1);
            tx(s -> { var store = new NativeStoreImpl(s); store.local(subject, true); var state = store.state(subject, false);
                if (held) state.pinHeld = true; else state.pinGeneration = UUID.randomUUID().toString(); return null; });
            stage = "INVALIDATION_REFUSED_WITHOUT_REFUND";
            gate.release.countDown(); check(pending.get(15, TimeUnit.SECONDS));
            check("RESERVED".equals(proof(subject).status) && state(subject).pinReserved == 1);
        } finally { gate.release.countDown(); executor.shutdownNow(); }
        return passed("pending-" + name + "-invalidation-no-refund");
    }
    private Map<String, Object> lost() {
        stage = "LOST_APPLICATION_RESULT_COMMITTED";
        String subject = user("lost"); String context = permit(subject, "lost-response-grant", null, false);
        String reference = verify(context, pins.get("lost")); consume(context, reference);
        // Deliberately discard the successful service result; no reference, context or credential leaves this process.
        return passed("committed-result-deliberately-discarded");
    }
    private Map<String, Object> reconcile() {
        stage = "RESTART_ORIGINAL_JOURNAL_AND_BUDGETS";
        String subject = existing("lost"); var original = proof(subject);
        check("CONSUMED".equals(original.status) && original.consumedAt != null);
        var grant = new NativeSupportAuthorization.Grant("lost-response-grant", original.targetIssuer, REALM, original.subject,
                original.tenant, original.customerLink, original.staffIssuer, original.staffSubject, original.caseId, original.callId,
                original.permittedAction, original.purpose, Instant.ofEpochMilli(original.expiresAt));
        check(NativeSupportEvidenceImpl.grantDigest(grant).equals(original.grantDigest));
        String context = UUID.randomUUID().toString(); PERMITS.put(context, new Permit(grant, null, false));
        check(refused(() -> consume(context, original.id)));
        check(count("SELECT count(*) FROM ff_native_audit WHERE reference_id='" + original.id + "' AND event_type='SUPPORT_PIN_CONSUMED'") == 1);
        check(state(existing("budget")).pinFailures == 3 && state(existing("budget")).pinHeld);
        check(state(existing("interrupted")).pinReserved == 3 && state(existing("interrupted")).pinFailures == 0);
        check(count("SELECT count(*) FROM ff_native_support_proof WHERE subject='" + existing("interrupted") + "' AND status='RESERVED'") == 3);
        return passed("original-journal-and-budgets-after-restart-no-replay");
    }
}
