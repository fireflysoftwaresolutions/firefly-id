package io.firefly.id.nativeauth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.jpa.entities.CredentialEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.storage.UserStoragePrivateUtil;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeIssuedReservationTest {
    @Test void anotherReservationCannotReuseAnIssuedChallengeBeforeAnyAttemptOrVerification() {
        var fixture = new Fixture();
        assertThrows(NativeRefusal.class, () -> fixture.attest(UUID.randomUUID()));
        assertEquals(0, fixture.state.knowledgeAttempts); assertEquals(0, fixture.state.possessionAttempts);
        verify(fixture.em, never()).persist(any());
        verifyNoInteractions(fixture.hash);
    }

    @Test void matchingIssuedReservationVerifiesAndPersistsItsExactBindingOnce() {
        var fixture = new Fixture();
        String result = fixture.attest(fixture.reservation);
        assertNotNull(result); assertEquals(fixture.proof.id, result);
        assertEquals(fixture.reservation.toString(), fixture.proof.reservationId);
        assertEquals(fixture.issued.id, fixture.proof.providerChallengeId);
        assertTrue(fixture.proof.completed); assertTrue(fixture.proof.verified);
        assertEquals(1, fixture.state.knowledgeAttempts); assertEquals(0, fixture.state.possessionAttempts);
        verify(fixture.em).persist(fixture.proof);
        verify(fixture.hash).verify(eq("synthetic-password"), any(PasswordCredentialModel.class));
    }

    private static final class Fixture {
        final KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        final EntityManager em = mock(EntityManager.class);
        final PasswordHashProvider hash = mock(PasswordHashProvider.class);
        final UserProvider users = mock(UserProvider.class);
        final NativeState state = new NativeState();
        final NativeCeremony ceremony = new NativeCeremony();
        final NativeIssuedChallenge issued = new NativeIssuedChallenge();
        final UUID operation = UUID.randomUUID(), challenge = UUID.randomUUID(), reservation = UUID.randomUUID();
        NativeAttestation proof;

        @SuppressWarnings("unchecked") Fixture() {
            var realm = session.getContext().getRealm(); when(realm.getId()).thenReturn("realm"); when(realm.getName()).thenReturn("customers");
            Map<String, String> configuration = Map.ofEntries(
                    Map.entry("population", "HUMAN"), Map.entry("allowed-origin", "https://id.test"),
                    Map.entry("issuer", "https://id.test/realms/customers"), Map.entry("client-id", "recovery"),
                    Map.entry("tenant-attribute", "tenant_id"), Map.entry("link-attribute", "party_id"),
                    Map.entry("domain-audience", "domain"), Map.entry("core-audience", "core"),
                    Map.entry("core-workload-client-id", "native-core"), Map.entry("domain-workload-client-id", "native-domain"),
                    Map.entry("ttl-seconds", "300"));
            when(realm.getAttribute(anyString())).thenAnswer(call -> configuration.get(call.getArgument(0, String.class).replace("firefly.native-recovery.", "")));
            var jpa = mock(JpaConnectionProvider.class); when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa); when(jpa.getEntityManager()).thenReturn(em);
            var user = mock(UserModel.class); when(user.getId()).thenReturn("subject"); when(users.getUserById(realm, "subject")).thenReturn(user);
            when(user.getFirstAttribute(UserModel.DISABLED_REASON)).thenReturn("permanentLockout");
            String owner = UUID.randomUUID().toString();
            when(user.getAttributeStream("tenant_id")).thenAnswer(call -> Stream.of("tenant"));
            when(user.getAttributeStream("party_id")).thenAnswer(call -> Stream.of(owner));
            when(session.clients().getClientByClientId(realm, "realm-management")).thenReturn(null);
            var entity = new UserEntity(); entity.setId("subject"); entity.setRealmId("realm");
            when(em.find(UserEntity.class, "subject", LockModeType.PESSIMISTIC_WRITE)).thenReturn(entity);
            var credential = new CredentialModel(); credential.setId("credential"); credential.setType("password");
            credential.setCredentialData("{\"algorithm\":\"fixture\",\"hashIterations\":1}");
            credential.setSecretData("{\"value\":\"synthetic\",\"salt\":\"\"}");
            var manager = mock(SubjectCredentialManager.class); when(user.credentialManager()).thenReturn(manager);
            when(manager.getStoredCredentialsStream()).thenAnswer(call -> Stream.of(credential));
            when(manager.getStoredCredentialsByTypeStream("password")).thenAnswer(call -> Stream.of(credential));
            var stored = new CredentialEntity(); stored.setId("credential"); stored.setType("password"); stored.setUser(entity);
            stored.setCredentialData(credential.getCredentialData()); stored.setSecretData(credential.getSecretData());
            when(em.find(CredentialEntity.class, "credential", LockModeType.PESSIMISTIC_WRITE)).thenReturn(stored);
            when(session.getProvider(PasswordHashProvider.class, "fixture")).thenReturn(hash);
            when(hash.verify(eq("synthetic-password"), any(PasswordCredentialModel.class))).thenReturn(true);
            state.id = NativeSecurityImpl.digest("realm\nsubject"); state.generation = "generation"; state.locked = true;
            state.credentialRevision = new NativeStoreImpl(session).revision(user);
            when(em.find(NativeState.class, state.id, LockModeType.PESSIMISTIC_WRITE)).thenReturn(state);
            ceremony.id = "ceremony"; ceremony.realmId = "realm"; ceremony.subject = "subject"; ceremony.ownerLink = owner;
            ceremony.generation = state.generation; ceremony.operationId = operation.toString(); ceremony.knowledgeChallengeId = challenge.toString();
            ceremony.expiresAt = System.currentTimeMillis() + 60000;
            ceremony.bindingJson = NativeActorImpl.json(new Binding("https://id.test/realms/customers", "tenant", "recovery", null,
                    "subject", "https://id.test/realms/customers", "customers", "subject", "HUMAN", PURPOSE, state.generation));
            when(em.find(NativeCeremony.class, ceremony.id, LockModeType.PESSIMISTIC_WRITE)).thenReturn(ceremony);
            issued.id = "provider-challenge"; issued.ceremonyId = ceremony.id; issued.operationId = ceremony.operationId;
            issued.reservationId = reservation.toString(); issued.category = "KNOWLEDGE"; issued.credentialId = "credential"; issued.expiresAt = ceremony.expiresAt;
            when(em.find(NativeIssuedChallenge.class, issued.id)).thenReturn(issued);
            var existing = mock(TypedQuery.class, RETURNS_SELF); when(em.createQuery(anyString(), eq(NativeAttestation.class))).thenReturn(existing);
            when(existing.getResultList()).thenReturn(List.of());
            doAnswer(call -> { if (call.getArgument(0) instanceof NativeAttestation value) proof = value; return null; }).when(em).persist(any());
            when(em.find(eq(NativeAttestation.class), anyString(), eq(LockModeType.PESSIMISTIC_WRITE))).thenAnswer(call -> proof);
        }

        @SuppressWarnings("unchecked") String attest(UUID suppliedReservation) {
            try (var phases = mockStatic(NativePhasesImpl.class); var local = mockStatic(UserStoragePrivateUtil.class)) {
                phases.when(() -> NativePhasesImpl.run(eq(session), any())).thenAnswer(call -> ((Function<KeycloakSession, Object>) call.getArgument(1)).apply(session));
                local.when(() -> UserStoragePrivateUtil.userLocalStorage(session)).thenReturn(users);
                return new NativeEngineImpl(session).attest(ceremony.id,
                        new Reservation(operation, challenge, suppliedReservation, issued.id, issued.category, Instant.ofEpochMilli(ceremony.expiresAt)),
                        "synthetic-password");
            }
        }
    }
}
