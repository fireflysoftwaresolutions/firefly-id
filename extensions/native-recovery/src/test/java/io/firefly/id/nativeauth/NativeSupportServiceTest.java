package io.firefly.id.nativeauth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.storage.UserStoragePrivateUtil;
import java.time.Instant;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeSupportServiceTest {
    @Test void currentOwnerRefusalAfterReservationPreservesSlotAndCannotCheckPin() {
        var fixture = new Fixture();
        when(fixture.owner.authorize("signed-context")).thenAnswer(call -> {
            assertFalse(fixture.inPhase);
            if (fixture.proof != null) throw new NativeRefusal();
            return fixture.grant;
        });
        assertThrows(NativeRefusal.class, () -> fixture.run(() -> fixture.service.verify("signed-context", "57290418")));
        assertEquals(1, fixture.state.pinReserved); assertEquals(0, fixture.state.pinFailures);
        assertEquals("RESERVED", fixture.proof.status); verifyNoInteractions(fixture.hash);
        verify(fixture.owner, times(2)).authorize("signed-context");
    }
    @Test void changedOwnerGrantAfterReservationAlsoPreservesSlotWithoutPinCheck() {
        var fixture = new Fixture(); var g = fixture.grant;
        var changed = new NativeSupportAuthorization.Grant(g.nonce(), g.targetIssuer(), g.realm(), g.subject(), g.tenant(), g.customerLink(),
                g.staffIssuer(), "different-operator", g.caseId(), g.callId(), g.permittedAction(), g.purpose(), g.expiresAt());
        when(fixture.owner.authorize("signed-context")).thenReturn(g, changed);
        assertThrows(NativeRefusal.class, () -> fixture.run(() -> fixture.service.verify("signed-context", "57290418")));
        assertEquals(1, fixture.state.pinReserved); assertEquals("RESERVED", fixture.proof.status);
        verifyNoInteractions(fixture.hash);
    }
    @Test void acceptedProofConsumesOnceUnderOrderedLocksWithImmutableAuditAttribution() {
        var fixture = new Fixture();
        fixture.run(() -> fixture.service.verify("signed-context", "57290418"));
        assertEquals("VERIFIED", fixture.proof.status); assertEquals(0, fixture.state.pinReserved);
        clearInvocations(fixture.em);
        fixture.run(() -> { fixture.service.consume("signed-context", fixture.proof.id); return null; });
        var ordered = inOrder(fixture.em);
        ordered.verify(fixture.em).find(UserEntity.class, "customer", LockModeType.PESSIMISTIC_WRITE);
        ordered.verify(fixture.em).find(NativeState.class, fixture.state.id, LockModeType.PESSIMISTIC_WRITE);
        ordered.verify(fixture.em).find(NativeSupportProof.class, fixture.proof.id, LockModeType.PESSIMISTIC_WRITE);
        ordered.verify(fixture.em).persist(argThat(value -> value instanceof NativeAudit audit
                && "SUPPORT_PIN_CONSUMED".equals(audit.eventType) && fixture.proof.id.equals(audit.referenceId)
                && fixture.grant.staffIssuer().equals(audit.actorIssuer) && "operator".equals(audit.actorSubject)
                && "case".equals(audit.supportCaseId) && "call".equals(audit.supportCallId)
                && "tenant".equals(audit.supportTenant) && fixture.grant.customerLink().equals(audit.supportCustomerLink)
                && "VERIFY_SUPPORT_PIN".equals(audit.supportAction) && "TELEPHONE_SUPPORT_KNOWLEDGE".equals(audit.supportPurpose)
                && fixture.proof.grantDigest.equals(audit.supportGrantDigest) && fixture.proof.nonceDigest.equals(audit.supportNonceDigest)));
        assertEquals("CONSUMED", fixture.proof.status);
        assertThrows(NativeRefusal.class, () -> fixture.run(() -> { fixture.service.consume("signed-context", fixture.proof.id); return null; }));
        verify(fixture.hash, times(1)).verify(anyString(), any(PasswordCredentialModel.class));
    }
    @Test void ownerOutageBeforeConsumptionLeavesVerifiedProofAndDoesNotAcquireNativeLocks() {
        var fixture = new Fixture(); fixture.accepted(); clearInvocations(fixture.em);
        when(fixture.owner.authorize("signed-context")).thenThrow(new IllegalStateException("synthetic owner outage"));
        assertThrows(IllegalStateException.class, () -> fixture.run(() -> { fixture.service.consume("signed-context", fixture.proof.id); return null; }));
        assertEquals("VERIFIED", fixture.proof.status); verifyNoInteractions(fixture.em);
    }
    @Test void expiryWhileWaitingForLocksCannotConsumeUsingPreLockTime() {
        var fixture = new Fixture(); fixture.accepted();
        Instant before = fixture.grant.expiresAt().minusSeconds(60), after = fixture.grant.expiresAt();
        try (var clock = mockStatic(Instant.class, CALLS_REAL_METHODS)) {
            clock.when(Instant::now).thenReturn(before, after);
            assertThrows(NativeRefusal.class, () -> fixture.run(() -> { fixture.service.consume("signed-context", fixture.proof.id); return null; }));
        }
        assertEquals("VERIFIED", fixture.proof.status); assertNull(fixture.proof.consumedAt);
    }
    @Test void disabledFederatedPrivilegedOrMissingNativeCredentialCustomersAreRefused() {
        for (int refusal = 0; refusal < 4; refusal++) {
            var fixture = new Fixture();
            if (refusal == 0) when(fixture.user.isEnabled()).thenReturn(false);
            if (refusal == 1) fixture.entity.setFederationLink("external-provider");
            if (refusal == 2) {
                var admin = mock(ClientModel.class); var role = mock(RoleModel.class);
                when(fixture.session.clients().getClientByClientId(fixture.session.getContext().getRealm(), "realm-management")).thenReturn(admin);
                when(admin.getRolesStream()).thenAnswer(call -> Stream.of(role)); when(fixture.user.hasRole(role)).thenReturn(true);
            }
            if (refusal == 3) when(fixture.user.credentialManager().getStoredCredentialById("credential")).thenReturn(null);
            assertThrows(NativeRefusal.class, () -> fixture.run(() -> fixture.service.verify("signed-context", "57290418")));
            assertEquals(0, fixture.state.pinReserved); verify(fixture.em, never()).persist(any()); verifyNoInteractions(fixture.hash);
        }
    }
    private static final class Fixture {
        final KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        final EntityManager em = mock(EntityManager.class);
        final UserProvider users = mock(UserProvider.class);
        final UserModel user = mock(UserModel.class);
        final UserEntity entity = new UserEntity();
        final PasswordHashProvider hash = mock(PasswordHashProvider.class);
        final NativeSupportAuthorization owner = mock(NativeSupportAuthorization.class);
        final NativeSupportPinServiceImpl service = spy(new NativeSupportPinServiceImpl(session));
        final NativeState state = new NativeState();
        final NativeSupportAuthorization.Grant grant = new NativeSupportAuthorization.Grant("nonce", "https://id.test/realms/customers",
                "customers", "customer", "tenant", "76d9cb6f-edf9-4c3e-a82b-9fcba6698800", "https://id.test/realms/staff",
                "operator", "case", "call", "VERIFY_SUPPORT_PIN", "TELEPHONE_SUPPORT_KNOWLEDGE", Instant.now().plusSeconds(60));
        NativeSupportProof proof;
        boolean inPhase;
        Fixture() {
            var realm = session.getContext().getRealm(); when(realm.getId()).thenReturn("realm-id"); when(realm.getName()).thenReturn("customers");
            Map<String, String> configuration = Map.ofEntries(
                    Map.entry("population", "HUMAN"), Map.entry("allowed-origin", "https://id.test"),
                    Map.entry("issuer", grant.targetIssuer()), Map.entry("client-id", "recovery"),
                    Map.entry("tenant-attribute", "tenant_id"), Map.entry("link-attribute", "party_id"),
                    Map.entry("domain-audience", "domain"), Map.entry("core-audience", "core"),
                    Map.entry("core-workload-client-id", "native-core"), Map.entry("domain-workload-client-id", "native-domain"),
                    Map.entry("ttl-seconds", "300"));
            when(realm.getAttribute(anyString())).thenAnswer(call -> configuration.get(call.getArgument(0, String.class).replace("firefly.native-recovery.", "")));
            var jpa = mock(JpaConnectionProvider.class); doReturn(jpa).when(session).getProvider(JpaConnectionProvider.class); when(jpa.getEntityManager()).thenReturn(em);
            when(user.getId()).thenReturn("customer"); when(user.isEnabled()).thenReturn(true); when(users.getUserById(realm, "customer")).thenReturn(user);
            when(user.getAttributeStream("tenant_id")).thenAnswer(call -> Stream.of(grant.tenant()));
            when(user.getAttributeStream("party_id")).thenAnswer(call -> Stream.of(grant.customerLink()));
            when(session.clients().getClientByClientId(realm, "realm-management")).thenReturn(null);
            entity.setId("customer"); entity.setRealmId("realm-id");
            when(em.find(UserEntity.class, "customer", LockModeType.PESSIMISTIC_WRITE)).thenReturn(entity);
            var credential = new CredentialModel(); credential.setId("credential"); credential.setType("firefly-support-pin");
            credential.setCredentialData("{\"algorithm\":\"argon2\",\"hashIterations\":1}");
            credential.setSecretData("{\"value\":\"synthetic\",\"salt\":\"\"}");
            var manager = mock(SubjectCredentialManager.class); when(user.credentialManager()).thenReturn(manager);
            when(manager.getStoredCredentialById("credential")).thenReturn(credential);
            doReturn(hash).when(session).getProvider(PasswordHashProvider.class, "argon2");
            when(hash.verify(anyString(), any(PasswordCredentialModel.class))).thenReturn(true);
            state.id = NativeSecurityImpl.digest("realm-id\ncustomer"); state.realmId = "realm-id"; state.subject = "customer";
            state.pinGeneration = "generation"; state.pinCredentialId = "credential"; state.pinKeyVersion = "v1";
            when(em.find(NativeState.class, state.id, LockModeType.PESSIMISTIC_WRITE)).thenReturn(state);
            doAnswer(call -> { if (call.getArgument(0) instanceof NativeSupportProof value) proof = value; return null; }).when(em).persist(any());
            when(em.find(eq(NativeSupportProof.class), anyString(), eq(LockModeType.PESSIMISTIC_WRITE))).thenAnswer(call -> proof);
            doReturn(owner).when(service).authority("signed-context");
            when(owner.authorize("signed-context")).thenAnswer(call -> { assertFalse(inPhase); return grant; });
        }
        void accepted() {
            proof = NativeSupportEvidenceImpl.reserve(grant, "realm-id", state, Instant.now());
            NativeSupportEvidenceImpl.complete(proof, state, true);
        }
        @SuppressWarnings("unchecked") <T> T run(java.util.function.Supplier<T> action) {
            try (var phases = mockStatic(NativePhasesImpl.class); var local = mockStatic(UserStoragePrivateUtil.class);
                    var keys = mockStatic(NativePinProtectionImpl.class)) {
                phases.when(() -> NativePhasesImpl.run(eq(session), any())).thenAnswer(call -> {
                    assertFalse(inPhase); inPhase = true;
                    try { return ((Function<KeycloakSession, Object>) call.getArgument(1)).apply(session); }
                    finally { inPhase = false; }
                });
                local.when(() -> UserStoragePrivateUtil.userLocalStorage(session)).thenReturn(users);
                keys.when(() -> NativePinProtectionImpl.keyed(anyString(), anyString(), anyString(), anyString())).thenReturn("synthetic-keyed-value");
                return action.get();
            }
        }
    }
}
