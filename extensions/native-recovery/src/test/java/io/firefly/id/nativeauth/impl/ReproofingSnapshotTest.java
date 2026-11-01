package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.NativeState;
import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.*;
import org.keycloak.credential.CredentialModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import jakarta.persistence.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingSnapshotTest {
    @Test void completeRevisionBindsContactVerificationHistoryAndPinAuthority() {
        var session = mock(KeycloakSession.class); var realm = mock(RealmModel.class); var em = mock(EntityManager.class); var connection = mock(JpaConnectionProvider.class);
        var context = mock(KeycloakContext.class); var users = mock(UserProvider.class); when(session.getContext()).thenReturn(context); when(context.getRealm()).thenReturn(realm); when(session.users()).thenReturn(users); when(session.getProvider(JpaConnectionProvider.class)).thenReturn(connection); when(connection.getEntityManager()).thenReturn(em);
        when(realm.getName()).thenReturn("customers"); when(realm.getId()).thenReturn("realm-id");
        Map<String,String> attributes = Map.of("enabled","true","population","HUMAN","allowed-origin","https://id.test","issuer","https://id.test/realms/customers","core-workload-client-id","core-owner","domain-workload-client-id","domain-owner","ttl-seconds","600","tenant-attribute","tenant","link-attribute","party");
        when(realm.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.getArgument(0,String.class).replace("firefly.reproofing.","")));
        var policy = mock(PasswordPolicy.class); when(policy.toString()).thenReturn("length(12)"); when(realm.getPasswordPolicy()).thenReturn(policy);
        var otp = mock(OTPPolicy.class); when(otp.getAlgorithm()).thenReturn("HmacSHA1"); when(otp.getDigits()).thenReturn(6); when(otp.getPeriod()).thenReturn(30); when(otp.getType()).thenReturn("totp"); when(realm.getOTPPolicy()).thenReturn(otp);
        var user = mock(UserModel.class, RETURNS_DEEP_STUBS); when(user.getId()).thenReturn("subject"); when(user.isEnabled()).thenReturn(true); when(user.isEmailVerified()).thenReturn(true); when(user.getEmail()).thenReturn("first@example.test");
        when(user.getAttributeStream("tenant")).thenAnswer(call -> Stream.of("tenant")); when(user.getAttributeStream("party")).thenAnswer(call -> Stream.of("00000000-0000-0000-0000-000000000001")); when(user.getRoleMappingsStream()).thenAnswer(call -> Stream.empty());
        CredentialModel credential = new CredentialModel(); credential.setId("history-id"); credential.setType("password-history");
        when(user.credentialManager().getStoredCredentialsStream()).thenAnswer(call -> Stream.of(credential));
        UserEntity owner = new UserEntity(); owner.setId("subject"); CredentialEntity stored = new CredentialEntity(); stored.setId("history-id"); stored.setType("password-history"); stored.setUser(owner); stored.setSecretData("old-hash");
        when(em.find(CredentialEntity.class,"history-id",LockModeType.PESSIMISTIC_WRITE)).thenReturn(stored);
        var policyFence = new ReproofingRealmPolicyEntityImpl(); when(em.find(ReproofingRealmPolicyEntityImpl.class,"realm-id",LockModeType.PESSIMISTIC_WRITE)).thenReturn(policyFence);
        var roles = mock(jakarta.persistence.Query.class); when(em.createNativeQuery(anyString())).thenReturn(roles); when(roles.setParameter(anyString(),any())).thenReturn(roles); when(roles.getResultList()).thenReturn(List.of("role"));
        var state = new NativeState(); state.pinGeneration = "pin-epoch"; var store = new ReproofingStoreImpl(session); String original = store.revision(user,state);
        when(user.getEmail()).thenReturn("second@example.test"); assertNotEquals(original,store.revision(user,state)); when(user.getEmail()).thenReturn("first@example.test");
        when(user.isEmailVerified()).thenReturn(false); assertNotEquals(original,store.revision(user,state)); when(user.isEmailVerified()).thenReturn(true);
        stored.setSecretData("replacement-history-hash"); assertNotEquals(original,store.revision(user,state)); stored.setSecretData("old-hash");
        state.pinGeneration = "new-pin-epoch"; assertNotEquals(original,store.revision(user,state)); state.pinGeneration = "pin-epoch";
        assertEquals(original,store.revision(user,state));
        policyFence.revision = 1; assertNotEquals(original,store.revision(user,state)); policyFence.revision = 0;
        var recovery = new ReproofingStateImpl(); when(em.find(eq(ReproofingStateImpl.class),anyString(),eq(LockModeType.PESSIMISTIC_WRITE))).thenReturn(recovery);
        assertEquals(original,store.revision(user,state)); recovery.invalidationVersion = 1; assertNotEquals(original,store.revision(user,state));
        when(user.credentialManager().getStoredCredentialsStream()).thenAnswer(call -> Stream.empty()); assertNotEquals(original,store.revision(user,state));
    }
}
