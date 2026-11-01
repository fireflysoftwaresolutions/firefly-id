package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.*;
import org.keycloak.storage.UserStoragePrivateUtil;
import jakarta.persistence.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingPolicyLockOrderTest {
    @Test @SuppressWarnings({"rawtypes","unchecked"})
    void nativeUserLockPrecedesPolicyAndCurrentRawRealmIsLoadedOnlyAfterFence() throws Exception {
        Class policy;
        try { policy=Class.forName("io.firefly.id.nativeauth.impl.ReproofingRealmPolicyEntityImpl"); }
        catch(ClassNotFoundException missing) { fail("Missing current authorization policy lock boundary"); return; }
        var session=mock(KeycloakSession.class,RETURNS_DEEP_STUBS); var realm=mock(RealmModel.class); var em=mock(EntityManager.class); var jpa=mock(JpaConnectionProvider.class); var realms=mock(RealmProvider.class);
        doReturn(jpa).when(session).getProvider(JpaConnectionProvider.class); doReturn(realms).when(session).getProvider(RealmProvider.class); when(jpa.getEntityManager()).thenReturn(em); when(session.getContext().getRealm()).thenReturn(realm);
        when(realm.getId()).thenReturn("realm"); when(realm.getName()).thenReturn("customers");
        Map<String,String> attrs=Map.of("enabled","true","population","HUMAN","allowed-origin","https://id.test","issuer","https://id.test/realms/customers","core-workload-client-id","core","domain-workload-client-id","domain","ttl-seconds","600");
        when(realm.getAttribute(anyString())).thenAnswer(call -> attrs.get(call.getArgument(0,String.class).replace("firefly.reproofing.","")));
        var owner=new UserEntity(); owner.setId("subject"); owner.setRealmId("realm"); when(em.find(UserEntity.class,"subject",LockModeType.PESSIMISTIC_WRITE)).thenReturn(owner);
        var realmEntity=new RealmEntity(); realmEntity.setId("realm"); when(em.find(RealmEntity.class,"realm")).thenReturn(realmEntity); when(realms.getRealm("realm")).thenReturn(realm);
        Object row=policy.getConstructor().newInstance(); policy.getField("id").set(row,"realm"); when(em.find(policy,"realm",LockModeType.PESSIMISTIC_WRITE)).thenReturn(row);
        var users=mock(UserProvider.class); var user=mock(UserModel.class); when(users.getUserById(realm,"subject")).thenReturn(user); when(session.users().getFederatedIdentitiesStream(realm,user)).thenReturn(Stream.empty());
        try(var local=mockStatic(UserStoragePrivateUtil.class)) {
            local.when(() -> UserStoragePrivateUtil.userLocalStorage(session)).thenReturn(users);
            assertEquals(user,new ReproofingStoreImpl(session).local("subject"));
        }
        var order=inOrder(em,realms); order.verify(em).find(UserEntity.class,"subject",LockModeType.PESSIMISTIC_WRITE); order.verify(em).find(policy,"realm",LockModeType.PESSIMISTIC_WRITE); order.verify(realms).getRealm("realm");
    }
}
