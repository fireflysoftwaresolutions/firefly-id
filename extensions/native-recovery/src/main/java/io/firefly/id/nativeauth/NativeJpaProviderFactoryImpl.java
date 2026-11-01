package io.firefly.id.nativeauth;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import java.util.List;

public final class NativeJpaProviderFactoryImpl implements JpaEntityProviderFactory {
    @Override public JpaEntityProvider create(KeycloakSession session) { return new JpaEntityProvider() {
        @Override public List<Class<?>> getEntities() { return List.of(NativeState.class, NativeCeremony.class, NativeAttestation.class, NativeExecution.class, NativeAudit.class, NativeIssuedChallenge.class, NativeSupportProof.class, NativeTotpReplay.class); }
        @Override public String getChangelogLocation() { return "META-INF/firefly-native-recovery.xml"; }
        @Override public String getFactoryId() { return "firefly-native-recovery"; }
        @Override public void close() { }
    }; }
    @Override public String getId() { return "firefly-native-recovery"; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
