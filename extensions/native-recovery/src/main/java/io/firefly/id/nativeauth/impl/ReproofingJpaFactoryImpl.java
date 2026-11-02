package io.firefly.id.nativeauth.impl;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.*;
import org.keycloak.models.*;
import java.util.List;

public final class ReproofingJpaFactoryImpl implements JpaEntityProviderFactory {
    @Override public String getId() { return "firefly-independent-reproofing"; }
    @Override public JpaEntityProvider create(KeycloakSession session) { return new JpaEntityProvider() {
        @Override public List<Class<?>> getEntities() { return List.of(ReproofingRealmPolicyEntityImpl.class, ReproofingStateImpl.class, ReproofingCeremonyImpl.class, ReproofingExecutionImpl.class, ReproofingNotificationImpl.class); }
        @Override public String getChangelogLocation() { return "META-INF/firefly-reproofing.xml"; }
        @Override public String getFactoryId() { return getId(); }
        @Override public void close() { }
    }; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
