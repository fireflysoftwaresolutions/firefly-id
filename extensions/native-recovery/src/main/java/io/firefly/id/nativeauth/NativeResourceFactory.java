package io.firefly.id.nativeauth;

import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.services.resource.*;

public final class NativeResourceFactory implements RealmResourceProviderFactory {
    @Override public String getId() { return "native-recovery"; }
    @Override public RealmResourceProvider create(KeycloakSession session) { return new RealmResourceProvider() {
        @Override public Object getResource() { return new NativeResource(session); }
        @Override public void close() { }
    }; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
