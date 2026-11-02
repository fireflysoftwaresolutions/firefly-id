package io.firefly.id.nativeauth;

import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.services.resource.*;

public final class SupportQualificationFactory implements RealmResourceProviderFactory {
    @Override public String getId() { return "support-qualification"; }
    @Override public RealmResourceProvider create(KeycloakSession session) { return new RealmResourceProvider() {
        @Override public Object getResource() { return new SupportQualificationResource(session); }
        @Override public void close() { }
    }; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
