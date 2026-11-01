package io.firefly.id.gateway;

import io.firefly.id.nativeauth.NativeCeremonyGateway;
import org.keycloak.models.KeycloakSession;

import java.net.URI;

public final class DomainGatewayFactoryImpl implements NativeCeremonyGateway.Factory {
    @Override public boolean isQualified() { return true; }

    @Override public NativeCeremonyGateway create(KeycloakSession session) {
        String endpoint = session.getContext().getRealm().getAttribute("firefly.native-recovery.domain-url");
        if (endpoint == null || endpoint.isBlank()) throw new IllegalStateException("Explicit recovery owner endpoint required");
        try {
            return new DomainGatewayImpl(URI.create(endpoint));
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("Explicit recovery owner endpoint required");
        }
    }
}
