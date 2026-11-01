package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.NativePhases;
import io.firefly.id.nativeauth.ReproofingContracts.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ClientModel;
import org.keycloak.models.OAuth2DeviceConfig;
import org.keycloak.models.CibaConfig;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class ReproofingRpcImpl {
    private final KeycloakSession request;
    ReproofingRpcImpl(KeycloakSession request) { this.request = request; }
    Object call(String route, NativeRequest value) {
        require(Set.of("prepare", "admit", "journal").contains(route));
        String header = request.getContext().getRequestHeaders().getHeaderString("Authorization");
        if ("admit".equals(route)) NativePhases.run(request, child -> { authenticate(child, header, route); return null; });
        return NativePhases.run(request, child -> {
            if (!"admit".equals(route)) authenticate(child, header, route);
            var store = new ReproofingStoreImpl(child);
            require(value != null && value.binding() != null); Binding b = value.binding();
            require(b.nonce() != null && b.nonce().length() <= 128 && "CREDENTIAL_REPLACEMENT".equals(b.purpose()) && "HUMAN".equals(b.population()));
            var c = store.ceremony(b.nonce(), !"journal".equals(route)); require(b.equals(store.binding(c)));
            if ("journal".equals(route)) {
                require(value.caseId() != null && value.executionId() != null);
                var journal = ReproofingEngineImpl.journal(store, c);
                require(journal != null && journal.id.equals(value.executionId().toString()) && journal.caseId.equals(value.caseId().toString()) && journal.bindingJson.equals(c.bindingJson));
                return store.execution(journal);
            }
            if (value.caseId() != null && c.caseId != null) require(c.caseId.equals(value.caseId().toString()));
            if ("admit".equals(route)) { var user = store.local(c.subject); workload(child, header, route); store.current(c, user); return new Admission(b, true, Instant.ofEpochMilli(c.expiresAt)); }
            return new Admission(b, false, Instant.ofEpochMilli(c.expiresAt));
        });
    }
    static void authenticate(KeycloakSession child, String header, String route) {
        workload(child, header, route);
        ReproofingRealmPolicyImpl.lock(child);
        ReproofingRealmPolicyImpl.freshRealm(child);
        workload(child, header, route);
    }
    static void workload(KeycloakSession child, String header, String route) {
        var config = new ReproofingConfigImpl(child.getContext().getRealm());
        require(header != null && header.startsWith("Basic ") && header.length() <= 4096);
        String value = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8); int colon = value.indexOf(':'); require(colon > 0);
        String id = value.substring(0, colon), secret = value.substring(colon + 1);
        require((id.equals(config.value("core-workload-client-id")) && Set.of("prepare", "admit", "journal", "dispatch").contains(route))
                || (id.equals(config.value("domain-workload-client-id")) && Set.of("prepare", "admit").contains(route)));
        var client = ReproofingRealmPolicyImpl.freshClient(child, config.realm, id);
        require(client != null && client.isEnabled() && !client.isPublicClient() && !client.isStandardFlowEnabled() && !client.isDirectAccessGrantsEnabled()
                && !client.isImplicitFlowEnabled() && !client.isServiceAccountsEnabled()
                && disabled(client, OAuth2DeviceConfig.OAUTH2_DEVICE_AUTHORIZATION_GRANT_ENABLED) && disabled(client, CibaConfig.OIDC_CIBA_GRANT_ENABLED)
                && disabled(client, OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED) && disabled(client, OIDCConfigAttributes.JWT_AUTHORIZATION_GRANT_ENABLED)
                && client.validateSecret(secret));
    }
    private static boolean disabled(ClientModel client, String attribute) { String value = client.getAttribute(attribute); return value == null || "false".equals(value); }
}
