package io.firefly.id.nativeauth.impl;

import org.keycloak.models.RealmModel;
import java.net.URI;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class ReproofingConfigImpl {
    final RealmModel realm;
    ReproofingConfigImpl(RealmModel realm) {
        this.realm = realm;
        require("true".equals(realm.getAttribute("firefly.reproofing.enabled")) && !"master".equals(realm.getName()) && "HUMAN".equals(value("population")));
        requireOrigin(value("allowed-origin"), value("allowed-origin"));
        require(value("issuer").equals(value("allowed-origin") + "/realms/" + realm.getName()));
        require(!value("core-workload-client-id").equals(value("domain-workload-client-id")));
        require(ttl() > 0 && ttl() <= 600);
    }
    String value(String key) { String value = realm.getAttribute("firefly.reproofing." + key); require(value != null && !value.isBlank() && value.equals(value.strip()) && value.length() <= 512); return value; }
    int ttl() { return Integer.parseInt(value("ttl-seconds")); }
    String root() { return value("issuer") + "/firefly-recovery/lost-credentials"; }
    static URI origin(String value) { URI uri = URI.create(value); require("https".equals(uri.getScheme()) && uri.getHost() != null && uri.getRawUserInfo() == null && uri.getRawQuery() == null && uri.getRawFragment() == null && (uri.getPath().isEmpty() || "/".equals(uri.getPath()))); return uri; }
}
