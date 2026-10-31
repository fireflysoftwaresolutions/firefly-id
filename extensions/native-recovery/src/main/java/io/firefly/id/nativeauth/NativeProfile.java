package io.firefly.id.nativeauth;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import java.util.Set;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeSecurity.*;

public record NativeProfile(String issuer, String population, String clientId, String tenantAttribute,
        String linkAttribute, String origin, String domainAudience, String coreAudience,
        String coreWorkloadClientId, String domainWorkloadClientId, int ttlSeconds) {
    private static final String PREFIX = "firefly.native-recovery.";
    public static NativeProfile of(RealmModel realm) {
        require(realm != null && !"master".equals(realm.getName()));
        String population = attribute(realm, "population");
        require(Set.of("HUMAN", "STAFF").contains(population));
        String origin = attribute(realm, "allowed-origin"); requireOrigin(origin, origin);
        String issuer = attribute(realm, "issuer");
        require(issuer.equals(origin + "/realms/" + realm.getName()));
        int ttl;
        try { ttl = Integer.parseInt(attribute(realm, "ttl-seconds")); } catch (Exception error) { throw new NativeRefusal(); }
        require(ttl > 0 && ttl <= ("STAFF".equals(population) ? 180 : 300));
        return new NativeProfile(issuer, population, attribute(realm, "client-id"), attribute(realm, "tenant-attribute"),
                attribute(realm, "link-attribute"), origin, attribute(realm, "domain-audience"),
                attribute(realm, "core-audience"), attribute(realm, "core-workload-client-id"),
                attribute(realm, "domain-workload-client-id"), ttl);
    }
    private static String attribute(RealmModel realm, String key) {
        String value = realm.getAttribute(PREFIX + key);
        require(value != null && !value.isBlank() && value.equals(value.strip()) && value.length() <= 512);
        return value;
    }
    public String tenant(UserModel user) { return single(user, tenantAttribute); }
    public String link(UserModel user) {
        String value = single(user, linkAttribute);
        try { require(UUID.fromString(value).toString().equals(value)); } catch (Exception error) { throw new NativeRefusal(); }
        return value;
    }
    private String single(UserModel user, String name) {
        var values = user.getAttributeStream(name).toList();
        require(values.size() == 1 && values.get(0) != null && !values.get(0).isBlank() && values.get(0).length() <= 512);
        return values.get(0);
    }
}
