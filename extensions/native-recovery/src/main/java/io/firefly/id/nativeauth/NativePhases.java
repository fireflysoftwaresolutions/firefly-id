package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import java.util.function.Function;
import static io.firefly.id.nativeauth.NativeSecurity.*;

/** A completed Keycloak transaction manager cannot be restarted; each phase owns a fresh session. */
public final class NativePhases {
    private NativePhases() { }
    public static <T> T run(KeycloakSession request, Function<KeycloakSession, T> work) {
        String realmId = request.getContext().getRealm().getId();
        if (request.getTransactionManager().isActive()) {
            require(!request.getTransactionManager().getRollbackOnly());
            request.getTransactionManager().commit();
        }
        return KeycloakModelUtils.runJobInTransactionWithResult(request.getKeycloakSessionFactory(), child -> {
            var realm = child.realms().getRealm(realmId); require(realm != null);
            child.getContext().setRealm(realm);
            return work.apply(child);
        });
    }
}
