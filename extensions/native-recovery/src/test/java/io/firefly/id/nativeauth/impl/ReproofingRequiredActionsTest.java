package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.*;
import jakarta.persistence.EntityManager;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingRequiredActionsTest {
    @Test void verifiedReplacementFulfillsOnlyItsPasswordAndTotpActionsOnActualJpaUserModel() throws Exception {
        Class<?> implementation;
        try { implementation = Class.forName("io.firefly.id.nativeauth.impl.ReproofingRequiredActionsImpl"); }
        catch (ClassNotFoundException missing) { fail("Missing fulfilled replacement required-action retirement"); return; }
        var entity = new UserEntity(); entity.setId("customer"); var em = mock(EntityManager.class);
        for (String name : Set.of("CONFIGURE_TOTP", "UPDATE_PASSWORD", "VERIFY_EMAIL", "bank-review-required")) {
            var action = new UserRequiredActionEntity(); action.setUser(entity); action.setAction(name); entity.getRequiredActions().add(action);
        }
        var user = new UserAdapter(mock(KeycloakSession.class), mock(RealmModel.class), em, entity);
        assertEquals(4, user.getRequiredActionsStream().count());
        implementation.getMethod("complete", UserModel.class).invoke(null, user);
        assertEquals(Set.of("VERIFY_EMAIL", "bank-review-required"), user.getRequiredActionsStream().collect(java.util.stream.Collectors.toSet()));
        verify(em, times(2)).remove(any(UserRequiredActionEntity.class));
    }
}
