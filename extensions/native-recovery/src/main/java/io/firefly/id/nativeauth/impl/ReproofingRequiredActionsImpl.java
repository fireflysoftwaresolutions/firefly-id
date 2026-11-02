package io.firefly.id.nativeauth.impl;

import org.keycloak.models.UserModel;

public final class ReproofingRequiredActionsImpl {
    private ReproofingRequiredActionsImpl() { }
    public static void complete(UserModel user) {
        user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.name());
        user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD.name());
    }
}
