package io.firefly.id.nativeauth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public final class NativePrivilegedWebAuthnFactoryImpl extends WebAuthnAuthenticatorFactory {
    @Override public String getId() { return "firefly-privileged-webauthn"; }
    @Override public String getDisplayType() { return "Firefly privileged WebAuthn"; }
    @Override public String getHelpText() { return "Pre-enrolled local named account, password and required WebAuthn user verification."; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED };
    }
    @Override public Authenticator create(KeycloakSession session) { return new NativePrivilegedWebAuthnAuthenticatorImpl(session); }
}
