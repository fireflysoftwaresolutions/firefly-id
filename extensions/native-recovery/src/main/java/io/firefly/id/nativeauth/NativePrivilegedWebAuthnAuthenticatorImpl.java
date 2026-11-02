package io.firefly.id.nativeauth;

import java.util.List;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.storage.StorageId;

/** Keycloak 26.8.1 verifies the assertion; this boundary prohibits privileged enrollment and downgrade. */
public final class NativePrivilegedWebAuthnAuthenticatorImpl extends WebAuthnAuthenticator {
    public NativePrivilegedWebAuthnAuthenticatorImpl(KeycloakSession session) { super(session); }

    @Override public void authenticate(AuthenticationFlowContext context) {
        if (!admitted(context)) { context.failure(AuthenticationFlowError.INVALID_CREDENTIALS); return; }
        super.authenticate(context);
    }

    @Override public void action(AuthenticationFlowContext context) {
        // Resumed submissions must not rely on the admission state used to render a previous challenge.
        if (!admitted(context)) { context.failure(AuthenticationFlowError.INVALID_CREDENTIALS); return; }
        super.action(context);
    }

    boolean admitted(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        UserModel identified = context.getUser();
        if (realm == null || identified == null || identified.getId() == null
                || !StorageId.isLocalStorage(identified.getId())
                || !"password-webauthn-uv-v1".equals(realm.getAttribute("firefly.privileged-administration"))
                || realm.getWebAuthnPolicy() == null
                || !"required".equals(realm.getWebAuthnPolicy().getUserVerificationRequirement())
                || realm.getWebAuthnPolicyPasswordless() == null
                || Boolean.TRUE.equals(realm.getWebAuthnPolicyPasswordless().isPasskeysEnabled())
                || context.getAuthenticationSession() == null
                || !hasPasswordEvidence(context)) return false;
        UserModel current = session.users().getUserById(realm, identified.getId());
        if (current == null || !current.isEnabled() || !current.isEmailVerified() || current.getId() == null
                || !StorageId.isLocalStorage(current.getId()) || !identified.getId().equals(current.getId())
                || current.getUsername() == null || current.getUsername().isBlank()
                || current.getFederationLink() != null || current.getServiceAccountClientLink() != null
                || current.isFederated() || current.isServiceAccount()
                || current.getRequiredActionsStream().findAny().isPresent()
                || !current.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_TWOFACTOR)) return false;
        context.setUser(current);
        return true;
    }

    private boolean hasPasswordEvidence(AuthenticationFlowContext context) {
        try {
            return AuthenticatorUtil.getAuthnCredentials(context.getAuthenticationSession()).contains(PasswordCredentialModel.TYPE);
        } catch (RuntimeException malformedEvidence) {
            return false;
        }
    }

    // Returning false lets the required-execution machinery schedule registration instead of authenticating.
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) { return List.of(); }
}
