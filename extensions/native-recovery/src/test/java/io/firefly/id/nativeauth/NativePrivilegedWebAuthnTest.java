package io.firefly.id.nativeauth;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativePrivilegedWebAuthnTest {
    private final KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class, RETURNS_DEEP_STUBS);
    private final RealmModel realm = mock(RealmModel.class, RETURNS_DEEP_STUBS);
    private final UserModel user = mock(UserModel.class, RETURNS_DEEP_STUBS);
    private NativePrivilegedWebAuthnAuthenticatorImpl authenticator;

    @BeforeEach void prepare() {
        authenticator = new NativePrivilegedWebAuthnAuthenticatorImpl(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(user.getId()).thenReturn("named-local-administrator");
        when(user.getUsername()).thenReturn("named-administrator");
        when(user.isEnabled()).thenReturn(true);
        when(user.isEmailVerified()).thenReturn(true);
        when(session.users().getUserById(realm, user.getId())).thenReturn(user);
        when(realm.getAttribute("firefly.privileged-administration")).thenReturn("password-webauthn-uv-v1");
        when(realm.getWebAuthnPolicy().getUserVerificationRequirement()).thenReturn("required");
        when(context.getAuthenticationSession().getAuthNote(AuthenticationProcessor.AUTHN_CREDENTIALS))
                .thenReturn("[\"password\"]");
        when(user.credentialManager().isConfiguredFor("webauthn")).thenReturn(true);
        when(user.getRequiredActionsStream()).thenAnswer(call -> java.util.stream.Stream.empty());
    }

    @Test void unconfiguredUserNeverEntersAutomaticSetup() {
        when(user.credentialManager().isConfiguredFor("webauthn")).thenReturn(false);
        assertTrue(authenticator.configuredFor(session, realm, user));
        authenticator.setRequiredActions(session, realm, user);
        assertEquals(List.of(), authenticator.getRequiredActions(session));
        verify(user, never()).addRequiredAction(anyString());
        verify(context.getAuthenticationSession(), never()).addRequiredAction(anyString());
        authenticator.authenticate(context);
        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        verify(context, never()).challenge(any());
        verify(context, never()).success(anyString());
    }

    @Test void passwordlessCredentialDoesNotSatisfySecondFactor() {
        when(user.credentialManager().isConfiguredFor("webauthn")).thenReturn(false);
        when(user.credentialManager().isConfiguredFor("webauthn-passwordless")).thenReturn(true);
        assertFalse(authenticator.admitted(context));
    }

    @Test void validPreEnrolledNamedUserWithPasswordAndRequiredUvIsAdmitted() {
        assertTrue(authenticator.admitted(context));
        verify(context).setUser(user);
    }

    @Test void actionRechecksEnrollmentAfterChallengeInsteadOfSchedulingSetup() {
        assertTrue(authenticator.admitted(context));
        when(user.credentialManager().isConfiguredFor("webauthn")).thenReturn(false);
        authenticator.action(context);
        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        verify(context, never()).getHttpRequest();
        verify(context, never()).success(anyString());
        verify(user, never()).addRequiredAction(anyString());
    }

    @Test void actionRechecksLivePolicyAndUserStateOnResumedFlow() {
        assertTrue(authenticator.admitted(context));
        when(realm.getWebAuthnPolicy().getUserVerificationRequirement()).thenReturn("preferred");
        authenticator.action(context);
        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        verify(context, never()).getHttpRequest();
    }

    @Test void missingPasswordEvidenceAndPasswordlessEvidenceRefuse() {
        for (String evidence : new String[] { null, "[]", "[\"webauthn-passwordless\"]", "[\"otp\"]", "{}", "null", "[1]", "invalid" }) {
            when(context.getAuthenticationSession().getAuthNote(AuthenticationProcessor.AUTHN_CREDENTIALS)).thenReturn(evidence);
            assertFalse(authenticator.admitted(context));
        }
    }

    @Test void disabledUserOrUnverifiedEmailCannotSubmitAResumedAssertion() {
        when(user.isEnabled()).thenReturn(false);
        authenticator.action(context);
        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        verify(context, never()).getHttpRequest();
        when(user.isEnabled()).thenReturn(true);
        when(user.isEmailVerified()).thenReturn(false);
        assertFalse(authenticator.admitted(context));
    }

    @Test void refreshedDisabledDeletedAndForeignUsersRefuse() {
        UserModel changed = mock(UserModel.class);
        when(session.users().getUserById(realm, user.getId())).thenReturn(changed);
        assertFalse(authenticator.admitted(context));
        when(session.users().getUserById(realm, user.getId())).thenReturn(null);
        assertFalse(authenticator.admitted(context));
        when(session.users().getUserById(realm, user.getId())).thenReturn(user);
        when(user.getFederationLink()).thenReturn("external-store");
        assertFalse(authenticator.admitted(context));
        when(user.getFederationLink()).thenReturn(null);
        when(user.getServiceAccountClientLink()).thenReturn("workload");
        assertFalse(authenticator.admitted(context));
    }

    @Test void unreviewedRequiredActionCannotRunAfterPrivilegedLogin() {
        when(user.getRequiredActionsStream()).thenAnswer(call -> java.util.stream.Stream.of("webauthn-register"));
        assertFalse(authenticator.admitted(context));
    }

    @Test void missingOptInAndPasskeyPasswordSubstitutionRefuse() {
        when(realm.getAttribute("firefly.privileged-administration")).thenReturn(null);
        assertFalse(authenticator.admitted(context));
        when(realm.getAttribute("firefly.privileged-administration")).thenReturn("password-webauthn-uv-v1");
        when(realm.getWebAuthnPolicyPasswordless().isPasskeysEnabled()).thenReturn(true);
        assertFalse(authenticator.admitted(context));
    }

    @Test void factoryExposesOnlyRequiredExecutionWithoutUserSetup() {
        var factory = new NativePrivilegedWebAuthnFactoryImpl();
        assertEquals("firefly-privileged-webauthn", factory.getId());
        assertFalse(factory.isUserSetupAllowed());
        assertArrayEquals(new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED },
                factory.getRequirementChoices());
        assertInstanceOf(NativePrivilegedWebAuthnAuthenticatorImpl.class, factory.create(session));
    }
}
