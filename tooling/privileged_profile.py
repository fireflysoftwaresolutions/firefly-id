#!/usr/bin/env python3
"""Prepare or validate an offline Keycloak 26.8.1 privileged realm candidate; never contact a server."""
import argparse
import copy
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

PROFILE = 'password-webauthn-uv-v1'
BROWSER = 'firefly-privileged-browser-v1'
DENY = 'firefly-privileged-deny-v1'
ACTIONS = ('VERIFY_EMAIL', 'UPDATE_PROFILE', 'CONFIGURE_TOTP', 'UPDATE_PASSWORD',
           'TERMS_AND_CONDITIONS', 'delete_account', 'delete_credential', 'update_user_locale',
           'UPDATE_EMAIL', 'CONFIGURE_RECOVERY_AUTHN_CODES', 'webauthn-register',
           'webauthn-register-passwordless', 'VERIFY_PROFILE', 'idp_link')
BUILTIN_CLIENTS = {'account', 'account-console', 'admin-cli', 'broker', 'security-admin-console'}
# Explicit support is deliberately narrower than every possible Keycloak export/extension.
REALM_FIELDS = set('''id realm displayName displayNameHtml enabled sslRequired clients users roles groups
defaultSignatureAlgorithm maxSecondaryAuthFailures otpPolicyCodeReusable localizationTexts webAuthnPolicyPasswordlessMediation
scopeMappings clientScopeMappings defaultRole defaultGroups requiredCredentials passwordPolicy otpPolicyType
otpPolicyAlgorithm otpPolicyInitialCounter otpPolicyDigits otpPolicyLookAheadWindow otpPolicyPeriod otpSupportedApplications
webAuthnPolicyRpEntityName webAuthnPolicySignatureAlgorithms webAuthnPolicyRpId webAuthnPolicyAttestationConveyancePreference
webAuthnPolicyAuthenticatorAttachment webAuthnPolicyRequireResidentKey webAuthnPolicyResidentKey webAuthnPolicyUserVerificationRequirement
webAuthnPolicyCreateTimeout webAuthnPolicyAvoidSameAuthenticatorRegister webAuthnPolicyAcceptableAaguids webAuthnPolicyExtraOrigins
webAuthnPolicyPasswordlessRpEntityName webAuthnPolicyPasswordlessSignatureAlgorithms webAuthnPolicyPasswordlessRpId
webAuthnPolicyPasswordlessAttestationConveyancePreference webAuthnPolicyPasswordlessAuthenticatorAttachment
webAuthnPolicyPasswordlessRequireResidentKey webAuthnPolicyPasswordlessResidentKey webAuthnPolicyPasswordlessUserVerificationRequirement
webAuthnPolicyPasswordlessCreateTimeout webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister
webAuthnPolicyPasswordlessAcceptableAaguids webAuthnPolicyPasswordlessExtraOrigins webAuthnPolicyPasswordlessPasskeysEnabled
registrationAllowed registrationEmailAsUsername rememberMe verifyEmail loginWithEmailAllowed duplicateEmailsAllowed
resetPasswordAllowed editUsernameAllowed bruteForceProtected permanentLockout maxTemporaryLockouts
bruteForceStrategy maxFailureWaitSeconds minimumQuickLoginWaitSeconds waitIncrementSeconds quickLoginCheckMilliSeconds
maxDeltaTimeSeconds failureFactor attributes authenticationFlows authenticatorConfig requiredActions browserFlow
registrationFlow directGrantFlow resetCredentialsFlow clientAuthenticationFlow dockerAuthenticationFlow firstBrokerLoginFlow
identityProviders identityProviderMappers userFederationProviders userFederationMappers federatedUsers components
clientScopes defaultDefaultClientScopes defaultOptionalClientScopes clientPolicies clientProfiles
notBefore revokeRefreshToken refreshTokenMaxReuse accessTokenLifespan accessTokenLifespanForImplicitFlow
ssoSessionIdleTimeout ssoSessionMaxLifespan ssoSessionIdleTimeoutRememberMe ssoSessionMaxLifespanRememberMe
offlineSessionIdleTimeout offlineSessionMaxLifespanEnabled offlineSessionMaxLifespan clientSessionIdleTimeout
clientSessionMaxLifespan clientOfflineSessionIdleTimeout clientOfflineSessionMaxLifespan accessCodeLifespan
accessCodeLifespanUserAction accessCodeLifespanLogin actionTokenGeneratedByAdminLifespan actionTokenGeneratedByUserLifespan
oauth2DeviceCodeLifespan oauth2DevicePollingInterval smtpServer loginTheme accountTheme adminTheme emailTheme
browserSecurityHeaders eventsEnabled eventsListeners enabledEventTypes eventsExpiration adminEventsEnabled
adminEventsDetailsEnabled internationalizationEnabled supportedLocales defaultLocale keycloakVersion
userManagedAccessEnabled userManagedAccessAllowed organizationsEnabled verifiableCredentialsEnabled adminPermissionsEnabled
'''.split())
CLIENT_FIELDS = set('''id clientId name description rootUrl adminUrl baseUrl surrogateAuthRequired enabled alwaysDisplayInConsole
clientAuthenticatorType secret registrationAccessToken redirectUris webOrigins notBefore bearerOnly consentRequired
standardFlowEnabled implicitFlowEnabled directAccessGrantsEnabled serviceAccountsEnabled authorizationServicesEnabled
publicClient frontchannelLogout protocol attributes authenticationFlowBindingOverrides fullScopeAllowed nodeReRegistrationTimeout
registeredNodes protocolMappers defaultClientScopes optionalClientScopes access origin
'''.split())
SAFE_CLIENT_ATTRIBUTES = {
    'pkce.code.challenge.method': {'S256'}, 'realm_client': {'false', 'true'},
    'post.logout.redirect.uris': {'+'}, 'backchannel.logout.session.required': {'true'},
    'backchannel.logout.revoke.offline.tokens': {'true', 'false'},
    'oauth2.device.authorization.grant.enabled': {'false'}, 'oidc.ciba.grant.enabled': {'false'},
    'standard.token.exchange.enabled': {'false'}, 'oauth2.token.exchange.grant.enabled': {'false'},
    'use.refresh.tokens': {'true', 'false'}, 'client.use.lightweight.access.token.enabled': {'false'},
}

SOURCE_AUTHENTICATORS = set("""registration-page-form registration-user-creation registration-password-action
registration-recaptcha-action registration-terms-and-conditions reset-credentials-choose-user reset-credential-email
reset-password conditional-user-configured reset-otp direct-grant-validate-username direct-grant-validate-password
direct-grant-validate-otp auth-cookie auth-spnego auth-username-password-form conditional-credential auth-otp-form
webauthn-authenticator auth-recovery-authn-code-form identity-provider-redirector attestation-based client-secret
client-jwt client-secret-jwt client-x509 federated-jwt idp-review-profile idp-create-user-if-unique idp-confirm-link
idp-email-verification idp-username-password-form http-basic-authenticator docker-http-basic-authenticator
""".split())
SOURCE_CONFIGS = {
    'browser-conditional-credential': {'credentials': 'webauthn-passwordless'},
    'first-broker-login-conditional-credential': {'credentials': 'webauthn-passwordless'},
    'review profile config': {'update.profile.on.first.login': 'missing'},
    'create unique user config': {'require.password.update.after.registration': 'false'},
}


def existing_flows(document):
    flows = document.get('authenticationFlows', [])
    require(isinstance(flows, list), 'Authentication flow inventory required')
    aliases = [item.get('alias') for item in flows]
    require(len(set(aliases)) == len(aliases), 'Duplicate authentication flow alias refused')
    for item in flows:
        if item.get('alias') in (BROWSER, DENY):
            continue
        require(item.get('builtIn') is True and item.get('providerId') in ('basic-flow', 'client-flow', 'form-flow'),
                'Custom flow topology requires explicit review')
        for execution in item.get('authenticationExecutions', []):
            require(execution.get('authenticator') in SOURCE_AUTHENTICATORS or (
                    execution.get('authenticatorFlow') is True and execution.get('flowAlias') in aliases),
                    'Unsupported authenticator extension refused')
    for config in document.get('authenticatorConfig', []):
        require(config.get('alias') in SOURCE_CONFIGS and config.get('config') == SOURCE_CONFIGS[config['alias']],
                'Custom authenticator configuration requires explicit review')
    client_flow = document.get('clientAuthenticationFlow')
    if client_flow is not None:
        require(any(item.get('alias') == client_flow and item.get('providerId') == 'client-flow' for item in flows),
                'Client authentication flow binding is unsupported or dangling')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_document(content):
    def nonstandard_number(value):
        raise ValueError('Nonstandard JSON number refused')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON property refused')
            result[key] = value
        return result
    value = json.loads(content, object_pairs_hook=unique, parse_constant=nonstandard_number)
    require(isinstance(value, dict), 'Realm object required')
    return value


def origin_host(origin):
    require(isinstance(origin, str) and not any(ord(char) < 33 or ord(char) > 126 for char in origin)
            and not any(char in origin for char in ('\\', '@', '*', '%')), 'Exact HTTPS origin required')
    url = urlsplit(origin)
    require(url.scheme == 'https' and url.hostname and not url.path and not url.query and not url.fragment
            and not url.netloc.endswith(':'), 'Exact HTTPS origin without a path required')
    require(url.port is None or 1 <= url.port <= 65535, 'Invalid origin port')
    require(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', url.hostname) is not None,
            'DNS hostname required')
    require(origin == 'https://' + url.hostname + ((':' + str(url.port)) if url.port else ''),
            'Canonical HTTPS origin required')
    return url.hostname


def target(document, realm, origin):
    require(isinstance(realm, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', realm), 'Explicit realm required')
    require(document.get('realm') == realm, 'Realm does not match explicit target')
    hostname = origin_host(origin)
    require(document.get('enabled') is True and document.get('sslRequired') == 'all', 'Enabled TLS-only realm required')
    require(not (set(document) - REALM_FIELDS), 'Unsupported realm fields refused')
    return hostname


def internal_role_resource(document, client):
    realm = document['realm']
    name = client.get('clientId', '')
    identifier = (realm != 'master' and name == 'realm-management') or (
        realm == 'master' and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}-realm', name) is not None)
    roles = document.get('roles', {}).get('client', {}).get(name, [])
    return identifier and client.get('attributes', {}).get('realm_client') == 'true' and (
        {'view-realm', 'manage-realm'} <= {role.get('name') for role in roles})


def prerequisites(document, realm, origin, admin_origin=None):
    target(document, realm, origin)
    existing_flows(document)
    admin_origin = admin_origin or origin
    origin_host(admin_origin)
    require(document.get('verifyEmail') is True, 'Verified administrator email policy required')
    listeners = document.get('eventsListeners', [])
    require(isinstance(listeners, list) and 'jboss-logging' in listeners
            and set(listeners) <= {'jboss-logging', 'firefly-native-recovery-invalidation'},
            'Known retained event listeners required; custom audit collectors need explicit review')
    event_types = document.get('enabledEventTypes', [])
    require(isinstance(event_types, list) and (not event_types or {'LOGIN', 'LOGIN_ERROR'} <= set(event_types)),
            'Retained event selection must include sign-in successes and failures')
    for key in ('identityProviders', 'identityProviderMappers', 'userFederationProviders', 'userFederationMappers', 'federatedUsers'):
        require(not document.get(key), 'External identity or credential providers are unsupported')
    require(not document.get('userManagedAccessEnabled') and not document.get('userManagedAccessAllowed')
            and not document.get('organizationsEnabled')
            and not document.get('verifiableCredentialsEnabled'), 'Alternate authorization features are unsupported')
    require(not document.get('clientPolicies', {}).get('policies') and not document.get('clientProfiles', {}).get('profiles'),
            'Custom client policy/profile execution requires separate review')
    components = document.get('components', {})
    require(isinstance(components, dict) and set(components) <= {'org.keycloak.keys.KeyProvider'},
            'Only native signing-key components are supported')
    for component in components.get('org.keycloak.keys.KeyProvider', []):
        require(not component.get('subComponents'), 'Nested provider components are unsupported')
    attributes = document.get('attributes', {})
    require(isinstance(attributes, dict) and set(attributes) <= {'firefly.privileged-administration'},
            'Realm extension attributes require explicit review')
    clients = document.get('clients')
    require(isinstance(clients, list) and clients, 'Complete client inventory required')
    ids = [client.get('clientId') for client in clients]
    require(len(set(ids)) == len(ids) and BUILTIN_CLIENTS <= set(ids), 'Complete unique built-in client inventory required')
    for client in clients:
        require(not (set(client) - CLIENT_FIELDS), 'Unsupported client fields refused')
        require(client.get('protocol') == 'openid-connect', 'Only OIDC clients are supported')
        for key in ('directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled', 'authorizationServicesEnabled'):
            require(client.get(key, False) is False, 'Client alternate grant or service account must already be disabled')
        require(not client.get('authenticationFlowBindingOverrides'), 'Client authentication-flow override refused')
        attrs = client.get('attributes', {})
        require(isinstance(attrs, dict) and all(key in SAFE_CLIENT_ATTRIBUTES and value in SAFE_CLIENT_ATTRIBUTES[key]
                                               for key, value in attrs.items()), 'Unsupported client attributes refused')
        require(isinstance(client.get('defaultClientScopes'), list) and isinstance(client.get('optionalClientScopes'), list),
                'Explicit client scope inventory required')
        require('offline_access' not in client.get('defaultClientScopes', [])
                and 'offline_access' not in client.get('optionalClientScopes', []), 'Offline access is outside this profile')
        if client['clientId'] == 'security-admin-console':
            require(client.get('enabled') is True and client.get('standardFlowEnabled') is True
                    and client.get('publicClient') is True and not client.get('bearerOnly'), 'Enabled public console code flow required')
            require(attrs.get('pkce.code.challenge.method') == 'S256', 'Console PKCE S256 required')
            require(client.get('redirectUris') == [admin_origin + '/admin/' + realm + '/console/*']
                    and client.get('webOrigins') == [admin_origin], 'Exact administrative console origin and redirect required')
        elif internal_role_resource(document, client):
            require(client.get('bearerOnly') is True and client.get('publicClient') is False,
                    'Internal administrative role resource must remain confidential and bearer-only')
        else:
            require(client.get('enabled') is False or (client.get('bearerOnly') is True
                    and client.get('standardFlowEnabled') is False), 'Other interactive clients must already be disabled')
    users = document.get('users')
    require(isinstance(users, list) and users, 'Full pre-enrolled local user inventory required')
    require(len({user.get('username') for user in users}) == len(users), 'Unique named account inventory required')
    enabled = 0
    for user in users:
        require(not user.get('federationLink') and not user.get('federatedIdentities') and not user.get('serviceAccountClientId'),
                'Only named local nonservice users are supported')
        require(not user.get('requiredActions'), 'Outstanding user required actions must be resolved before transition')
        if user.get('enabled') is True:
            enabled += 1
            require(user.get('emailVerified') is True, 'Previously verified administrator email required')
            require(isinstance(user.get('username'), str) and user['username'].strip(), 'Named account required')
            credentials = user.get('credentials', [])
            require({'password', 'webauthn'} <= {credential.get('type') for credential in credentials}
                    and not any(credential.get('temporary') for credential in credentials),
                    'Existing permanent password and two-factor WebAuthn enrollment required')
    require(enabled > 0, 'At least one enabled pre-enrolled account required')
    for action in document.get('requiredActions', []):
        require(action.get('alias') in ACTIONS and action.get('providerId') == action.get('alias'),
                'Unsupported required-action provider refused')


def flow(alias, authenticators):
    return {'alias': alias, 'providerId': 'basic-flow', 'topLevel': True, 'builtIn': False,
            'authenticationExecutions': [
                {'authenticator': authenticator, 'authenticatorFlow': False, 'requirement': 'REQUIRED', 'priority': 10 * (i + 1)}
                for i, authenticator in enumerate(authenticators)]}


def controls(hostname):
    return {
        'attributes': {'firefly.privileged-administration': PROFILE},
        'registrationAllowed': False, 'resetPasswordAllowed': False, 'rememberMe': False,
        'registrationEmailAsUsername': False, 'editUsernameAllowed': False, 'verifyEmail': True,
        'browserFlow': BROWSER, 'directGrantFlow': DENY, 'registrationFlow': DENY,
        'resetCredentialsFlow': DENY, 'dockerAuthenticationFlow': DENY, 'firstBrokerLoginFlow': DENY,
        'authenticationFlows': [flow(BROWSER, ['auth-username-password-form', 'firefly-privileged-webauthn']),
                                flow(DENY, ['deny-access-authenticator'])],
        'requiredActions': [{'alias': action, 'providerId': action, 'name': action, 'enabled': False,
                             'defaultAction': False, 'priority': i * 10, 'config': {}}
                            for i, action in enumerate(ACTIONS)],
        'webAuthnPolicyRpId': hostname, 'webAuthnPolicyUserVerificationRequirement': 'required',
        'webAuthnPolicyExtraOrigins': [], 'webAuthnPolicyPasswordlessPasskeysEnabled': False,
        'eventsEnabled': True, 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False,
    }


def build_profile(document, *, realm, origin, admin_origin=None, acknowledge_master=False):
    require(realm != 'master' or acknowledge_master is True, 'Master candidate requires explicit acknowledgment')
    prerequisites(document, realm, origin, admin_origin)
    candidate = copy.deepcopy(document)
    candidate.update(controls(target(document, realm, origin)))
    candidate['authenticationFlows'] += copy.deepcopy([item for item in document.get('authenticationFlows', [])
                                                       if item.get('alias') not in (BROWSER, DENY)])
    validate_profile(candidate, realm=realm, origin=origin, admin_origin=admin_origin)
    return candidate


def validate_profile(document, *, realm, origin, admin_origin=None):
    prerequisites(document, realm, origin, admin_origin)
    expected = controls(target(document, realm, origin))
    for key, value in expected.items():
        if key == 'authenticationFlows':
            selected = [item for item in document.get(key, []) if item.get('alias') in (BROWSER, DENY)]
            require(selected == value, 'Privileged flow topology differs from the reviewed profile')
        else:
            require(document.get(key) == value, 'Privileged realm control differs from the reviewed profile: ' + key)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('generate', 'validate'))
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--realm', required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--admin-origin')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--acknowledge-master', action='store_true')
    args = parser.parse_args()
    try:
        document = parse_document(args.input.read_text())
        if args.mode == 'generate':
            require(args.output is not None, 'A new output path is required')
            candidate = build_profile(document, realm=args.realm, origin=args.origin,
                                      admin_origin=args.admin_origin, acknowledge_master=args.acknowledge_master)
            # Exports can contain credential material. Never overwrite or print their contents.
            import os
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                json.dump(candidate, output, indent=2)
                output.write('\n')
        else:
            validate_profile(document, realm=args.realm, origin=args.origin, admin_origin=args.admin_origin)
    except (ValueError, TypeError, KeyError, AttributeError, OSError):
        parser.exit(2, 'Privileged profile refused; inspect the offline input against the documented prerequisites.\n')
    print('Offline privileged profile ' + ('prepared' if args.mode == 'generate' else 'validated') + '; no server was contacted.')


if __name__ == '__main__':
    main()
