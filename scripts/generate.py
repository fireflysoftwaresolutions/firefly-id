#!/usr/bin/env python3
"""Create a new, explicitly synthetic sandbox. Never overwrite retained state."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROFILE_TYPE = 'org.keycloak.userprofile.UserProfileProvider'
POLICIES_PATH = ROOT / 'config/authentication-policies.json'


def write(path, content, mode=0o644):
    path.write_text(content)
    path.chmod(mode)


def authentication_policy(kind):
    policies = json.loads(POLICIES_PATH.read_text())
    if policies['schemaVersion'] != 1:
        raise ValueError('Unsupported authentication policy schema')
    selected = policies['profiles'][kind]
    return {**policies['defaults'], **selected['realmSettings']}, selected['mfaRequired']


def workforce_browser_flows():
    return [
        {'alias': 'firefly-workforce-browser', 'providerId': 'basic-flow',
         'description': 'Workforce session or mandatory password and OTP',
         'topLevel': True, 'builtIn': False,
         'authenticationExecutions': [
             {'authenticator': 'auth-cookie', 'authenticatorFlow': False,
              'requirement': 'ALTERNATIVE', 'priority': 10},
             {'flowAlias': 'firefly-workforce-forms', 'authenticatorFlow': True,
              'requirement': 'ALTERNATIVE', 'priority': 20}]},
        {'alias': 'firefly-workforce-forms', 'providerId': 'basic-flow',
         'description': 'Workforce password and required OTP, including enrollment',
         'topLevel': False, 'builtIn': False,
         'authenticationExecutions': [
             {'authenticator': 'auth-username-password-form', 'authenticatorFlow': False,
              'requirement': 'REQUIRED', 'priority': 10},
             {'authenticator': 'auth-otp-form', 'authenticatorFlow': False,
              'requirement': 'REQUIRED', 'priority': 20}]},
    ]


def profile():
    attributes = [
        {'name': 'username', 'required': {'roles': ['admin', 'user']},
         'permissions': {'view': ['admin', 'user'], 'edit': ['admin']},
         'validations': {'length': {'min': 3, 'max': 255}}},
        {'name': 'email', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin', 'user']},
         'validations': {'email': {}, 'length': {'max': 254}}},
        {'name': 'firstName', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin', 'user']},
         'validations': {'length': {'max': 100}}},
        {'name': 'lastName', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin', 'user']},
         'validations': {'length': {'max': 100}}},
    ]
    for name in ('tenant_id', 'party_id', 'staff_actor_id'):
        attributes.append({'name': name, 'multivalued': False,
                           'permissions': {'view': ['admin'], 'edit': ['admin']},
                           'validations': {'length': {'max': 128}}})
    # In pinned UPConfig, null disables unmanaged attributes; DISABLED is only a UI label.
    return {'unmanagedAttributePolicy': None, 'attributes': attributes}


def client(client_id, port, kind, secret=None):
    result = {
        'clientId': client_id, 'name': 'Provisional sandbox example: ' + client_id,
        'protocol': 'openid-connect', 'enabled': True, 'publicClient': secret is None,
        'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
        'implicitFlowEnabled': False, 'serviceAccountsEnabled': False,
        'fullScopeAllowed': False,
        'redirectUris': [f'http://localhost:{port}/oidc/callback'],
        'webOrigins': [f'http://localhost:{port}'] if secret is None else [],
        'attributes': {'pkce.code.challenge.method': 'S256',
                       'post.logout.redirect.uris': f'http://localhost:{port}/signed-out',
                       'oauth2.device.authorization.grant.enabled': 'false',
                       'oidc.ciba.grant.enabled': 'false'},
        'defaultClientScopes': ['basic', 'profile', 'email'], 'optionalClientScopes': [],
        'protocolMappers': [
            {'name': name, 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-usermodel-attribute-mapper',
             'consentRequired': False,
             'config': {'user.attribute': name, 'claim.name': name, 'jsonType.label': 'String',
                        'id.token.claim': 'false', 'access.token.claim': 'true',
                        'userinfo.token.claim': 'false', 'multivalued': 'false'}}
            for name in ('tenant_id', 'staff_actor_id' if kind == 'workforce' else 'party_id')
        ] + [
            {'name': name, 'protocol': 'openid-connect',
             'protocolMapper': 'oidc-hardcoded-claim-mapper', 'consentRequired': False,
             'config': {'claim.name': name, 'claim.value': value, 'jsonType.label': 'String',
                        'id.token.claim': 'false', 'access.token.claim': 'true',
                        'userinfo.token.claim': 'false'}}
            for name, value in [('principal_kind', 'STAFF' if kind == 'workforce' else 'HUMAN'),
                                ('client_id', client_id)]
        ] + [{'name': 'sandbox-api-audience', 'protocol': 'openid-connect',
              'protocolMapper': 'oidc-audience-mapper', 'consentRequired': False,
              'config': {'included.custom.audience': 'sandbox-api',
                         'id.token.claim': 'false', 'access.token.claim': 'true'}}],
    }
    if secret is not None:
        result['secret'] = secret
        result['clientAuthenticatorType'] = 'client-secret'
    return result


def receiver_client(secret):
    return {
        'clientId': 'sandbox-api', 'name': 'Synthetic audience-bound introspection receiver',
        'protocol': 'openid-connect', 'enabled': True, 'publicClient': False,
        'clientAuthenticatorType': 'client-secret', 'secret': secret,
        'standardFlowEnabled': False, 'directAccessGrantsEnabled': False,
        'implicitFlowEnabled': False, 'serviceAccountsEnabled': False,
        'fullScopeAllowed': False, 'redirectUris': [], 'webOrigins': [],
        'defaultClientScopes': [], 'optionalClientScopes': [], 'protocolMappers': [],
        'attributes': {'oauth2.device.authorization.grant.enabled': 'false',
                       'oidc.ciba.grant.enabled': 'false'},
    }


def configuration_lookup_client(client_id, tenant, secret):
    result = receiver_client(secret)
    audience = result['clientId']
    result.update({'clientId': client_id, 'name': 'Optional synthetic Configuration lookup service',
                   'serviceAccountsEnabled': True, 'authorizationServicesEnabled': False,
                   'defaultClientScopes': ['basic']})
    result['attributes']['standard.token.exchange.enabled'] = 'false'
    result['protocolMappers'] = [
        {'name': name, 'protocol': 'openid-connect', 'protocolMapper': 'oidc-hardcoded-claim-mapper',
         'consentRequired': False,
         'config': {'claim.name': name, 'claim.value': value, 'jsonType.label': 'String',
                    'id.token.claim': 'false', 'access.token.claim': 'true', 'userinfo.token.claim': 'false'}}
        for name, value in [('tenant_id', tenant), ('client_id', client_id), ('principal_kind', 'MACHINE')]
    ]
    result['protocolMappers'].append({
        'name': 'configuration-receiver-audience', 'protocol': 'openid-connect',
        'protocolMapper': 'oidc-audience-mapper', 'consentRequired': False,
        'config': {'included.custom.audience': audience, 'id.token.claim': 'false', 'access.token.claim': 'true'}})
    return result


def realm(kind, password, backend_secret, verification_password=None, policy_fixture=None, receiver_secret=None):
    name = 'sandbox-' + kind
    attrs = {'tenant_id': ['synthetic-tenant']}
    if kind == 'workforce':
        attrs['staff_actor_id'] = [str(uuid.uuid4())]
    else:
        attrs['party_id'] = [str(uuid.uuid4())]
    result = {
        'realm': name, 'displayName': 'Firefly Identity · ' + kind + ' sandbox',
        'enabled': True, 'sslRequired': 'none',
        'registrationAllowed': False, 'registrationEmailAsUsername': False,
        'editUsernameAllowed': False, 'resetPasswordAllowed': True,
        'rememberMe': False, 'verifyEmail': True, 'loginWithEmailAllowed': True,
        'duplicateEmailsAllowed': False, 'accessTokenLifespan': 300,
        'ssoSessionIdleTimeout': 1800, 'ssoSessionMaxLifespan': 28800,
        'revokeRefreshToken': True, 'refreshTokenMaxReuse': 0,
        'loginTheme': 'firefly-id', 'accountTheme': 'firefly-id',
        'adminTheme': 'firefly-id', 'emailTheme': 'firefly-id',
        'internationalizationEnabled': True, 'supportedLocales': ['en', 'es'],
        'defaultLocale': 'en',
        'eventsEnabled': True, 'eventsExpiration': 604800,
        'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False,
        'smtpServer': {'host': 'mailpit', 'port': '1025', 'from': 'identity@example.invalid',
                       'fromDisplayName': 'Firefly Identity Sandbox', 'auth': 'false',
                       'ssl': 'false', 'starttls': 'false'},
        'components': {PROFILE_TYPE: [{'providerId': 'declarative-user-profile',
                                     'config': {'kc.user.profile.config': [json.dumps(profile())]}}]},
        'clients': [client('sandbox-web', 3000, kind), client('sandbox-backend', 8081, kind, backend_secret)],
        'users': [{'username': 'synthetic-' + kind, 'email': kind + '@example.invalid',
                   'enabled': True, 'emailVerified': True, 'firstName': 'Synthetic',
                   'lastName': kind.capitalize(), 'attributes': attrs,
                   'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}],
    }
    if receiver_secret is not None:
        result['clients'].append(receiver_client(receiver_secret))
    policy, mfa_required = authentication_policy(kind)
    result.update(policy)
    if mfa_required:
        result.update({'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1',
                       'otpPolicyDigits': 6, 'otpPolicyPeriod': 30,
                       'otpPolicyLookAheadWindow': 1, 'otpPolicyCodeReusable': False,
                       'browserFlow': 'firefly-workforce-browser',
                       'authenticationFlows': workforce_browser_flows()})
        result['users'][0]['requiredActions'] = ['CONFIGURE_TOTP']
    if policy_fixture is not None:
        linkage = 'staff_actor_id' if kind == 'workforce' else 'party_id'
        result['users'].append({
            'username': policy_fixture['username'], 'email': policy_fixture['email'],
            'enabled': True, 'emailVerified': True, 'firstName': 'Synthetic',
            'lastName': 'Policy fixture',
            'attributes': {'tenant_id': ['synthetic-tenant'], linkage: [str(uuid.uuid4())]},
            'credentials': [{'type': 'password', 'value': policy_fixture['password'], 'temporary': False}],
        })
    if kind == 'customers' and verification_password is not None:
        result['users'].append({
            'username': 'synthetic-verify-email', 'email': 'verify-email@example.invalid',
            'enabled': True, 'emailVerified': False, 'firstName': 'Synthetic',
            'lastName': 'Verification', 'requiredActions': ['VERIFY_EMAIL'],
            'attributes': {'tenant_id': ['synthetic-tenant'], 'party_id': [str(uuid.uuid4())]},
            'credentials': [{'type': 'password', 'value': verification_password, 'temporary': False}],
        })
    # Realm import intentionally bypasses automatic default-role assignment upstream.
    # These native account roles permit self service only, with no business/admin grant.
    for user in result['users']:
        user['clientRoles'] = {'account': ['manage-account', 'view-profile']}
    return result


def compose(output, project, theme_dir):
    images = json.loads((ROOT / 'deploy/images.lock.json').read_text())
    def mount(source, target, readonly=True):
        return {'type': 'bind', 'source': str(source), 'target': target, 'read_only': readonly}
    common = {'restart': 'no', 'security_opt': ['no-new-privileges:true'],
              'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
    return {
        'name': project,
        'services': {
            'postgres': {**common, 'image': images['postgres']['image'],
                         'environment': {'POSTGRES_USER': 'bootstrap_admin',
                                         'POSTGRES_DB': 'postgres',
                                         'POSTGRES_PASSWORD_FILE': '/run/secrets/postgres-admin-password'},
                         'secrets': ['postgres-admin-password', 'db-password'],
                         'volumes': ['database:/var/lib/postgresql/data',
                                     mount(ROOT / 'deploy/postgres/init.sh', '/docker-entrypoint-initdb.d/10-firefly-id.sh')],
                         'healthcheck': {'test': ['CMD-SHELL', 'pg_isready -U bootstrap_admin -d postgres'],
                                         'interval': '5s', 'timeout': '3s', 'retries': 24},
                         'mem_limit': '512m', 'networks': ['identity']},
            'mailpit': {**common, 'image': images['mailpit']['image'],
                        'environment': {'MP_MAX_MESSAGES': '100', 'MP_MAX_AGE': '24h'},
                        'ports': ['127.0.0.1:8025:8025'], 'mem_limit': '128m',
                        'networks': ['identity', 'ingress']},
            'keycloak': {**common, 'image': images['keycloak']['image'],
                         'entrypoint': ['/bin/bash', '/opt/firefly/entrypoint.sh'],
                         'command': ['start', '--import-realm', '--spi-theme--default=firefly-id'],
                         'environment': {'KC_DB': 'postgres', 'KC_DB_URL_HOST': 'postgres',
                                         'KC_DB_URL_DATABASE': 'firefly_id', 'KC_DB_USERNAME': 'firefly_id',
                                         'KC_HTTP_ENABLED': 'true', 'KC_HTTP_PORT': '8180',
                                         'KC_HOSTNAME': 'http://id.firefly.test:8180',
                                         'KC_HOSTNAME_STRICT': 'true', 'KC_HOSTNAME_BACKCHANNEL_DYNAMIC': 'true',
                                         'KC_HEALTH_ENABLED': 'true', 'KC_METRICS_ENABLED': 'true',
                                         'KC_HTTP_MANAGEMENT_SCHEME': 'http',
                                         'KC_BOOTSTRAP_ADMIN_USERNAME': 'sandbox-bootstrap',
                                         'JAVA_OPTS_KC_HEAP': '-Xms128m -Xmx512m'},
                         'secrets': ['db-password', 'admin-password'],
                         'volumes': [mount(ROOT / 'deploy/keycloak-entrypoint.sh', '/opt/firefly/entrypoint.sh'),
                                     mount(output / 'realms', '/opt/keycloak/data/import'),
                                     mount(ROOT / 'config/password-blacklist.txt',
                                           '/opt/keycloak/data/password-blacklists/firefly-baseline.txt'),
                                     mount(theme_dir, '/opt/keycloak/themes/firefly-id')],
                         'ports': ['127.0.0.1:8180:8180', '127.0.0.1:9000:9000'],
                         'depends_on': {'postgres': {'condition': 'service_healthy'},
                                        'mailpit': {'condition': 'service_started'}},
                         'healthcheck': {'test': ['CMD', 'bash', '-ec',
                             "{ printf 'HEAD /health/ready HTTP/1.0\\r\\n\\r\\n' >&0; grep 'HTTP/1.0 200'; } 0<>/dev/tcp/localhost/9000"],
                             'interval': '10s', 'timeout': '5s', 'retries': 30, 'start_period': '60s'},
                         'mem_limit': '1g', 'networks': {'identity': {'aliases': ['id.firefly.test']}, 'ingress': {}}},
        },
        'secrets': {name: {'file': str(output / 'secrets' / name)} for name in
                    ('postgres-admin-password', 'db-password', 'admin-password')},
        'volumes': {'database': {'labels': {'org.firefly-id.owner': project}}},
        'networks': {'identity': {'internal': True, 'labels': {'org.firefly-id.owner': project}},
                     'ingress': {'labels': {'org.firefly-id.owner': project}}},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['sandbox', 'production'], required=True)
    parser.add_argument('--output', type=Path, default=ROOT / '.state/sandbox')
    parser.add_argument('--theme-dir', type=Path, default=ROOT / 'dist/themes/firefly-id')
    parser.add_argument('--configuration-lookup-client-id')
    parser.add_argument('--configuration-lookup-realm', choices=['customers', 'workforce', 'institutions'])
    parser.add_argument('--configuration-lookup-tenant')
    args = parser.parse_args()
    if args.mode == 'production':
        parser.error('Production contract is not selected. Approve realm/client/claim and deployment contracts first; no production generator is enabled.')
    lookup = (args.configuration_lookup_client_id, args.configuration_lookup_realm, args.configuration_lookup_tenant)
    if any(value is not None for value in lookup):
        if not all(value is not None for value in lookup):
            parser.error('Configuration lookup provisioning requires explicit client ID, realm and opaque tenant.')
        if (not re.fullmatch(r'[a-z][a-z0-9.-]{2,79}', lookup[0])
                or lookup[0] in {'sandbox-api', 'sandbox-web', 'sandbox-backend', 'account', 'account-console',
                                 'admin-cli', 'security-admin-console', 'realm-management', 'broker'}):
            parser.error('Configuration lookup requires a distinct nonreserved client ID.')
        if (not lookup[2] or lookup[2] != lookup[2].strip() or len(lookup[2].encode('utf-8')) > 1024
                or any(ord(char) < 32 or ord(char) == 127 for char in lookup[2])):
            parser.error('Configuration lookup requires a bounded, control-free opaque tenant.')
    theme_dir = args.theme_dir.resolve()
    if not all((theme_dir / kind / 'theme.properties').is_file()
               for kind in ('login', 'account', 'admin', 'email', 'welcome')):
        parser.error('Build theme first: python3 tooling/build_theme.py (missing built theme at ' + str(theme_dir) + ')')
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('Output already exists; preserve retained secrets and database. Choose a new empty path.')
    for kind in ('customers', 'workforce', 'institutions', 'administrators'):
        authentication_policy(kind)
    if not (ROOT / 'config/password-blacklist.txt').is_file():
        parser.error('Required baseline password denylist is missing; no state was generated.')
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    for directory in ('secrets', 'realms'):
        (output / directory).mkdir(mode=0o700)
    project = 'firefly-id-sandbox-' + uuid.uuid4().hex[:10]
    for name in ('postgres-admin-password', 'db-password', 'admin-password'):
        write(output / 'secrets' / name, secrets.token_urlsafe(36) + '\n')
    verification_password = 'Aa1' + secrets.token_urlsafe(36)
    credentials = {'verify_email': {'username': 'synthetic-verify-email',
                                    'password': verification_password}}
    write(output / 'secrets/workforce-totp.json',
          json.dumps({'status': 'pending-enrollment'}) + '\n', 0o600)
    for kind in ('customers', 'workforce', 'institutions'):
        password = 'Aa1' + secrets.token_urlsafe(36)
        backend_secret = secrets.token_urlsafe(36)
        receiver_secret = secrets.token_urlsafe(36)
        policy_fixture = None
        if kind in ('customers', 'workforce'):
            policy_fixture = {'username': 'synthetic-policy-' + kind,
                              'email': 'policy-' + kind + '@example.invalid',
                              'password': 'Aa1' + secrets.token_urlsafe(36)}
            credentials['policy_' + kind] = policy_fixture
        realm_data = realm(kind, password, backend_secret, verification_password, policy_fixture, receiver_secret)
        if kind == args.configuration_lookup_realm:
            lookup_secret = secrets.token_urlsafe(48)
            realm_data['clients'].append(configuration_lookup_client(lookup[0], lookup[2], lookup_secret))
            write(output / 'secrets/configuration-lookup-client-secret', lookup_secret + '\n', 0o600)
            issuer = f'http://id.firefly.test:8180/realms/sandbox-{kind}'
            write(output / 'configuration-lookup-client.json', json.dumps({
                'status': 'configured-not-issued', 'issuer': issuer, 'client_id': lookup[0],
                'tenant_id': lookup[2], 'audience': 'sandbox-api',
                'token_endpoint': issuer + '/protocol/openid-connect/token',
                'jwks_uri': issuer + '/protocol/openid-connect/certs',
                'secret_file': 'secrets/configuration-lookup-client-secret'}, indent=2) + '\n', 0o600)
        write(output / 'realms' / ('sandbox-' + kind + '-realm.json'), json.dumps(realm_data, indent=2) + '\n')
        credentials[kind] = {'username': 'synthetic-' + kind, 'password': password,
                             'backend_client_secret': backend_secret,
                             'introspection_client_secret': receiver_secret}
    # Files are mounted read-only and readable by container UID 1000. Parent directories
    # remain owner-only on the host; local Compose does not remap secret-file ownership.
    (output / 'realms').chmod(0o755)
    write(output / 'credentials.json', json.dumps(credentials, indent=2) + '\n', 0o600)
    write(output / 'compose.json', json.dumps(compose(output, project, theme_dir), indent=2) + '\n', 0o600)
    write(output / 'ownership.json', json.dumps({'project': project, 'mode': 'sandbox',
          'compose': str(output / 'compose.json'),
          'compose_sha256': hashlib.sha256((output / 'compose.json').read_bytes()).hexdigest(),
          'theme_dir': str(theme_dir), 'created_by': 'firefly-id/scripts/generate.py'}, indent=2) + '\n', 0o600)
    print('Generated synthetic sandbox at ' + str(output))
    print('Provisional example realms/clients only; credentials are in local protected files.')


if __name__ == '__main__':
    main()
