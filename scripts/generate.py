#!/usr/bin/env python3
"""Create a new, explicitly synthetic sandbox. Never overwrite retained state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROFILE_TYPE = 'org.keycloak.userprofile.UserProfileProvider'


def write(path, content, mode=0o644):
    path.write_text(content)
    path.chmod(mode)


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
        'defaultClientScopes': ['profile', 'email'], 'optionalClientScopes': [],
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


def realm(kind, password, backend_secret, verification_password=None):
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
        'duplicateEmailsAllowed': False, 'bruteForceProtected': True,
        'permanentLockout': False, 'failureFactor': 5, 'waitIncrementSeconds': 60,
        'maxFailureWaitSeconds': 900, 'accessTokenLifespan': 300,
        'ssoSessionIdleTimeout': 1800, 'ssoSessionMaxLifespan': 28800,
        'revokeRefreshToken': True, 'refreshTokenMaxReuse': 0,
        'passwordPolicy': 'length(14) and digits(1) and upperCase(1) and lowerCase(1)',
        'loginTheme': 'firefly-id', 'accountTheme': 'firefly-id',
        'adminTheme': 'firefly-id', 'emailTheme': 'firefly-id',
        'internationalizationEnabled': False, 'supportedLocales': ['en'],
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
    if kind == 'workforce':
        result.update({'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1',
                       'otpPolicyDigits': 6, 'otpPolicyPeriod': 30,
                       'otpPolicyLookAheadWindow': 1, 'otpPolicyCodeReusable': False})
        result['users'][0]['requiredActions'] = ['CONFIGURE_TOTP']
    if kind == 'customers' and verification_password is not None:
        result['users'].append({
            'username': 'synthetic-verify-email', 'email': 'verify-email@example.invalid',
            'enabled': True, 'emailVerified': False, 'firstName': 'Synthetic',
            'lastName': 'Verification', 'requiredActions': ['VERIFY_EMAIL'],
            'attributes': {'tenant_id': ['synthetic-tenant'], 'party_id': [str(uuid.uuid4())]},
            'credentials': [{'type': 'password', 'value': verification_password, 'temporary': False}],
        })
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
    args = parser.parse_args()
    if args.mode == 'production':
        parser.error('Production contract is not selected. Approve realm/client/claim and deployment contracts first; no production generator is enabled.')
    theme_dir = args.theme_dir.resolve()
    if not all((theme_dir / kind / 'theme.properties').is_file()
               for kind in ('login', 'account', 'admin', 'email', 'welcome')):
        parser.error('Build theme first: python3 tooling/build_theme.py (missing built theme at ' + str(theme_dir) + ')')
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('Output already exists; preserve retained secrets and database. Choose a new empty path.')
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
        write(output / 'realms' / ('sandbox-' + kind + '-realm.json'),
              json.dumps(realm(kind, password, backend_secret, verification_password), indent=2) + '\n')
        credentials[kind] = {'username': 'synthetic-' + kind, 'password': password,
                             'backend_client_secret': backend_secret}
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
