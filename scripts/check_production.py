#!/usr/bin/env python3
"""Read-only audit of supplied production candidates, never production approval."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
JAVA_TRIM_CHARACTERS = ''.join(chr(value) for value in range(33))
DECISIONS = [
    'LEGAL_APPLICABILITY', 'CUSTOMER_FACTOR_FLOW', 'PRIVILEGED_FACTOR_FLOW',
    'TRUSTED_IDENTITY_BINDING', 'KYC_ASSURANCE_PROVIDER', 'WORKFORCE_ADMIN_RECOVERY',
    'BPO_DELEGATION', 'NETWORK_CERTIFICATES_DATABASE_PRIVILEGES', 'BOOTSTRAP_ACCOUNT_REMOVAL',
    'RETAINED_DATA_HA', 'NOTIFICATION_CHANNEL', 'CONSUMER_CURRENT_STATE', 'AUDIT_PRIVACY_INCIDENTS',
]
BUILTIN_CLIENTS = {'account', 'account-console', 'admin-cli', 'broker', 'realm-management', 'security-admin-console'}
SERVER_OPTIONS = {
    'db', 'db-url', 'db-username', 'db-tls-mode', 'db-tls-trust-store-file',
    'hostname', 'hostname-admin', 'hostname-strict', 'hostname-backchannel-dynamic',
    'http-enabled', 'https-certificate-file', 'https-certificate-key-file', 'https-protocols',
    'https-management-protocols', 'tls-hostname-verifier', 'proxy-headers', 'proxy-trusted-addresses',
    'http-management-scheme', 'http-management-port', 'legacy-observability-interface',
    'health-enabled', 'metrics-enabled', 'log', 'log-console-output', 'shutdown-delay', 'shutdown-timeout',
}


def parse_config(text):
    """Accept a conservative literal subset, not Java-properties interpolation."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '\\' in line or '${' in line or '=' not in line or '\x00' in line:
            raise ValueError('INPUT_INVALID')
        key, value = (part.strip() for part in line.split('=', 1))
        if not re.fullmatch(r'[a-z][a-z0-9-]*', key) or key in result:
            raise ValueError('INPUT_INVALID')
        result[key] = value
    return result


def load_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('INPUT_INVALID')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('INPUT_INVALID')))


def https_url(value, origin=False):
    if not isinstance(value, str) or any(char in value for char in ('*', '\\', '\n', '\r', '\t')):
        return False
    try:
        url = urlsplit(value)
        host = url.hostname
        if (url.scheme != 'https' or not host or url.username is not None or url.password is not None
                or url.fragment or url.query or url.port == 0 or '%' in url.netloc):
            return False
        if origin and url.path not in ('', '/'):
            return False
        if host == 'localhost' or host.endswith('.localhost'):
            return False
        try:
            address = ipaddress.ip_address(host)
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                return False
        except ValueError:
            if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', host):
                return False
        return True
    except ValueError:
        return False


def absolute_path(value):
    return isinstance(value, str) and value.startswith('/') and '..' not in Path(value).parts


def database_url(value):
    if not isinstance(value, str) or not value.startswith('jdbc:postgresql://'):
        return False
    # Pinned upstream checks contains(key) anywhere in a full URL before injecting TLS.
    if any(key in value.lower() for key in ('sslmode', 'sslrootcert', 'sslfactory', 'sslhostnameverifier')):
        return False
    try:
        url = urlsplit(value[5:])
        return bool(url.hostname and url.port != 0 and not url.username and not url.password
                    and not url.query and not url.fragment and '?' not in value and '#' not in value
                    and re.fullmatch(r'/[a-zA-Z0-9_-]+', url.path)
                    and re.fullmatch(r'[a-zA-Z0-9.:-]+', url.hostname))
    except ValueError:
        return False


def server_findings(server):
    findings = set()
    if not server.keys() <= SERVER_OPTIONS:
        findings.add('SERVER_UNREVIEWED_OPTION')
    required = {'db': 'postgres', 'db-tls-mode': 'verify-server', 'http-enabled': 'false',
                'hostname-strict': 'true', 'hostname-backchannel-dynamic': 'false',
                'http-management-scheme': 'inherited', 'tls-hostname-verifier': 'DEFAULT',
                'legacy-observability-interface': 'false'}
    if any(server.get(key) != value for key, value in required.items()):
        findings.add('SERVER_TRANSPORT')
    if (not https_url(server.get('hostname'), origin=True)
            or not https_url(server.get('hostname-admin'), origin=True)
            or urlsplit(server.get('hostname', '')).hostname == urlsplit(server.get('hostname-admin', '')).hostname):
        findings.add('SERVER_HOSTNAME')
    protocols = set(server.get('https-protocols', '').split(','))
    if not protocols or not protocols <= {'TLSv1.2', 'TLSv1.3'}:
        findings.add('SERVER_TRANSPORT')
    management_protocols = set(server.get('https-management-protocols', server.get('https-protocols', '')).split(','))
    if not management_protocols or not management_protocols <= {'TLSv1.2', 'TLSv1.3'}:
        findings.add('SERVER_TRANSPORT')
    if not all(absolute_path(server.get(key)) for key in ('https-certificate-file', 'https-certificate-key-file')):
        findings.add('SERVER_CERTIFICATE_INPUT')
    if (not database_url(server.get('db-url')) or not absolute_path(server.get('db-tls-trust-store-file'))
            or not server.get('db-username') or server['db-username'].lower() in {'postgres', 'root', 'sa', 'admin'}
            or any(key.startswith(('db-url-properties', 'db-driver')) for key in server)):
        findings.add('SERVER_DATABASE')
    if any('password' in key or key.startswith('bootstrap-admin-') for key in server):
        findings.add('SERVER_STATIC_SECRET_OR_BOOTSTRAP')
    if server.get('proxy-headers') not in ('forwarded', 'xforwarded'):
        findings.add('SERVER_PROXY_TRUST')
    try:
        proxies = server.get('proxy-trusted-addresses', '').split(',')
        networks = []
        for value in proxies:
            network = ipaddress.ip_network(value.strip(), strict=True)
            if network.prefixlen == 0 or network.is_unspecified or network.is_multicast:
                raise ValueError('SERVER_PROXY_TRUST')
            networks.append(network)
        for version in (4, 6):
            if any(network.prefixlen == 0 for network in ipaddress.collapse_addresses(
                    network for network in networks if network.version == version)):
                raise ValueError('SERVER_PROXY_TRUST')
    except ValueError:
        findings.add('SERVER_PROXY_TRUST')
    return findings


def client_safe(client):
    if (not isinstance(client, dict) or not isinstance(client.get('clientId'), str)
            or not client['clientId'].strip()):
        return False
    if client.get('enabled') is False:
        return True
    if client.get('protocol') != 'openid-connect':
        return False
    if any(type(client.get(key)) is not bool for key in (
            'enabled', 'publicClient', 'standardFlowEnabled', 'directAccessGrantsEnabled',
            'implicitFlowEnabled', 'serviceAccountsEnabled')):
        return False
    if client['serviceAccountsEnabled'] and (client['publicClient'] or client['standardFlowEnabled']):
        return False
    attrs = client.get('attributes', {})
    if not isinstance(attrs, dict):
        return False
    if (client.get('directAccessGrantsEnabled') is not False or client.get('implicitFlowEnabled') is not False
            or any(str(attrs.get(key, 'false')).lower() != 'false' for key in (
                'oauth2.device.authorization.grant.enabled', 'oidc.ciba.grant.enabled',
                'standard.token.exchange.enabled', 'oauth2.jwt.authorization.grant.enabled'))):
        return False
    # Native console return routes have their own exact-version qualification;
    # their names do not exempt enabled clients from the common grant guards.
    if client['clientId'] in BUILTIN_CLIENTS:
        return True
    logout = attrs.get('post.logout.redirect.uris', '')
    if not isinstance(logout, str) or (logout and logout != '+' and not all(https_url(url) for url in logout.split('##'))):
        return False
    if client.get('standardFlowEnabled') is True:
        if (client.get('serviceAccountsEnabled') is not False
                or attrs.get('pkce.code.challenge.method') != 'S256'
                or not isinstance(client.get('redirectUris'), list) or not client['redirectUris']
                or not all(https_url(url) for url in client['redirectUris'])):
            return False
    for key in ('webOrigins', 'redirectUris'):
        if not isinstance(client.get(key, []), list) or not all(https_url(url, origin=key == 'webOrigins') for url in client.get(key, [])):
            return False
    return True


def client_token_lifetime_safe(client, realm_lifetime):
    if not isinstance(client, dict):
        return False
    if client.get('enabled') is False:
        return True
    attributes = client.get('attributes', {})
    if not isinstance(attributes, dict):
        return False
    if 'access.token.lifespan' not in attributes:
        return True
    value = attributes['access.token.lifespan']
    if not isinstance(value, str):
        return False
    # Keycloak inherits only when absent or Java-trimmed empty; -1 uses SSO max.
    if not value.strip(JAVA_TRIM_CHARACTERS):
        return True
    return (bool(re.fullmatch(r'[0-9]{1,10}', value)) and type(realm_lifetime) is int
            and 0 < int(value) <= realm_lifetime)


def audit(server, realms, catalogue):
    if (not isinstance(server, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in server.items())
            or not isinstance(realms, dict) or catalogue.get('schemaVersion') != 1):
        raise ValueError('INPUT_INVALID')
    findings = server_findings(server)
    required = {'customers', 'workforce', 'administrators'}
    if not required <= realms.keys() or not realms.keys() <= catalogue['profiles'].keys():
        findings.add('REALM_POPULATIONS')
    names = []
    for profile, realm in realms.items():
        if not isinstance(realm, dict) or profile not in catalogue['profiles']:
            raise ValueError('INPUT_INVALID')
        name = realm.get('realm')
        if not isinstance(name, str) or not name or (name == 'master') != (profile == 'administrators'):
            findings.add('REALM_POPULATIONS')
        names.append(name)
        guards = {'enabled': True, 'sslRequired': 'all', 'registrationAllowed': False,
                  'editUsernameAllowed': False, 'duplicateEmailsAllowed': False, 'verifyEmail': True,
                  'revokeRefreshToken': True, 'refreshTokenMaxReuse': 0, 'adminEventsDetailsEnabled': False}
        guards.update(catalogue['defaults'])
        if any(type(realm.get(key)) is not type(value) or realm.get(key) != value for key, value in guards.items()):
            findings.add('REALM_POLICY')
        if (realm.get('eventsEnabled') is not True or realm.get('adminEventsEnabled') is not True
                or type(realm.get('eventsExpiration')) is not int or realm['eventsExpiration'] <= 0
                or realm.get('enabledEventTypes', []) != []):
            findings.add('REALM_AUDIT_EVENTS')
        selected = catalogue['profiles'][profile]['realmSettings']
        policy = realm.get('passwordPolicy', '')
        terms = policy.split(' and ') if isinstance(policy, str) else []
        # Keycloak's Java trim removes U+0000–U+0020 before storing last-wins identifiers.
        identifiers = [term.split('(', 1)[0].strip(JAVA_TRIM_CHARACTERS) for term in terms]
        if (not set(selected['passwordPolicy'].split(' and ')) <= set(terms)
                or len(set(identifiers)) != len(identifiers)):
            findings.add('REALM_PASSWORD_POLICY')
        for key in ('ssoSessionIdleTimeout', 'accessTokenLifespan', 'ssoSessionMaxLifespan'):
            if key not in selected:
                continue
            value = realm.get(key)
            if type(value) is not int or not 0 < value <= selected[key]:
                findings.add('REALM_SESSION_POLICY')
        clients = realm.get('clients')
        if not isinstance(clients, list) or not clients or not all(client_safe(client) for client in clients):
            findings.add('REALM_CLIENT')
        if isinstance(clients, list):
            identifiers = [client.get('clientId') for client in clients if isinstance(client, dict)]
            if (any(not isinstance(value, str) or not value.strip() for value in identifiers)
                    or len({value for value in identifiers if isinstance(value, str)}) != len(clients)):
                findings.add('REALM_CLIENT')
            if not all(client_token_lifetime_safe(client, realm.get('accessTokenLifespan')) for client in clients):
                findings.add('REALM_CLIENT_SESSION_POLICY')
    if len(set(names)) != len(names):
        findings.add('REALM_POPULATIONS')
    return report(findings)


def report(findings):
    return {'scope': 'Supplied offline candidate only; no deployed, factor-flow or regulatory acceptance',
            'candidate_checks_passed': not findings, 'production_approved': False,
            'findings': sorted(findings), 'decisions_required': DECISIONS}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('INPUT_INVALID')


def read(path):
    with Path(path).open('rb') as stream:
        content = stream.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:
        raise ValueError('INPUT_INVALID')
    return content.decode('utf-8')


def main():
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument('--server-config', type=Path, required=True)
        parser.add_argument('--realm', action='append', default=[], metavar='PROFILE=FILE')
        args = parser.parse_args()
        server = parse_config(read(args.server_config))
        realms = {}
        for item in args.realm:
            profile, filename = item.split('=', 1)
            if profile in realms:
                raise ValueError('INPUT_INVALID')
            realms[profile] = load_json(read(filename))
        result = audit(server, realms, load_json(read(ROOT / 'config/authentication-policies.json')))
        if any(key.startswith(('KC_', 'KCRAW_', 'QUARKUS_', 'KEYCLOAK_ADMIN')) or key in (
                'JAVA_OPTS', 'JAVA_OPTS_APPEND', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS') for key in os.environ):
            result = report(set(result['findings']) | {'EXTERNAL_CONFIG_SOURCE'})
    except (ValueError, TypeError, KeyError, OSError, OverflowError, RecursionError):
        result = report({'INPUT_INVALID'})
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result['candidate_checks_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
