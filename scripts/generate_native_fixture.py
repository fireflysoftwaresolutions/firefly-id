#!/usr/bin/env python3
"""Generate NEW hosted-only synthetic native acceptance state; never overwrite retained state."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import uuid

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://id.firefly.test:8443'


def protected(path, value):
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise SystemExit('Native fixture generation is restricted to the owned hosted Linux runner')
    output = args.output.resolve()
    if output.parent != ROOT / '.state' or not output.name.startswith('native-') or output.exists():
        raise SystemExit('Refusing non-owned, existing or ambiguous native state')
    run = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    if output.name != 'native-' + run:
        raise SystemExit('State must be scoped to this exact hosted attempt')
    spec = importlib.util.spec_from_file_location('synthetic_base_generator', ROOT / 'scripts/generate.py')
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    output.mkdir(parents=True, mode=0o700)
    for name in ('secrets', 'realms', 'tls', 'providers', 'logs', 'pepper'):
        (output / name).mkdir(mode=0o700)
    values = {name: secrets.token_urlsafe(36) for name in ('postgres', 'keycloak-db', 'core-db', 'admin', 'store')}
    values['pepper'] = secrets.token_hex(32)
    protected(output / 'pepper/v1', secrets.token_bytes(32).hex())
    profiles = []
    for kind, population, core_port, domain_port in [('customers', 'HUMAN', 8444, 8445), ('workforce', 'STAFF', 8446, 8447)]:
        realm_name = 'native-' + kind
        person = {'id': str(uuid.uuid4()), 'username': 'synthetic-' + kind, 'email': kind + '@example.invalid', 'password': secrets.token_urlsafe(32)}
        core_secret, domain_secret = secrets.token_urlsafe(36), secrets.token_urlsafe(36)
        realm = base.realm(kind, person['password'], secrets.token_urlsafe(36))
        realm.update(realm=realm_name, sslRequired='all', verifyEmail=False, resetPasswordAllowed=False,
                     loginTheme='firefly-id-native', accountTheme='firefly-id-native' if population == 'HUMAN' else 'firefly-id',
                     otpPolicyType='totp', otpPolicyAlgorithm='HmacSHA1', otpPolicyDigits=6, otpPolicyPeriod=30,
                     otpPolicyLookAheadWindow=1, otpPolicyCodeReusable=False)
        issuer = ORIGIN + '/realms/' + realm_name
        core_origin = f'https://core-{kind}.firefly.test:{core_port}'
        domain_origin = f'https://domain-{kind}.firefly.test:{domain_port}'
        attrs = {'population': population, 'client-id': 'native-ceremony', 'tenant-attribute': 'tenant_id',
                 'link-attribute': 'party_id' if population == 'HUMAN' else 'staff_actor_id',
                 'allowed-origin': ORIGIN, 'issuer': issuer, 'domain-audience': 'firefly-recovery-domain',
                 'core-audience': 'firefly-recovery-core', 'core-workload-client-id': 'native-core-owner',
                 'domain-workload-client-id': 'native-domain-owner', 'domain-url': domain_origin,
                 'ttl-seconds': '300' if population == 'HUMAN' else '180'}
        realm['attributes'] = {'firefly.native-recovery.' + key: value for key, value in attrs.items()}
        user = realm['users'][0]
        user.update(id=person['id'], requiredActions=['CONFIGURE_TOTP'], realmRoles=['offline_access'])
        browser = base.client('native-browser', 8448, kind)
        browser.update(redirectUris=['https://localhost:8448/oidc/callback'], webOrigins=['https://localhost:8448'],
                       optionalClientScopes=['offline_access'])
        realm['clients'] = [browser, base.receiver_client(secrets.token_urlsafe(36))]
        realm['clients'][1]['clientId'] = 'native-ceremony'
        for client_id, secret in [('native-core-owner', core_secret), ('native-domain-owner', domain_secret)]:
            client = base.receiver_client(secret); client['clientId'] = client_id
            realm['clients'].append(client)
        held = json.loads(json.dumps(user)); held.update(id=str(uuid.uuid4()), username='manual-' + kind, email='manual-' + kind + '@example.invalid', enabled=False, requiredActions=[])
        held['attributes']['party_id' if population == 'HUMAN' else 'staff_actor_id'] = [str(uuid.uuid4())]
        realm['users'].append(held)
        expiry_people = {}
        if os.environ.get('FIREFLY_NATIVE_AUTHORITY_EXPIRY') == 'true':
            for role in ('expiry_actor', 'expiry_receipt'):
                identity = {'id': str(uuid.uuid4()), 'username': role + '-' + kind,
                            'email': role + '-' + kind + '@example.invalid', 'password': secrets.token_urlsafe(32)}
                entry = json.loads(json.dumps(user))
                entry.update({key: identity[key] for key in ('id', 'username', 'email')})
                entry['credentials'] = [{'type': 'password', 'value': identity['password'], 'temporary': False}]
                entry['attributes']['party_id' if population == 'HUMAN' else 'staff_actor_id'] = [str(uuid.uuid4())]
                realm['users'].append(entry)
                expiry_people[role] = identity
        for field in ('id', 'username', 'email'):
            values_for_field = [entry[field].casefold() for entry in realm['users']]
            if len(values_for_field) != len(set(values_for_field)):
                raise RuntimeError('Synthetic native user identity fields must be unique before import')
        protected(output / 'realms' / (realm_name + '.json'), realm)
        protected(output / 'secrets' / ('core-' + kind), core_secret)
        protected(output / 'secrets' / ('domain-' + kind), domain_secret)
        profiles.append({'kind': kind, 'population': population, 'realm': realm_name, 'issuer': issuer,
                         'core': core_origin, 'domain': domain_origin, 'core_port': core_port, 'domain_port': domain_port, 'domain_backend_port': domain_port + 4,
                         'person': person, 'manual': {'id': held['id'], 'username': held['username']}, **expiry_people,
                         'core_secret_file': str(output / 'secrets' / ('core-' + kind)),
                         'domain_secret_file': str(output / 'secrets' / ('domain-' + kind))})
    protected(output / 'credentials.json', {'profiles': profiles, **values})
    protected(output / 'postgres.env', f"POSTGRES_PASSWORD={values['postgres']}\nPOSTGRES_DB=postgres\n")
    protected(output / 'keycloak.env', f"KC_DB_PASSWORD={values['keycloak-db']}\nKC_BOOTSTRAP_ADMIN_PASSWORD={values['admin']}\n")
    protected(output / 'ownership.json', {'kind': 'native-integration', 'run': run, 'project': 'firefly-native-' + run,
                                         'root': str(output), 'containers': [], 'processes': [], 'fixture_version': 1})
    print('Generated new owned native customer/workforce fixture; all credentials remain private.')


if __name__ == '__main__':
    main()
