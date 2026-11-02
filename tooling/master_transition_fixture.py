#!/usr/bin/env python3
"""Hosted synthetic master qualification; exact import and retained transition are separate experiments."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('privileged_profile', ROOT / 'tooling/privileged_profile.py')
profile = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(profile)
LABEL = 'org.firefly-id.master-transition'
ORIGIN = 'https://id.firefly.test:8443'
PHASE = 'initialization'
PROFILE_DIAGNOSTIC = None
NATIVE_DIAGNOSTIC = None
# Diagnostic catalogs are pinned 26.8.1 representation fields/provider IDs, not acceptance allowlists.
UPSTREAM_REALM_FIELDS = profile.REALM_FIELDS | set('''adminPermissionsClient applicationScopeMappings applications
certificate clientTemplates codeSecret defaultRoles oauthClients organizations passwordCredentialGrantAllowed privateKey
protocolMappers publicKey realmCacheEnabled social socialProviders updateProfileOnInitialSocialLogin userCacheEnabled'''.split())
UPSTREAM_CLIENT_FIELDS = profile.CLIENT_FIELDS | set('''type directGrantsOnly clientTemplate useTemplateConfig
useTemplateScope useTemplateMappers authorizationSettings'''.split())
UPSTREAM_ATTRIBUTES = set(profile.SAFE_REALM_ATTRIBUTES) | set(profile.SAFE_CLIENT_ATTRIBUTES) | set('''
firefly.privileged-administration frontendUrl clientOfflineSessionIdleTimeout clientSessionMaxLifespan clientSessionIdleTimeout
user.info.response.signature.alg user.info.encrypted.response.alg user.info.encrypted.response.enc
request.object.signature.alg request.object.encryption.alg request.object.encryption.enc request.object.required request.uris
jwks.url use.jwks.url jwks.string use.jwks.string exclude.session.state.from.auth.response exclude.issuer.from.auth.response
tls.client.certificate.bound.access.tokens dpop.bound.access.tokens id.token.signed.response.alg id.token.encrypted.response.alg
id.token.encrypted.response.enc access.token.signed.response.alg access.token.lifespan client.session.idle.timeout
client.session.max.lifespan client.offline.session.idle.timeout client.offline.session.max.lifespan
token.endpoint.auth.signing.alg token.endpoint.auth.signing.max.exp backchannel.logout.url logout.confirmation.enabled
client_credentials.use_refresh_token token.response.type.bearer.lower-case access.token.header.type.rfc9068
id.token.as.detached.signature authorization.signed.response.alg authorization.encrypted.response.alg
authorization.encrypted.response.enc frontchannel.logout.url frontchannel.logout.session.required
standard.token.exchange.enableRefreshRequestedTokenType oauth2.jwt.authorization.grant.enabled
oauth2.jwt.authorization.grant.idp oauth2.jwt.authorization.grant.audience external.token.enabled external.token.idp
logoUri tosUri policyUri sectorIdentifierUri allow.token.introspection.without.audience.check
allow.userinfo.with.lightweight.access.token allow.oidc.params.in.redirect.uris require.pushed.authorization.requests
ciba.backchannel.token.delivery.mode ciba.backchannel.client.notification.endpoint ciba.backchannel.auth.request.signing.alg
client.secret.creation.time client.secret.rotation.enabled client.secret.expiration.time client.secret.rotated
client.secret.rotated.creation.time client.secret.rotated.expiration.time client.secret.remaining.expiration.time
client.secret.authentication.allowed.method
'''.split())
UPSTREAM_AUTHENTICATORS = profile.SOURCE_AUTHENTICATORS | set('''auth-username-form auth-password-form
conditional-sub-flow-executed conditional-client-scope conditional-user-role conditional-level-of-authentication
conditional-user-attribute idp-detect-existing-broker-user idp-confirm-override-link idp-auto-link
idp-add-organization-member auth-conditional-otp-form auth-x509-client-username-form direct-grant-auth-x509-username
webauthn-authenticator-passwordless deny-access-authenticator allow-access-authenticator organization passkeys-authenticator
user-session-limits firefly-privileged-webauthn'''.split())
IMPORTED_REALM_ATTRIBUTE_FIELDS = {key: key for key in (
    'clientSessionIdleTimeout', 'clientSessionMaxLifespan', 'clientOfflineSessionIdleTimeout',
    'clientOfflineSessionMaxLifespan', 'scimApiEnabled')}
IMPORTED_REALM_ATTRIBUTE_FIELDS['realmReusableOtpCode'] = 'otpPolicyCodeReusable'
UPSTREAM_ATTRIBUTES.update(IMPORTED_REALM_ATTRIBUTE_FIELDS)
NATIVE_OIDC_MAPPERS = set('''oidc-usermodel-attribute-mapper oidc-usermodel-property-mapper oidc-full-name-mapper
oidc-address-mapper oidc-usermodel-realm-role-mapper oidc-usermodel-client-role-mapper oidc-audience-resolve-mapper
oidc-audience-mapper oidc-sha256-pairwise-sub-mapper oidc-hardcoded-claim-mapper oidc-group-membership-mapper
oidc-allowed-origins-mapper oidc-acr-mapper oidc-amr-mapper oidc-sub-mapper'''.split())


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_owner(root, directory, owner, run_id):
    require(re.fullmatch(r'[0-9]+-[0-9]+', run_id), 'Hosted attempt identity required')
    expected = root / '.state' / ('master-' + run_id)
    require(directory == expected and directory.resolve() == expected and not directory.is_symlink(), 'Owned canonical state path required')
    project = 'ff-master-' + run_id
    require(owner.get('run') == run_id and owner.get('root') == str(expected)
            and owner.get('kind') == 'master-transition' and owner.get('project') == project, 'State ownership mismatch')
    allowed = {project + '-' + kind for kind in ('postgres', 'mailpit', 'retained', 'imported', 'export', 'import')}
    require(isinstance(owner.get('containers'), list) and set(owner['containers']) <= allowed, 'Container ownership mismatch')
    require(not any(path.is_symlink() for path in directory.rglob('*')), 'Symlink inside owned state refused')
    return owner


def profile_diagnostic(document, failure):
    gates = {
        'Unsupported realm fields refused': 'UNSUPPORTED_REALM_FIELDS',
        'Realm extension attributes require explicit review': 'REALM_ATTRIBUTES',
        'Unsupported client fields refused': 'UNSUPPORTED_CLIENT_FIELDS',
        'Unsupported client attributes refused': 'CLIENT_ATTRIBUTES',
        'Only native signing-key components are supported': 'COMPONENTS',
        'Only reviewed native signing-key, user-profile, and registration-policy components are supported': 'COMPONENTS',
        'Only the native declarative user-profile provider is supported': 'USER_PROFILE_PROVIDER',
        'Custom user-profile component settings require explicit review': 'USER_PROFILE_SETTINGS',
        'Custom declarative user-profile configuration requires explicit review': 'USER_PROFILE_CONFIGURATION',
        'Custom flow topology requires explicit review': 'FLOW_TOPOLOGY',
        'Unsupported authenticator extension refused': 'AUTHENTICATOR_PROVIDER',
        'Custom authenticator configuration requires explicit review': 'AUTHENTICATOR_CONFIG',
        'Custom client policy/profile execution requires separate review': 'CLIENT_POLICIES',
        'Unsupported required-action provider refused': 'REQUIRED_ACTION_PROVIDER',
        'Alternate authorization features are unsupported': 'ALTERNATE_AUTHORIZATION',
        'Client alternate grant or service account must already be disabled': 'CLIENT_ALTERNATE_GRANTS',
        'Offline access is outside this profile': 'OFFLINE_ACCESS',
        'Other interactive clients must already be disabled': 'INTERACTIVE_CLIENTS',
        'Existing permanent password and two-factor WebAuthn enrollment required': 'PRE_ENROLLED_CREDENTIALS',
        'Outstanding user required actions must be resolved before transition': 'OUTSTANDING_USER_ACTIONS',
        'Exact administrative console origin and redirect required': 'CONSOLE_ORIGINS',
        'Effective flow execution topology differs': 'FLOW_READBACK',
        'Effective client controls differ': 'CLIENT_READBACK',
        'Effective required actions differ': 'ACTION_READBACK',
        'Signing component inventory differs': 'SIGNING_COMPONENT_READBACK',
        'Native user-profile configuration object required': 'USER_PROFILE_OBJECT',
        'Duplicate user-profile components refused': 'DUPLICATE_USER_PROFILE',
        'Authentication flow inventory required': 'FLOW_INVENTORY',
        'Duplicate authentication flow alias refused': 'DUPLICATE_FLOW_ALIAS',
        'Realm object required': 'REALM_OBJECT',
        'Exact HTTPS origin required': 'HTTPS_ORIGIN',
        'Exact HTTPS origin without a path required': 'HTTPS_ORIGIN_PATH',
        'Invalid origin port': 'ORIGIN_PORT',
        'DNS hostname required': 'DNS_HOSTNAME',
        'Canonical HTTPS origin required': 'CANONICAL_ORIGIN',
        'Explicit realm required': 'EXPLICIT_REALM',
        'Realm does not match explicit target': 'REALM_TARGET',
        'Enabled TLS-only realm required': 'REALM_TLS_ENABLED',
        'Verified administrator email policy required': 'REALM_VERIFY_EMAIL',
        'Known retained event listeners required; custom audit collectors need explicit review': 'EVENT_LISTENERS',
        'Retained event selection must include sign-in successes and failures': 'EVENT_SELECTION',
        'Complete client inventory required': 'CLIENT_INVENTORY',
        'Complete unique built-in client inventory required': 'BUILTIN_CLIENT_INVENTORY',
        'Full pre-enrolled local user inventory required': 'USER_INVENTORY',
        'Unique named account inventory required': 'UNIQUE_USER_INVENTORY',
        'At least one enabled pre-enrolled account required': 'ENABLED_USER_INVENTORY',
        'Master candidate requires explicit acknowledgment': 'MASTER_ACKNOWLEDGMENT',
        'Native component list required': 'COMPONENT_LIST',
        'Client authentication flow binding is unsupported or dangling': 'CLIENT_FLOW_BINDING',
        'External identity or credential providers are unsupported': 'EXTERNAL_PROVIDERS',
        'Only OIDC clients are supported': 'CLIENT_PROTOCOL',
        'Client authentication-flow override refused': 'CLIENT_FLOW_OVERRIDE',
        'Explicit client scope inventory required': 'CLIENT_SCOPE_INVENTORY',
        'Only named local nonservice users are supported': 'LOCAL_NONSERVICE_USERS',
        'Nested provider components are unsupported': 'NESTED_COMPONENTS',
        'Duplicate JSON property refused': 'DUPLICATE_JSON_PROPERTY',
        'Enabled public console code flow required': 'CONSOLE_CODE_FLOW',
        'Console PKCE S256 required': 'CONSOLE_PKCE',
        'Previously verified administrator email required': 'USER_VERIFIED_EMAIL',
        'Named account required': 'NAMED_USER',
        'Privileged flow topology differs from the reviewed profile': 'PRIVILEGED_FLOW_TOPOLOGY',
        'A new output path is required': 'OUTPUT_PATH',
        'Duplicate or invalid user-profile role set refused': 'USER_PROFILE_ROLE_SET',
        'Internal administrative role resource must remain confidential and bearer-only': 'INTERNAL_ROLE_RESOURCE',
        'Complete native registration policy inventory required': 'REGISTRATION_POLICY_INVENTORY',
        'Unreviewed native registration policy identity': 'REGISTRATION_POLICY_IDENTITY',
        'Unreviewed native registration policy configuration': 'REGISTRATION_POLICY_CONFIGURATION',
        'Imported realm attribute does not mirror retained typed control': 'IMPORTED_REALM_ATTRIBUTE',
    }
    def mapping(value):
        return value if isinstance(value, dict) else {}
    def rows(value):
        return [item for item in value[:64] if isinstance(item, dict)] if isinstance(value, list) else []
    def count(value):
        return min(len(value), 10000)
    def names(value, known):
        return sorted(set(value) & known)
    def known(value, catalog):
        return value if isinstance(value, str) and value in catalog else 'OTHER'
    def profile_shape(component):
        config = mapping(component.get('config'))
        result = {'configKeyCount': count(config), 'knownConfigKeys': names(config, {'kc.user.profile.config'}),
                  'jsonObject': False}
        values = config.get('kc.user.profile.config')
        if isinstance(values, list) and len(values) == 1 and isinstance(values[0], str):
            try:
                configured = profile.parse_document(values[0])
                result.update(jsonObject=True, knownKeys=names(configured, {'attributes', 'groups', 'unmanagedAttributePolicy'}),
                              unknownKeyCount=count(set(configured) - {'attributes', 'groups', 'unmanagedAttributePolicy'}),
                              attributes=[{'name': known(item.get('name'), {'username', 'email', 'firstName', 'lastName'}),
                                           'knownKeys': names(item, {'name', 'displayName', 'validations', 'annotations', 'permissions',
                                                                    'required', 'selector', 'group', 'multivalued'}),
                                           'requiredPresent': item.get('required') is not None,
                                           'multivaluedFalse': item.get('multivalued') is False}
                                          for item in rows(configured.get('attributes'))])
            except (ValueError, TypeError):
                pass
        return result
    attributes = mapping(document.get('attributes'))
    clients = rows(document.get('clients'))
    authenticators = [step.get('authenticator') for flow in rows(document.get('authenticationFlows'))
                      for step in rows(flow.get('authenticationExecutions')) if isinstance(step.get('authenticator'), str)]
    actions = set(profile.ACTIONS) | {'verifiable_credential_offer'}
    message = str(failure)
    result = {'gate': gates.get(message, 'UNCLASSIFIED'),
              'profileSourceLines': [frame.lineno for frame in traceback.extract_tb(failure.__traceback__)
                                     if Path(frame.filename).resolve() == ROOT / 'tooling/privileged_profile.py'][-6:],
              'unsupportedRealmFieldCount': count(set(document) - profile.REALM_FIELDS),
              'knownUnsupportedRealmFields': names(set(document) - profile.REALM_FIELDS, UPSTREAM_REALM_FIELDS),
              'realmAttributeCount': count(attributes), 'knownRealmAttributes': names(attributes, UPSTREAM_ATTRIBUTES),
              'unknownRealmAttributeCount': count(set(attributes) - UPSTREAM_ATTRIBUTES),
              'realmNativeDefaults': {key: attributes[key] == profile.SAFE_REALM_ATTRIBUTES[key]
                                      for key in names(attributes, set(profile.SAFE_REALM_ATTRIBUTES))},
              'realmMirrorAttributes': {key: 'ZERO' if attributes[key] == '0' else 'FALSE' if attributes[key] == 'false'
                                       else 'TRUE' if attributes[key] == 'true' else 'OTHER'
                                       for key in names(attributes, set(IMPORTED_REALM_ATTRIBUTE_FIELDS))},
              'alternateAuthorizationDisabled': {key: document[key] is False for key in (
                  'scimApiEnabled', 'organizationsEnabled', 'userManagedAccessEnabled', 'userManagedAccessAllowed',
                  'verifiableCredentialsEnabled') if key in document},
              'clients': [{'clientId': known(client.get('clientId'), profile.BUILTIN_CLIENTS | {'master-realm', 'realm-management'}),
                           'protocol': known(client.get('protocol'), {'openid-connect', 'saml'}),
                           'protocolPresent': 'protocol' in client,
                           'scopes': {key: {'present': key in client, 'isList': isinstance(client.get(key), list),
                                            'count': count(client[key]) if isinstance(client.get(key), list) else 0,
                                            'offlineAccessPresent': isinstance(client.get(key), list) and 'offline_access' in client[key]}
                                      for key in ('defaultClientScopes', 'optionalClientScopes')},
                           'knownUnsupportedFields': names(set(client) - profile.CLIENT_FIELDS, UPSTREAM_CLIENT_FIELDS),
                           'unknownFieldCount': count(set(client) - UPSTREAM_CLIENT_FIELDS),
                           'knownAttributes': names(mapping(client.get('attributes')), UPSTREAM_ATTRIBUTES),
                           'unknownAttributeCount': count(set(mapping(client.get('attributes'))) - UPSTREAM_ATTRIBUTES),
                           'reviewedAttributes': {key: mapping(client.get('attributes'))[key] in profile.SAFE_CLIENT_ATTRIBUTES[key]
                                                  if isinstance(mapping(client.get('attributes'))[key], str) else False
                                                  for key in names(mapping(client.get('attributes')), set(profile.SAFE_CLIENT_ATTRIBUTES))}}
                          for client in clients],
              'knownAuthenticators': names(authenticators, UPSTREAM_AUTHENTICATORS),
              'unknownAuthenticatorCount': count(set(authenticators) - UPSTREAM_AUTHENTICATORS),
              'authenticatorConfigs': [{'alias': known(item.get('alias'), profile.SOURCE_CONFIGS),
                                       'reviewedDefault': item.get('config') == profile.SOURCE_CONFIGS.get(known(item.get('alias'), profile.SOURCE_CONFIGS), False),
                                       'configKeyCount': count(mapping(item.get('config')))}
                                      for item in rows(document.get('authenticatorConfig'))],
              'requiredActions': [{'alias': known(item.get('alias'), actions),
                                   'provider': known(item.get('providerId'), actions),
                                   'enabled': item.get('enabled') is True, 'defaultAction': item.get('defaultAction') is True,
                                   'configKeyCount': count(mapping(item.get('config')))}
                                  for item in rows(document.get('requiredActions'))],
              'nativeUserProfiles': [profile_shape(component) for component in rows(
                  mapping(document.get('components')).get(profile.USER_PROFILE_PROVIDER))]}
    for prefix in ('Preserved realm setting differs: ', 'Effective realm control differs: '):
        if message.startswith(prefix) and message[len(prefix):] in profile.REALM_FIELDS:
            result.update(gate='REALM_READBACK', field=message[len(prefix):])
    return result


def candidate_receipt(directory):
    path = directory / 'candidate.json'
    require(path.is_file() and not path.is_symlink(), 'Exact regular candidate file required')
    content = path.read_bytes()
    require(profile.parse_document(content).get('realm') == 'master', 'Master candidate required')
    return {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}


def verify_candidate(directory, receipt):
    require(candidate_receipt(directory) == receipt, 'Exact generated candidate changed')


def verified_component_readback(candidate, effective, rows):
    # Pinned StripSecretsUtils removes properties absent from each factory's config metadata.
    # Verify hidden material in SQL first; API omission alone is never evidence of retention.
    common = {'priority', 'enabled', 'active'}
    visible = {
        'rsa-generated': common | {'keySize', 'algorithm'},
        'rsa-enc-generated': common | {'keySize', 'algorithm'},
        'hmac-generated': common | {'secretSize', 'algorithm'},
        'aes-generated': common | {'secretSize'},
        'ecdsa-generated': common | {'ecGenerateCertificate', 'ecdsaEllipticCurveKey'},
    }
    hidden = {
        'rsa-generated': {'privateKey', 'certificate', 'keyUse'},
        'rsa-enc-generated': {'privateKey', 'certificate', 'keyUse'},
        'hmac-generated': {'secret', 'kid'}, 'aes-generated': {'secret', 'kid'},
        'ecdsa-generated': {'ecdsaPrivateKey', 'ecdsaPublicKey', 'certificate'},
    }
    def inventory(document):
        profile.reviewed_native_components(document.get('components', {}), realm=document.get('realm'))
        result = {}
        for kind, entries in document.get('components', {}).items():
            for component in entries:
                identity = component.get('id')
                require(isinstance(identity, str) and identity and identity not in result, 'Unique component identity required')
                result[identity] = (kind, component)
        return result
    def configuration(kind, component):
        if kind == profile.USER_PROFILE_PROVIDER:
            return {'kc.user.profile.config': profile.native_user_profile_configuration(component, realm='master')}
        if kind == profile.REGISTRATION_POLICY_PROVIDER:
            return profile.native_registration_configuration(component)
        config = component.get('config', {})
        require(isinstance(config, dict) and all(isinstance(value, list) and value
                and all(isinstance(item, str) for item in value) for value in config.values()), 'Component configuration shape differs')
        return {key: sorted(value) for key, value in config.items()}
    expected = inventory(candidate)
    restored = json.loads(json.dumps(effective))
    actual = inventory(restored)
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), 'Component database inventory required')
    database = {row.get('id'): row for row in rows}
    require(len(database) == len(rows) and set(expected) == set(actual) == set(database), 'Component inventory differs')
    for identity, (kind, component) in expected.items():
        actual_kind, observed = actual[identity]
        provider = component.get('providerId')
        require(kind == actual_kind and provider == observed.get('providerId'), 'Component provider identity differs')
        row = database[identity]
        require(all(row.get(key) == value for key, value in {
            'providerType': kind, 'providerId': provider, 'name': component.get('name'),
            'subType': component.get('subType'), 'realmId': candidate.get('id'), 'parentId': candidate.get('id')}.items())
            and isinstance(candidate.get('id'), str) and candidate['id'], 'Component database identity differs')
        expected_config = configuration(kind, component)
        require(expected_config == configuration(kind, {**component, 'config': row.get('config')}), 'Component database configuration differs')
        if kind in (profile.USER_PROFILE_PROVIDER, profile.REGISTRATION_POLICY_PROVIDER):
            require(expected_config == configuration(kind, observed), 'Native component API configuration differs')
        else:
            require(provider in visible and set(expected_config) <= visible[provider] | hidden[provider],
                    'Unreviewed key provider configuration refused')
            require(configuration(kind, observed) == {key: value for key, value in expected_config.items() if key in visible[provider]},
                    'Key provider API configuration differs')
        observed['config'] = row['config']
    return restored


def imported_readback(candidate, effective, window):
    require(isinstance(window, dict) and all(type(window.get(key)) is int for key in ('minimum', 'maximum'))
            and 0 < window['minimum'] <= window['maximum'] <= window['minimum'] + 241,
            'Measured native import window required')
    restored = json.loads(json.dumps(effective))
    for attribute, field in IMPORTED_REALM_ATTRIBUTE_FIELDS.items():
        if attribute in restored.get('attributes', {}) and attribute not in candidate.get('attributes', {}):
            value = candidate.get(field)
            expected_type = bool if field in ('otpPolicyCodeReusable', 'scimApiEnabled') else int
            require(type(value) is expected_type and type(restored.get(field)) is expected_type
                    and restored[field] == value and restored['attributes'][attribute] == (
                        str(value).lower() if expected_type is bool else str(value)),
                    'Imported realm attribute does not mirror retained typed control')
            del restored['attributes'][attribute]
    expected = {client['clientId']: client for client in candidate['clients']}
    for actual in restored.get('clients', []):
        source = expected.get(actual.get('clientId'))
        require(source is not None, 'Unexpected imported client')
        protected = profile.internal_role_resource(candidate, source) and profile.internal_role_resource(restored, actual)
        if protected:
            require(source.get('bearerOnly') is True and actual.get('bearerOnly') is True
                    and source.get('publicClient') is False and actual.get('publicClient') is False,
                    'Imported internal resource lost bearer-only confinement')
            require(all(actual.get(key, False) is False for key in ('directAccessGrantsEnabled', 'implicitFlowEnabled',
                        'serviceAccountsEnabled', 'authorizationServicesEnabled')), 'Imported internal resource gained a grant')
            # RepresentationToModel supplies OIDC only when the native protected resource omitted a protocol.
            if 'protocol' not in source and actual.get('protocol') == 'openid-connect':
                del actual['protocol']
        source_attributes = source.get('attributes', {})
        actual_attributes = actual.get('attributes', {})
        # DefaultExportImportManager adds '+' on import; active interactive clients get no waiver.
        if (protected or (source.get('enabled') is False and actual.get('enabled') is False)) and (
                'post.logout.redirect.uris' not in source_attributes and actual_attributes.get('post.logout.redirect.uris') == '+'):
            del actual_attributes['post.logout.redirect.uris']
        creation = 'client.secret.creation.time'
        if protected and creation not in source_attributes and creation in actual_attributes:
            require(source.get('secret') is None, 'Existing client secret metadata changed')
            value = actual_attributes[creation]
            require(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,9}', value) is not None
                    and window['minimum'] <= int(value) <= window['maximum'] and int(value) <= 2147483647,
                    'Native imported secret metadata outside measured window')
            del actual_attributes[creation]
    # MigrationUtils materializes the existing OIDCAttributeMapperHelper absent-userinfo fallback.
    for kind, identity in (('clientScopes', 'id'), ('clients', 'clientId')):
        containers = {item.get(identity): item for item in candidate.get(kind, [])}
        for container in restored.get(kind, []):
            source = containers.get(container.get(identity), {})
            mappers = {item.get('id'): item for item in source.get('protocolMappers', []) if item.get('id')}
            for mapper in container.get('protocolMappers', []):
                original = mappers.get(mapper.get('id'))
                if original is None or original.get('protocol') != 'openid-connect' or mapper.get('protocol') != 'openid-connect':
                    continue
                if original.get('protocolMapper') not in NATIVE_OIDC_MAPPERS or mapper.get('protocolMapper') != original.get('protocolMapper'):
                    continue
                config = original.get('config', {})
                actual_config = mapper.get('config', {})
                if ('userinfo.token.claim' not in config and config.get('id.token.claim') in ('true', 'false')
                        and actual_config.get('userinfo.token.claim') == config['id.token.claim']):
                    del actual_config['userinfo.token.claim']
    return restored


def verify_effective(candidate, effective, retirement_window=None, *, import_window=None):
    if import_window is not None:
        effective = imported_readback(candidate, effective, import_window)
    # Partial export omits users; identity/credential/role retention is checked independently.
    checked = dict(effective, users=candidate['users'])
    console = next(client for client in candidate['clients'] if client['clientId'] == 'security-admin-console')
    profile.prerequisites(checked, 'master', console['webOrigins'][0])
    def canonical(value, ignored=frozenset()):
        if isinstance(value, dict):
            return {key: canonical(item, ignored) for key, item in value.items() if key not in ignored}
        if isinstance(value, list):
            return sorted((canonical(item, ignored) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
        return value
    special = {'users', 'authenticationFlows', 'requiredActions', 'clients', 'components', 'keycloakVersion'}
    for key in (set(candidate) | set(effective)) - special:
        if key == 'notBefore' and retirement_window is not None:
            value = effective.get(key)
            require(isinstance(value, int) and value >= candidate.get(key, 0)
                    and retirement_window['minimum'] <= value <= retirement_window['maximum'], 'Retirement watermark outside measured operation')
            continue
        require(canonical(candidate.get(key)) == canonical(effective.get(key)), 'Preserved realm setting differs: ' + key)
    def components(document):
        profile.reviewed_native_components(document.get('components', {}), realm=document.get('realm'))
        result = json.loads(json.dumps(document.get('components', {})))
        for component in result.get(profile.USER_PROFILE_PROVIDER, []):
            component['config'] = {'kc.user.profile.config': profile.native_user_profile_configuration(component, realm=document.get('realm'))}
        for component in result.get(profile.REGISTRATION_POLICY_PROVIDER, []):
            component['config'] = profile.native_registration_configuration(component)
        return canonical(result)
    require(components(candidate) == components(effective), 'Signing component inventory differs')
    expected = profile.controls(profile.origin_host('https://' + candidate['webAuthnPolicyRpId']))
    for key in expected:
        if key in ('authenticationFlows', 'requiredActions'):
            continue
        require(effective.get(key) == candidate[key], 'Effective realm control differs: ' + key)
    def flows(document):
        result = {}
        for item in document.get('authenticationFlows', []):
            require(item['alias'] not in result, 'Duplicate effective flow')
            steps = sorted(item.get('authenticationExecutions', []), key=lambda value: value['priority'])
            result[item['alias']] = [item.get('providerId'), item.get('topLevel'), item.get('builtIn'), [
                {key: execution.get(key) for key in ('authenticator', 'authenticatorFlow', 'requirement', 'priority', 'flowAlias', 'authenticatorConfig')}
                for execution in steps]]
        return result
    require(flows(candidate) == flows(effective), 'Effective flow execution topology differs')
    def actions(document):
        values = document.get('requiredActions', [])
        require(len({item['alias'] for item in values}) == len(values), 'Duplicate effective action')
        return {item['alias']: {key: item.get(key, {} if key == 'config' else None)
                               for key in ('providerId', 'enabled', 'defaultAction', 'priority', 'config')} for item in values}
    require(actions(candidate) == actions(effective), 'Effective required actions differ')
    client_keys = ('id', 'enabled', 'protocol', 'publicClient', 'bearerOnly', 'standardFlowEnabled',
                   'directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled', 'authorizationServicesEnabled',
                   'authenticationFlowBindingOverrides', 'attributes', 'redirectUris', 'webOrigins',
                   'defaultClientScopes', 'optionalClientScopes', 'fullScopeAllowed', 'consentRequired', 'clientAuthenticatorType',
                   'protocolMappers', 'notBefore', 'frontchannelLogout', 'registeredNodes', 'rootUrl', 'adminUrl', 'baseUrl', 'type')
    def clients(document):
        values = document.get('clients', [])
        require(len({item['clientId'] for item in values}) == len(values), 'Duplicate effective client')
        result = {}
        for item in values:
            normalized = {}
            for key in client_keys:
                default = {} if key in ('attributes', 'authenticationFlowBindingOverrides') else [] if key in (
                    'redirectUris', 'webOrigins', 'defaultClientScopes', 'optionalClientScopes') else False if key == 'authorizationServicesEnabled' else None
                value = item.get(key, default)
                normalized[key] = canonical(value)
            result[item['clientId']] = normalized
        return result
    require(clients(candidate) == clients(effective), 'Effective client controls differ')


def readback_diagnostic(candidate, effective, import_window=None):
    if 'users' in candidate and 'users' not in effective:
        effective = dict(effective, users=candidate['users'])
    normalization_succeeded = True
    if import_window is not None:
        try:
            effective = imported_readback(candidate, effective, import_window)
        except (ValueError, KeyError, TypeError):
            normalization_succeeded = False
    def canonical(value):
        if isinstance(value, dict):
            return {key: canonical(item) for key, item in value.items()}
        if isinstance(value, list):
            return sorted((canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
        return value
    def differences(before, after):
        return {key for key in set(before) | set(after) if canonical(before.get(key)) != canonical(after.get(key))}
    def category(values, key):
        if key not in values: return 'ABSENT'
        value = values[key]
        return 'NULL' if value is None else 'EMPTY' if value == '' else 'TRUE' if value == 'true' else 'FALSE' if value == 'false' else 'OTHER'
    mapper_fields = {'id', 'name', 'protocol', 'protocolMapper', 'config', 'consentRequired', 'consentText'}
    config_keys = set('''id.token.claim access.token.claim userinfo.token.claim introspection.token.claim lightweight.claim
claim.name user.attribute user.session.note jsonType.label multivalued aggregate.attrs full.path
usermodel.clientRoleMapping.clientId usermodel.clientRoleMapping.rolePrefix usermodel.realmRoleMapping.rolePrefix
included.client.audience included.custom.audience access.tokenResponse.claim address.formatted address.street
address.locality address.region address.postal_code address.country'''.split())
    def match(before, actual, identity, fallback):
        return next((item for item in actual if before.get(identity) is not None and item.get(identity) == before[identity]),
                    next((item for item in actual if before.get(fallback) is not None and item.get(fallback) == before[fallback]), {}))
    def mappers(before, actual):
        result = []
        for index, item in enumerate(before[:64]):
            observed = match(item, actual, 'id', 'name')
            if canonical(item) == canonical(observed): continue
            config = item.get('config', {}); observed_config = observed.get('config', {})
            changed = differences(config, observed_config)
            result.append({'index': index, 'sameId': item.get('id') == observed.get('id'),
                           'provider': item.get('protocolMapper') if item.get('protocolMapper') in NATIVE_OIDC_MAPPERS else 'OTHER',
                           'knownFields': sorted(differences(item, observed) & mapper_fields),
                           'knownConfig': [{'key': key, 'expected': category(config, key), 'actual': category(observed_config, key)}
                                           for key in sorted(changed & config_keys)],
                           'unknownConfigDifferenceCount': min(len(changed - config_keys), 10000)})
        return result[:32]
    def containers(kind, identity, fallback, fields):
        before = candidate.get(kind, []); actual = effective.get(kind, [])
        result = []
        for index, item in enumerate(before[:64]):
            observed = match(item, actual, identity, fallback)
            if canonical(item) == canonical(observed): continue
            result.append({'index': index, 'sameId': item.get('id') == observed.get('id'),
                           'knownFields': sorted(differences(item, observed) & fields),
                           'unknownFieldDifferenceCount': min(len(differences(item, observed) - fields), 10000),
                           'expectedMapperCount': min(len(item.get('protocolMappers', [])), 10000),
                           'actualMapperCount': min(len(observed.get('protocolMappers', [])), 10000),
                           'mappers': mappers(item.get('protocolMappers', []), observed.get('protocolMappers', []))})
        return result[:32]
    changed = differences(candidate, effective)
    return {'normalizationSucceeded': normalization_succeeded, 'knownRealmFields': sorted(changed & profile.REALM_FIELDS),
            'unknownRealmFieldDifferenceCount': min(len(changed - profile.REALM_FIELDS), 10000),
            'clientCountMatches': len(candidate.get('clients', [])) == len(effective.get('clients', [])),
            'scopeCountMatches': len(candidate.get('clientScopes', [])) == len(effective.get('clientScopes', [])),
            'clients': containers('clients', 'id', 'clientId', profile.CLIENT_FIELDS),
            'clientScopes': containers('clientScopes', 'id', 'name', {'id', 'name', 'description', 'protocol', 'attributes', 'protocolMappers'})}


def verify_retained(before, after):
    for key in set(before) - {'events', 'adminEvents'}:
        require(before[key] == after[key], 'Retained identity material changed: ' + key)
    for key in ('events', 'adminEvents'):
        require(before[key] and set(before[key]) <= set(after[key]), 'Retained audit rows disappeared: ' + key)


def require_hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'Owned hosted Linux runner required')
    require(not any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')),
            'Docker override refused')
    endpoint = subprocess.check_output(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], text=True)
    require(json.loads(endpoint) == 'unix:///var/run/docker.sock', 'Local hosted Docker required')


def state():
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    directory = ROOT / '.state' / ('master-' + run_id)
    owner = json.loads((directory / 'ownership.json').read_text())
    return directory, validate_owner(ROOT, directory, owner, run_id)


def private_write(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as stream:
        stream.write(value)


def save_owner(directory, owner):
    private_write(directory / 'ownership.json', json.dumps(owner))


def write_native_environment(directory, credentials):
    private_write(directory / 'keycloak.env', 'KC_DB_PASSWORD=' + credentials['database'] + '\n')
    private_write(directory / 'bootstrap.env', 'KC_BOOTSTRAP_ADMIN_PASSWORD=' + credentials['bootstrap'] + '\n')


def native_log_diagnostic(content):
    exceptions = {'java.lang.NullPointerException', 'java.lang.IllegalArgumentException', 'java.lang.IllegalStateException',
                  'java.lang.RuntimeException', 'java.lang.ClassNotFoundException', 'java.lang.NoClassDefFoundError',
                  'java.io.FileNotFoundException', 'java.nio.file.AccessDeniedException', 'java.net.BindException',
                  'org.keycloak.models.ModelException', 'org.keycloak.models.ModelDuplicateException',
                  'org.keycloak.models.ModelValidationException', 'org.keycloak.models.ModelIllegalStateException',
                  'jakarta.persistence.PersistenceException', 'jakarta.persistence.EntityExistsException',
                  'org.hibernate.exception.ConstraintViolationException', 'org.hibernate.exception.SQLGrammarException',
                  'org.hibernate.exception.JDBCConnectionException', 'org.postgresql.util.PSQLException',
                  'com.fasterxml.jackson.databind.JsonMappingException', 'com.fasterxml.jackson.core.JsonParseException',
                  'com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException',
                  'com.fasterxml.jackson.databind.exc.MismatchedInputException', 'jakarta.ws.rs.NotFoundException'}
    patterns = {'REALM_IMPORT': r'failed to import realm', 'DUPLICATE_KEY': r'duplicate key value violates unique constraint',
                'FOREIGN_KEY': r'violates foreign key constraint', 'NOT_NULL': r'violates not-null constraint',
                'REALM_EXISTS': r'realm .* already exists', 'JSON_UNKNOWN_FIELD': r'unrecognized field',
                'FILE_PERMISSION': r'permission denied|accessdeniedexception',
                'ADDRESS_IN_USE': r'address already in use', 'CONNECTION_REFUSED': r'connection refused',
                'MISSING_FILE': r'no such file or directory|filenotfoundexception',
                'UNKNOWN_OPTION': r'unknown option|unmatched argument',
                'INVALID_OPTION': r'invalid value for option|invalid option value',
                'MISSING_FLOW': r'unable to resolve auth flow|authentication flow .* does not exist',
                'MISSING_ROLE': r'role .* does not exist|role .* not found',
                'MISSING_PROVIDER': r'provider .* not found|failed to find provider',
                'MISSING_REQUIRED_ACTION': r'required action .* not found|unable to find required action',
                'INVALID_COMPONENT': r'componentvalidationexception|invalid component',
                'INVALID_CLIENT': r'clienttypeexception|client validation|invalid client',
                'PLACEHOLDER_REPLACEMENT': r'placeholder|could not resolve expression',
                'SCHEMA_MIGRATION': r'liquibase\.exception|database migration failed',
                'DUPLICATE_MODEL': r'modelduplicateexception', 'INVALID_MODEL': r'modelvalidationexception'}
    files = {'ImportUtils', 'ExportUtils', 'SingleFileImportProvider', 'DirImportProvider',
             'RepresentationToModel', 'DefaultExportImportManager', 'RealmManager', 'KeycloakModelUtils',
             'JpaRealmProvider', 'JpaClientProvider', 'JpaUserProvider', 'ClientAdapter', 'RealmAdapter',
             'UserAdapter', 'ClientScopeAdapter', 'AuthenticationExecutionAdapter', 'AuthenticationFlowAdapter',
             'KeycloakApplication', 'QuarkusKeycloakApplication', 'Import', 'AbstractImportExportCommand'}
    frames = []
    for match in re.finditer(r'\bat org\.keycloak\.[^\s(]+\(([A-Za-z]+)\.java:([0-9]{1,6})\)', content):
        if match[1] in files:
            value = match[1] + '.java:' + match[2]
            if value not in frames:
                frames.append(value)
    return {'exceptionClasses': sorted(value for value in exceptions if re.search(r'\b' + re.escape(value) + r'\b', content)),
            'categories': sorted(key for key, pattern in patterns.items() if re.search(pattern, content, re.IGNORECASE)),
            'sourceFrames': frames[:20]}


def native_container_diagnostic(state):
    code = state.get('ExitCode')
    return {'inspected': True, 'exitCode': code if type(code) is int and 0 <= code <= 255 else None,
            'oomKilled': state.get('OOMKilled') is True, 'running': state.get('Running') is True,
            'runtimeErrorPresent': bool(state.get('Error'))}


def run(command, directory, label, *, input=None, env=None):
    global PHASE, NATIVE_DIAGNOSTIC
    PHASE = label
    with (directory / 'logs' / (label + '.log')).open('ab') as output:
        result = subprocess.run(command, input=input, stdout=output, stderr=subprocess.STDOUT, env=env)
    if result.returncode != 0 and label in ('import-create', 'export-create'):
        with (directory / 'logs' / (label + '.log')).open('rb') as output:
            output.seek(max(0, os.fstat(output.fileno()).st_size - 2 * 1024 * 1024))
            NATIVE_DIAGNOSTIC = native_log_diagnostic(output.read().decode(errors='replace'))
            NATIVE_DIAGNOSTIC['processExitCode'] = result.returncode if -128 <= result.returncode <= 255 else None
    require(result.returncode == 0, 'Owned lifecycle phase refused')


def inspect_container(owner, kind):
    name = owner['project'] + '-' + kind
    require(name in owner['containers'], 'Container not owned by receipt')
    result = subprocess.run(['docker', 'inspect', name], capture_output=True)
    require(result.returncode == 0, 'Owned container missing')
    actual = json.loads(result.stdout)[0]
    require(actual['Config'].get('Labels', {}).get(LABEL) == owner['run'], 'Container ownership label mismatch')
    require(actual['Config']['Image'] == images()[kind if kind in ('postgres', 'mailpit') else 'keycloak']['image'], 'Pinned owned image required')
    if kind == 'mailpit':
        bindings = actual['HostConfig']['PortBindings']
        require(all(bindings.get(str(port) + '/tcp') == [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]
                    for port in (1025, 8025)), 'Owned loopback mail transport required')
    elif kind == 'postgres':
        require(actual['HostConfig']['PortBindings'].get('5432/tcp') == [{'HostIp': '127.0.0.1', 'HostPort': '5432'}], 'Loopback database binding required')
    else:
        require(actual['HostConfig']['NetworkMode'] == 'host', 'Owned local native network required')
        database = 'master_imported' if kind in ('import', 'imported') else 'master_retained'
        require('KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/' + database in actual['Config']['Env'], 'Owned database binding mismatch')
        mounts = {item['Destination']: item['Source'] for item in actual['Mounts']}
        require(mounts.get('/run/tls') == owner['root'] + '/tls' and mounts.get('/run/exchange') == owner['root'] + '/exchange'
                and mounts.get('/opt/keycloak/providers') == owner['root'] + '/providers', 'Owned native mounts mismatch')
    return name, actual


def stop_kind(directory, owner, kind):
    name, actual = inspect_container(owner, kind)
    if actual['State']['Running']:
        run(['docker', 'stop', '--time', '30', name], directory, kind + '-stop')


def psql(directory, owner, sql, database='postgres', *, read_only=False):
    name, _ = inspect_container(owner, 'postgres')
    options = ['-e', 'PGOPTIONS=-c default_transaction_read_only=on'] if read_only else []
    result = subprocess.run(['docker', 'exec', '-i', *options, name, 'psql', '-X', '-U', 'postgres', '-d', database,
                             '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=sqlstate', '-At'], input=sql.encode(), capture_output=True)
    require(result.returncode == 0, 'Owned database operation refused')
    return result.stdout.decode().strip()


def read_component_rows(directory, owner):
    require(owner['phase'] in ('imported', 'retained'), 'Active component readback phase required')
    _, actual = inspect_container(owner, owner['phase'])
    require(actual['State']['Running'], 'Active owned native runtime required')
    database = 'master_imported' if owner['phase'] == 'imported' else 'master_retained'
    query = """SELECT coalesce(json_agg(q ORDER BY q.id),'[]'::json) FROM (
        SELECT c.id,c.name,c.provider_id AS "providerId",c.provider_type AS "providerType",
               c.sub_type AS "subType",c.parent_id AS "parentId",c.realm_id AS "realmId",
               coalesce((SELECT json_object_agg(k.name,k.config_values) FROM (
                   SELECT name,json_agg(value ORDER BY value) AS config_values FROM component_config
                   WHERE component_id=c.id GROUP BY name) k),'{}'::json) AS config
        FROM component c JOIN realm r ON r.id=c.realm_id WHERE r.name='master') q;"""
    return json.loads(psql(directory, owner, query, database, read_only=True))


def wait_ready(directory):
    context = ssl.create_default_context(cafile=str(directory / 'tls/ca.crt'))
    for _ in range(120):
        try:
            with urllib.request.urlopen(ORIGIN + '/realms/master/.well-known/openid-configuration', context=context, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(1)
    raise ValueError('Owned TLS readiness deadline')


def prepare():
    run_id = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    require(re.fullmatch(r'[0-9]+-[0-9]+', run_id), 'Hosted attempt identity required')
    directory = ROOT / '.state' / ('master-' + run_id)
    require(not directory.exists() and not directory.is_symlink() and not (ROOT / '.state').is_symlink(), 'Fresh state required')
    for port in (5432, 8443, 1025, 8025):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    directory.mkdir(parents=True, mode=0o700)
    for name in ('logs', 'tls', 'providers', 'exchange'):
        (directory / name).mkdir(mode=0o700)
    owner = {'run': run_id, 'root': str(directory), 'kind': 'master-transition',
             'project': 'ff-master-' + run_id, 'containers': [], 'phase': 'prepared'}
    save_owner(directory, owner)
    credentials = {key: secrets.token_urlsafe(32) for key in ('postgres', 'database', 'bootstrap', 'ordinary', 'emergency')}
    private_write(directory / 'credentials.json', json.dumps(credentials))
    private_write(directory / 'postgres.env', 'POSTGRES_PASSWORD=' + credentials['postgres'] + '\n')
    write_native_environment(directory, credentials)
    tls = directory / 'tls'
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt'),
         '-subj', '/CN=Owned Master Fixture CA', '-days', '2', '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], directory, 'tls-ca')
    run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', str(tls / 'server.key'), '-out', str(tls / 'server.csr'),
         '-subj', '/CN=id.firefly.test'], directory, 'tls-request')
    private_write(tls / 'server.ext', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:id.firefly.test,IP:127.0.0.1\n')
    run(['openssl', 'x509', '-req', '-in', str(tls / 'server.csr'), '-CA', str(tls / 'ca.crt'), '-CAkey', str(tls / 'ca.key'),
         '-CAcreateserial', '-out', str(tls / 'server.crt'), '-days', '2', '-extfile', str(tls / 'server.ext')], directory, 'tls-sign')
    jar = ROOT / 'extensions/native-recovery/target/firefly-id-native-recovery-26.10.1-SNAPSHOT.jar'
    require(jar.is_file(), 'Built native provider required')
    import shutil
    shutil.copyfile(jar, directory / 'providers' / jar.name)
    # Only this fresh run's mount tree is traversable to the pinned image UID. Secrets stay 0600.
    for path in (directory, tls, directory / 'providers'):
        path.chmod(0o755)
    for path in (tls / 'ca.crt', tls / 'server.crt', directory / 'providers' / jar.name):
        path.chmod(0o644)
    (tls / 'server.key').chmod(0o600)
    run(['sudo', 'chown', '1000:0', str(tls / 'server.key'), str(directory / 'exchange')], directory, 'owned-mount-owner')
    run(['sudo', 'chown', '1000:' + str(os.getgid()), str(directory / 'exchange')], directory, 'owned-exchange-group')
    run(['sudo', 'chmod', '770', str(directory / 'exchange')], directory, 'owned-exchange-access')
    run(['sudo', 'tee', '-a', '/etc/hosts'], directory, 'owned-hostname', input=b'\n127.0.0.1 id.firefly.test\n')
    nss = Path.home() / '.pki/nssdb'; nss.mkdir(parents=True, exist_ok=True)
    if not (nss / 'cert9.db').exists():
        run(['certutil', '-N', '-d', 'sql:' + str(nss), '--empty-password'], directory, 'browser-trust-create')
    run(['certutil', '-A', '-d', 'sql:' + str(nss), '-n', 'master-' + run_id, '-t', 'C,,', '-i', str(tls / 'ca.crt')], directory, 'browser-trust')
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write('NODE_EXTRA_CA_CERTS=' + str(tls / 'ca.crt') + '\n')


def images():
    return json.loads((ROOT / 'deploy/images.lock.json').read_text())


def create_container(directory, owner, kind, command):
    name = owner['project'] + '-' + kind
    require(name not in owner['containers'], 'Refusing to adopt an existing container receipt')
    result = subprocess.run(['docker', 'inspect', name], capture_output=True)
    require(result.returncode != 0, 'Refusing an existing container name')
    owner['containers'].append(name); save_owner(directory, owner)
    try:
        run(['docker', 'run', '--name', name, '--label', LABEL + '=' + owner['run']] + command, directory, kind + '-create')
    except ValueError:
        if kind in ('import', 'export') and NATIVE_DIAGNOSTIC is not None:
            NATIVE_DIAGNOSTIC['container'] = {'inspected': False}
            try:
                _, actual = inspect_container(owner, kind)
                NATIVE_DIAGNOSTIC['container'] = native_container_diagnostic(actual['State'])
            except (ValueError, KeyError, TypeError):
                pass
        raise
    inspect_container(owner, kind)


def native_command(directory, kind, database, command, *, bootstrap=False):
    require(database in ('master_retained', 'master_imported'), 'Only owned databases admitted')
    require(not bootstrap or (kind == 'retained' and database == 'master_retained' and command == ['start']),
            'Bootstrap credentials only admitted for initial retained server creation')
    if kind == 'export':
        require(database == 'master_retained' and command == ['export', '--realm', 'master', '--users', 'same_file',
                '--file', '/run/exchange/source.json'], 'Pinned owned single-file export command required')
    initial = ['--env-file', str(directory / 'bootstrap.env'), '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-bootstrap'] if bootstrap else []
    return (['--detach'] if kind in ('retained', 'imported') else []) + initial + [
        '--network', 'host', '--env-file', str(directory / 'keycloak.env'), '--env', 'KC_DB=postgres',
        '--env', 'KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/' + database, '--env', 'KC_DB_USERNAME=master_fixture',
        '--env', 'KC_HTTP_ENABLED=false',
        '--env', 'KC_HTTP_HOST=127.0.0.1', '--env', 'KC_HTTPS_PORT=8443', '--env', 'KC_HOSTNAME=' + ORIGIN,
        '--env', 'KC_HOSTNAME_STRICT=true', '--env', 'KC_HTTPS_CERTIFICATE_FILE=/run/tls/server.crt',
        '--env', 'KC_HTTPS_CERTIFICATE_KEY_FILE=/run/tls/server.key', '--env', 'KC_LOG_LEVEL=warn',
        '--env', 'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m', '--volume', str(directory / 'tls') + ':/run/tls:ro',
        '--volume', str(directory / 'providers') + ':/opt/keycloak/providers:ro',
        '--volume', str(ROOT / 'dist/themes') + ':/opt/keycloak/themes:ro',
        '--volume', str(directory / 'exchange') + ':/run/exchange',
        '--add-host', 'id.firefly.test:127.0.0.1', images()['keycloak']['image']] + command


def start():
    directory, owner = state(); credentials = json.loads((directory / 'credentials.json').read_text())
    require(owner['phase'] == 'prepared', 'Fresh prepared fixture required')
    create_container(directory, owner, 'postgres', ['--detach', '--publish', '127.0.0.1:5432:5432',
                     '--env-file', str(directory / 'postgres.env'), images()['postgres']['image']])
    name, _ = inspect_container(owner, 'postgres')
    for _ in range(90):
        if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'], capture_output=True).returncode == 0:
            break
        time.sleep(1)
    else:
        raise ValueError('Postgres readiness deadline')
    psql(directory, owner, "CREATE ROLE master_fixture LOGIN PASSWORD '" + credentials['database'] + "'; CREATE DATABASE master_retained OWNER master_fixture; CREATE DATABASE master_imported OWNER master_fixture;")
    create_container(directory, owner, 'mailpit', ['--detach', '--publish', '127.0.0.1:1025:1025',
                     '--publish', '127.0.0.1:8025:8025', images()['mailpit']['image']])
    create_container(directory, owner, 'retained', native_command(directory, 'retained', 'master_retained', ['start'], bootstrap=True))
    wait_ready(directory); owner['phase'] = 'enrollment'; save_owner(directory, owner)


def snapshot(directory, owner):
    tables = {'users': 'user_entity', 'credentials': 'credential', 'roles': 'user_role_mapping',
              'events': 'event_entity', 'adminEvents': 'admin_event_entity', 'roleDefinitions': 'keycloak_role',
              'roleComposites': 'composite_role', 'groups': 'keycloak_group', 'groupMembership': 'user_group_membership',
              'groupRoles': 'group_role_mapping', 'userAttributes': 'user_attribute', 'requiredActions': 'user_required_action'}
    tables.update({'components': 'component', 'componentConfig': 'component_config'})
    result = {}
    for key, table in tables.items():
        # Full row hashes remain private. Equality proves credential hashes and stored key counters survive.
        query = "SELECT coalesce(json_agg(h ORDER BY h),'[]'::json) FROM (SELECT md5(row_to_json(t)::text) h FROM " + table + " t) q;"
        result[key] = json.loads(psql(directory, owner, query, 'master_retained'))
    return result


def export_candidate():
    global PHASE, PROFILE_DIAGNOSTIC
    directory, owner = state(); require(owner['phase'] == 'enrollment', 'Enrollment phase required')
    private_write(directory / 'retained-before.json', json.dumps(snapshot(directory, owner)))
    stop_kind(directory, owner, 'retained')
    create_container(directory, owner, 'export', native_command(directory, 'export', 'master_retained',
                     ['export', '--realm', 'master', '--users', 'same_file', '--file', '/run/exchange/source.json']))
    source = directory / 'exchange/source.json'
    run(['sudo', 'chown', str(os.getuid()) + ':' + str(os.getgid()), str(source)], directory, 'export-private-owner')
    source.chmod(0o600)
    PHASE = 'actual-export-prerequisites'
    document = profile.parse_document(source.read_bytes())
    try:
        profile.prerequisites(document, 'master', ORIGIN)
    except (ValueError, TypeError, KeyError) as failure:
        PROFILE_DIAGNOSTIC = profile_diagnostic(document, failure)
        raise
    run([sys.executable, str(ROOT / 'tooling/privileged_profile.py'), 'generate', '--input', str(source),
         '--realm', 'master', '--origin', ORIGIN, '--acknowledge-master', '--output', str(directory / 'candidate.json')], directory, 'exact-profile-generation')
    receipt = candidate_receipt(directory); private_write(directory / 'candidate-receipt.json', json.dumps(receipt))
    # The read-only mounted import copy must be byte-identical to the generator output.
    target = directory / 'exchange/candidate.json'
    with target.open('xb') as output:
        output.write((directory / 'candidate.json').read_bytes())
    target.chmod(0o640)
    run(['sudo', 'chown', '1000:' + str(os.getgid()), str(target)], directory, 'candidate-import-owner')
    owner['phase'] = 'candidate'; save_owner(directory, owner)


def import_start():
    directory, owner = state(); require(owner['phase'] == 'candidate', 'Exact candidate phase required')
    verify_candidate(directory, json.loads((directory / 'candidate-receipt.json').read_text()))
    require((directory / 'exchange/candidate.json').read_bytes() == (directory / 'candidate.json').read_bytes(), 'Mounted import differs from generated candidate')
    require(psql(directory, owner, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';", 'master_imported') == '0', 'Import database must be empty')
    owner['importWindow'] = {'minimum': int(time.time())}
    create_container(directory, owner, 'import', native_command(directory, 'import', 'master_imported',
                     ['import', '--file', '/run/exchange/candidate.json', '--override', 'false', '--verbose']))
    owner['importWindow']['maximum'] = int(time.time()) + 1
    create_container(directory, owner, 'imported', native_command(directory, 'imported', 'master_imported', ['start']))
    wait_ready(directory); owner['phase'] = 'imported'; save_owner(directory, owner)


def retained_start():
    directory, owner = state(); require(owner['phase'] == 'imported', 'Imported qualification phase required')
    stop_kind(directory, owner, 'imported')
    name, _ = inspect_container(owner, 'retained'); run(['docker', 'start', name], directory, 'retained-resume')
    wait_ready(directory); owner['phase'] = 'retained'; save_owner(directory, owner)


def restart():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    name, _ = inspect_container(owner, 'retained'); run(['docker', 'restart', name], directory, 'retained-restart')
    wait_ready(directory)


def verify_state():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    before = json.loads((directory / 'retained-before.json').read_text())
    after = snapshot(directory, owner)
    verify_retained(before, after)
    print(json.dumps({'retainedCounts': {key: len(value) for key, value in before.items()}}))


def bounded_events(rows):
    types = {'LOGIN', 'LOGIN_ERROR', 'UPDATE_CREDENTIAL', 'UPDATE_CREDENTIAL_ERROR', 'REGISTER', 'REGISTER_ERROR',
             'CUSTOM_REQUIRED_ACTION', 'CUSTOM_REQUIRED_ACTION_ERROR', 'CODE_TO_TOKEN', 'CODE_TO_TOKEN_ERROR'}
    errors = {'invalid_request', 'invalid_redirect_uri', 'invalid_code', 'expired_code', 'invalid_registration',
              'invalid_user_credentials', 'invalid_authentication_session', 'invalid_client', 'invalid_scope',
              'client_disabled', 'user_disabled', 'resolve_required_actions', 'cookie_not_found', 'not_allowed',
              'ssl_required', 'user_session_not_found', 'session_expired', 'invalid_token', 'invalid_signature',
              'pkce_verification_failed', 'illegal_origin', 'generic_authentication_error', 'generic'}
    return [{'type': item.get('type') if item.get('type') in types else 'OTHER',
             'error': item.get('error') if item.get('error') is None or item.get('error') in errors else 'OTHER'} for item in rows[:20]]


def authentication_diagnostic():
    directory, owner = state()
    database = 'master_imported' if owner['phase'] == 'imported' else 'master_retained'
    result = {'events': bounded_events(json.loads(psql(directory, owner,
        "SELECT coalesce(json_agg(q),'[]'::json) FROM (SELECT type,error FROM event_entity ORDER BY event_time DESC LIMIT 20) q;", database))),
        'credentialCounts': {}, 'exceptionClasses': []}
    for kind in ('ordinary', 'emergency'):
        result['credentialCounts'][kind] = json.loads(psql(directory, owner,
            "SELECT json_build_object('password',count(*) FILTER (WHERE c.type='password'),'webauthn',count(*) FILTER (WHERE c.type='webauthn'),"
            "'passwordless',count(*) FILTER (WHERE c.type='webauthn-passwordless')) FROM credential c JOIN user_entity u ON c.user_id=u.id "
            "WHERE u.username='synthetic-" + kind + "';", database))
    native, _ = inspect_container(owner, 'imported' if owner['phase'] == 'imported' else 'retained')
    captured = subprocess.run(['docker', 'logs', '--tail', '400', native], capture_output=True, timeout=10)
    content = (captured.stdout + captured.stderr).decode(errors='replace')
    known = {'java.lang.NullPointerException', 'java.lang.IllegalArgumentException', 'java.lang.IllegalStateException',
             'org.keycloak.models.ModelException', 'org.keycloak.models.ModelDuplicateException',
             'com.webauthn4j.verifier.exception.BadChallengeException', 'com.webauthn4j.verifier.exception.BadOriginException',
             'com.webauthn4j.verifier.exception.BadRpIdException', 'com.webauthn4j.verifier.exception.BadSignatureException',
             'com.webauthn4j.verifier.exception.UserNotPresentException', 'com.webauthn4j.verifier.exception.UserNotVerifiedException',
             'jakarta.ws.rs.BadRequestException', 'freemarker.core.InvalidReferenceException', 'org.hibernate.exception.ConstraintViolationException'}
    result['exceptionClasses'] = sorted(value for value in known if value in content)
    print(json.dumps(result))


def review_components():
    global PROFILE_DIAGNOSTIC
    _, owner = state(); require(owner['phase'] == 'enrollment', 'Owned source prerequisite phase required')
    values = json.load(sys.stdin)
    require(isinstance(values, list) and len(values) <= 64, 'Bounded owned component inventory required')
    native = {}
    for component in values:
        kind = component.get('providerType')
        native.setdefault(kind, []).append(component)
    try:
        profile.reviewed_native_components(native, realm='master')
    except (ValueError, TypeError, KeyError) as failure:
        PROFILE_DIAGNOSTIC = profile_diagnostic({'components': native}, failure)
        raise


def action_snapshot(directory, owner):
    result = snapshot(directory, owner)
    for table in ('offline_user_session', 'offline_client_session'):
        result[table] = json.loads(psql(directory, owner,
            "SELECT coalesce(json_agg(h ORDER BY h),'[]'::json) FROM (SELECT md5(row_to_json(t)::text) h FROM " + table + " t) q;", 'master_retained'))
    return result


def action_baseline():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    path = directory / 'action-before.json'; require(not path.exists(), 'Fresh action baseline required')
    private_write(path, json.dumps(action_snapshot(directory, owner)))


def verify_action_state():
    directory, owner = state(); require(owner['phase'] == 'retained', 'Retained phase required')
    verify_retained(json.loads((directory / 'action-before.json').read_text()), action_snapshot(directory, owner))


def readback():
    global PROFILE_DIAGNOSTIC
    directory, owner = state()
    verify_candidate(directory, json.loads((directory / 'candidate-receipt.json').read_text()))
    receipt = json.load(sys.stdin)
    effective = receipt['effective']
    try:
        candidate = profile.parse_document((directory / 'candidate.json').read_bytes())
        effective = verified_component_readback(candidate, receipt['effective'], read_component_rows(directory, owner))
        verify_effective(candidate, effective, receipt.get('retirementWindow'),
                         import_window=owner['importWindow'] if owner['phase'] == 'imported' else None)
    except (ValueError, TypeError, KeyError) as failure:
        PROFILE_DIAGNOSTIC = profile_diagnostic(receipt['effective'], failure)
        PROFILE_DIAGNOSTIC['readback'] = readback_diagnostic(candidate, effective,
            owner.get('importWindow') if owner['phase'] == 'imported' else None)
        raise


def stop():
    directory, owner = state()
    for name in reversed(owner['containers']):
        kind = name.removeprefix(owner['project'] + '-')
        # A failed creation may leave only a reservation; it is never an invitation to adopt another resource.
        if subprocess.run(['docker', 'inspect', name], capture_output=True).returncode == 0:
            stop_kind(directory, owner, kind)


def check():
    directory, owner = state()
    require(owner['phase'] == 'enrollment', 'Fresh owned runtime phase required')
    inspect_container(owner, 'postgres')
    inspect_container(owner, 'mailpit')
    _, native = inspect_container(owner, 'retained')
    require(native['State']['Running'], 'Owned retained native runtime required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['review_components', 'authentication_diagnostic', 'check', 'action_baseline', 'verify_action_state', 'prepare', 'start', 'export_candidate', 'import_start', 'retained_start', 'restart', 'verify_state', 'readback', 'stop'])
    args = parser.parse_args(); require_hosted(); os.umask(0o077)
    globals()[args.action]()


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        evidence = ROOT / '.work/master-transition'; evidence.mkdir(parents=True, exist_ok=True)
        diagnostic = {'status': 'FAILED', 'stage': PHASE,
                      'sourceLines': [frame.lineno for frame in traceback.extract_tb(failure.__traceback__)
                                      if Path(frame.filename).resolve() == Path(__file__).resolve()][-6:]}
        if PROFILE_DIAGNOSTIC is not None:
            diagnostic['profile'] = PROFILE_DIAGNOSTIC
        if NATIVE_DIAGNOSTIC is not None:
            diagnostic['native'] = NATIVE_DIAGNOSTIC
        (evidence / 'lifecycle-summary.json').write_text(json.dumps(diagnostic, indent=2) + '\n')
        print('Owned master fixture failed; raw logs and credential material remain private.', file=sys.stderr)
        raise SystemExit(1)
