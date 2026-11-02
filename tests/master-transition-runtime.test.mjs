import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

async function runtime() {
  assert.ok(existsSync(new URL('../tooling/master-transition-runtime.mjs', import.meta.url)), 'Master runtime is missing');
  return import('../tooling/master-transition-runtime.mjs');
}

test('master runtime rejects stale receipts and arbitrary paths before contacting a master', async () => {
  const { ownedRuntime } = await runtime();
  const root = '/owned/worktree';
  const env = { GITHUB_ACTIONS: 'true', RUNNER_OS: 'Linux', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1' };
  const owner = { kind: 'master-transition', root: root + '/.state/master-123-1', run: '123-1', project: 'ff-master-123-1', phase: 'enrollment' };
  assert.equal(ownedRuntime(root, env, owner), owner.root);
  for (const mutation of [{ run: '122-1' }, { root: '/existing' }, { kind: 'native-integration' }, { phase: 'retained' }]) {
    assert.throws(() => ownedRuntime(root, env, { ...owner, ...mutation }));
  }
  for (const mutation of [{ RUNNER_ENVIRONMENT: 'self-hosted' }, { RUNNER_OS: 'macOS' }, { GITHUB_RUN_ID: '../existing' }]) {
    assert.throws(() => ownedRuntime(root, { ...env, ...mutation }, owner));
  }
});

test('retained plan uses only generated profile flows and controls, never realm replacement or account imports', async () => {
  const { retainedOperations, CONTROL_KEYS } = await runtime();
  const controls = { attributes: { 'firefly.privileged-administration': 'password-webauthn-uv-v1' },
    browserFlow: 'firefly-privileged-browser-v1', directGrantFlow: 'firefly-privileged-deny-v1',
    authenticationFlows: ['firefly-privileged-browser-v1', 'firefly-privileged-deny-v1'].map((alias, i) => ({
      alias, providerId: 'basic-flow', builtIn: false, topLevel: true,
      authenticationExecutions: (i ? ['deny-access-authenticator'] : ['auth-username-password-form', 'firefly-privileged-webauthn'])
        .map((authenticator, j) => ({ authenticator, authenticatorFlow: false, requirement: 'REQUIRED', priority: 10 * (j + 1) })) })),
    requiredActions: [{ alias: 'webauthn-register', providerId: 'webauthn-register', enabled: false, defaultAction: false, priority: 0, config: {} }],
    users: [{ username: 'must-not-import' }], clients: [{ clientId: 'must-not-put' }] };
  for (const key of CONTROL_KEYS) if (!Object.hasOwn(controls, key)) controls[key] = false;
  const policies = {};
  for (const prefix of ['webAuthnPolicy', 'webAuthnPolicyPasswordless']) {
    for (const [key, value] of Object.entries({ RpEntityName: prefix + ' retained name', SignatureAlgorithms: ['ES256', 'RS256'],
      RpId: 'id.example.test', AttestationConveyancePreference: 'direct', AuthenticatorAttachment: 'cross-platform',
      RequireResidentKey: 'No', ResidentKey: 'discouraged', UserVerificationRequirement: 'required', CreateTimeout: 27,
      AvoidSameAuthenticatorRegister: true, AcceptableAaguids: ['retained-aaguid'], ExtraOrigins: [] })) policies[prefix + key] = value;
  }
  policies.webAuthnPolicyPasswordlessPasskeysEnabled = false;
  policies.webAuthnPolicyPasswordlessMediation = 'conditional';
  Object.assign(controls, policies);
  const result = retainedOperations(controls, ['attributes', 'browserFlow', 'directGrantFlow', 'authenticationFlows', 'requiredActions']);
  assert.equal(result.flows.length, 2);
  assert.deepEqual(Object.keys(result.realm).sort(), CONTROL_KEYS.filter(key => !['authenticationFlows', 'requiredActions'].includes(key)).sort());
  assert.deepEqual(Object.fromEntries(Object.keys(policies).map(key => [key, result.realm[key]])), policies);
  for (const key of Object.keys(policies)) {
    const missing = { ...controls }; delete missing[key];
    if (key === 'webAuthnPolicyPasswordlessMediation') {
      const native = retainedOperations(missing);
      assert.equal(Object.hasOwn(native.realm, key), false, 'Absent native null mediation must not invent a value');
      assert.equal(native.realm.webAuthnPolicyPasswordlessPasskeysEnabled, false);
    } else assert.throws(() => retainedOperations(missing), 'Missing retained policy field must refuse: ' + key);
  }
  assert.equal(retainedOperations({ ...controls, webAuthnPolicyPasswordlessMediation: null }).realm.webAuthnPolicyPasswordlessMediation, null);
  for (const key of ['webAuthnPolicyRpEntityName', 'webAuthnPolicyPasswordlessRpEntityName']) {
    for (const value of ['', null, false]) assert.throws(() => retainedOperations({ ...controls, [key]: value }));
  }
  const incomplete = { ...controls }; delete incomplete.webAuthnPolicyUserVerificationRequirement;
  assert.throws(() => retainedOperations(incomplete));
  assert.ok(!JSON.stringify(result).includes('must-not'));
  assert.throws(() => retainedOperations({ ...controls, authenticationFlows: [] }, ['browserFlow', 'authenticationFlows']));
});

test('retained control diagnostics expose fixed missing field names and native nullable shape only', async () => {
  const { retainedControlDiagnostic } = await runtime();
  assert.equal(typeof retainedControlDiagnostic, 'function');
  const value = retainedControlDiagnostic({ PRIVATE_FIELD: 'PRIVATE_VALUE', webAuthnPolicyRpEntityName: 'PRIVATE_NAME' });
  assert.ok(value.missingFields.includes('webAuthnPolicyPasswordlessMediation'));
  assert.ok(!value.missingRequiredFields.includes('webAuthnPolicyPasswordlessMediation'));
  assert.ok(value.missingRequiredFields.includes('webAuthnPolicyPasswordlessPasskeysEnabled'));
  assert.equal(value.passwordlessMediation, 'ABSENT');
  assert.equal(retainedControlDiagnostic({ webAuthnPolicyPasswordlessMediation: null }).passwordlessMediation, 'NULL');
  assert.equal(retainedControlDiagnostic({ webAuthnPolicyPasswordlessMediation: 'PRIVATE' }).passwordlessMediation, 'PRESENT');
  assert.doesNotMatch(JSON.stringify(value), /PRIVATE/);
});

test('runtime failure diagnostics expose only whitelisted class and owned source positions', async () => {
  const { safeRuntimeFailure } = await runtime();
  assert.equal(typeof safeRuntimeFailure, 'function', 'Safe runtime failure context is missing');
  const error = { name: 'TimeoutError', message: 'PRIVATE-TOKEN', stack: 'TimeoutError PRIVATE-TOKEN\n at start (file:///owned/tooling/master-transition-runtime.mjs:145:21)\n at other (file:///PRIVATE-PATH/file.mjs:12:3)' };
  assert.deepEqual(safeRuntimeFailure(error), { errorKind: 'TimeoutError', sourceFrames: ['master-transition-runtime.mjs:145:21'] });
  assert.deepEqual(safeRuntimeFailure({ name: 'PRIVATE-TYPE', message: 'PRIVATE-TOKEN', stack: 'PRIVATE' }), { errorKind: 'OTHER', sourceFrames: [] });
  assert.deepEqual(safeRuntimeFailure({ name: 'TypeError', cause: { code: 'UND_ERR_SOCKET', message: 'PRIVATE' } }),
    { errorKind: 'TypeError', sourceFrames: [], transportCode: 'UND_ERR_SOCKET' });
  assert.equal(safeRuntimeFailure({ name: 'TypeError', cause: { code: 'PRIVATE' } }).transportCode, 'OTHER');
});

test('retired authority GET retries only one named socket failure and returns actual HTTP evidence', async () => {
  const { retiredAccessRequest } = await runtime();
  assert.equal(typeof retiredAccessRequest, 'function');
  const failure = code => Object.assign(new TypeError('PRIVATE'), { cause: { code, message: 'PRIVATE' } });
  for (const code of ['UND_ERR_SOCKET', 'ECONNRESET', 'EPIPE']) {
    const calls = []; const events = []; const response = { status: 401 };
    assert.equal(await retiredAccessRequest(async (url, options) => {
      calls.push({ url, options }); if (calls.length === 1) throw failure(code); return response;
    }, 'PRIVATE-TOKEN', event => events.push(event)), response);
    assert.equal(calls.length, 2); assert.equal(calls[0].url, 'https://id.firefly.test:8443/admin/realms/master');
    assert.equal(calls[1].url, calls[0].url); assert.equal(calls[0].options.method, 'GET');
    assert.equal(calls[1].options, calls[0].options); assert.equal(calls[0].options.headers.Authorization, 'Bearer PRIVATE-TOKEN');
    assert.equal(events[0].transportCode, code); assert.equal(events[1].status, 401);
    assert.doesNotMatch(JSON.stringify(events), /PRIVATE/);
  }
  for (const status of [200, 401, 403, 503]) {
    let attempts = 0;
    assert.equal((await retiredAccessRequest(async () => { attempts++; return { status }; }, 'PRIVATE')).status, status);
    assert.equal(attempts, 1);
  }
  for (const error of [failure('ERR_TLS_CERT_ALTNAME_INVALID'), failure('UND_ERR_CONNECT_TIMEOUT'), failure('ECONNREFUSED'),
    failure('PRIVATE'), Object.assign(new Error('PRIVATE'), { name: 'AbortError' }), Object.assign(new Error('PRIVATE'), { cause: { code: 'ECONNRESET' } })]) {
    let attempts = 0;
    await assert.rejects(retiredAccessRequest(async () => { attempts++; throw error; }, 'PRIVATE'), value => value === error);
    assert.equal(attempts, 1);
  }
  let attempts = 0; const error = failure('UND_ERR_SOCKET');
  await assert.rejects(retiredAccessRequest(async () => { attempts++; throw error; }, 'PRIVATE'), value => value === error);
  assert.equal(attempts, 2);
});

test('retired authority GET uses one bounded deadline and cannot retry after it expires', async context => {
  const { retiredAccessRequest } = await runtime();
  const controller = new AbortController(); const expired = new DOMException('PRIVATE', 'TimeoutError');
  let deadlines = 0; let attempts = 0;
  context.mock.method(AbortSignal, 'timeout', milliseconds => {
    assert.equal(milliseconds, 30000); deadlines++; return controller.signal;
  });
  await assert.rejects(retiredAccessRequest(async (_url, options) => {
    attempts++; assert.equal(options.signal, controller.signal); assert.equal(options.method, 'GET');
    controller.abort(expired);
    throw Object.assign(new TypeError('PRIVATE'), { cause: { code: 'ECONNRESET' } });
  }, 'PRIVATE'), error => error === expired);
  assert.equal(deadlines, 1); assert.equal(attempts, 1);
});

test('authentication diagnostics classify known messages without returning arbitrary page or form text', async () => {
  const { classifyAuthenticationMessage, registrationSubmissionDiagnostic } = await runtime();
  assert.equal(typeof classifyAuthenticationMessage, 'function');
  assert.equal(classifyAuthenticationMessage('Passkey registration result is invalid. PRIVATE-DETAIL'), 'WEBAUTHN_REGISTRATION_VERIFICATION');
  assert.equal(classifyAuthenticationMessage('PRIVATE-UNKNOWN-ERROR'), 'UNCLASSIFIED');
  const body = new URLSearchParams({ error: 'SecurityError: PRIVATE-CREDENTIAL', clientDataJSON: 'PRIVATE', attestationObject: 'PRIVATE' });
  const result = registrationSubmissionDiagnostic(body.toString(), 'null', 400);
  assert.deepEqual(result, { status: 400, origin: 'NULL', browserError: 'SecurityError', attestationPresent: true,
    clientDataPresent: true, credentialIdPresent: false });
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
});


test('component diagnostics preserve only known provider categories and configuration shape', async () => {
  const { componentDiagnostic } = await runtime();
  assert.equal(typeof componentDiagnostic, 'function');
  assert.deepEqual(componentDiagnostic({ providerType: 'org.keycloak.userprofile.UserProfileProvider', providerId: 'declarative-user-profile',
    id: 'PRIVATE', config: { 'kc.user.profile.config': ['PRIVATE'] } }),
    { kind: 'USER_PROFILE', provider: 'declarative-user-profile', configuration: 'USER_PROFILE_JSON', nested: false });
  assert.deepEqual(componentDiagnostic({ providerType: 'PRIVATE', providerId: 'PRIVATE', config: { PRIVATE: ['PRIVATE'] } }),
    { kind: 'OTHER', provider: 'OTHER', configuration: 'OTHER', nested: false });
});

test('owned client preparation explicitly retires attributes while preserving unreviewed inputs', async () => {
  const { preparedClientAttributes } = await runtime();
  assert.equal(typeof preparedClientAttributes, 'function');
  const source = { clientId: 'admin-cli', attributes: { 'client.use.lightweight.access.token.enabled': 'true', unknown: 'preserve' } };
  assert.deepEqual(preparedClientAttributes(source), { 'client.use.lightweight.access.token.enabled': 'false', unknown: 'preserve' });
  assert.equal(source.attributes['client.use.lightweight.access.token.enabled'], 'true');
  assert.deepEqual(preparedClientAttributes({ clientId: 'broker', attributes: { 'client.secret.creation.time': '123', unknown: 'preserve' } }),
    { 'client.secret.creation.time': '123', 'client.use.lightweight.access.token.enabled': 'false', unknown: 'preserve' });
  assert.equal(preparedClientAttributes({ clientId: 'security-admin-console', attributes: {} })['pkce.code.challenge.method'], 'S256');
  for (const clientId of ['master-realm', 'unreviewed']) assert.throws(() => preparedClientAttributes({ clientId, attributes: {} }));
});

test('client attribute readback diagnostics report only fixed names and comparison booleans', async () => {
  const { clientAttributeDiagnostic } = await runtime();
  assert.equal(typeof clientAttributeDiagnostic, 'function');
  const expected = { 'realm_client': 'false', 'client.use.lightweight.access.token.enabled': 'false',
    'client.secret.creation.time': null, PRIVATE: 'PRIVATE' };
  const actual = { 'realm_client': 'false', 'client.use.lightweight.access.token.enabled': 'true',
    'client.secret.creation.time': 'PRIVATE', PRIVATE: 'DIFFERENT' };
  const result = clientAttributeDiagnostic('broker', expected, actual);
  assert.equal(result.clientId, 'broker');
  assert.deepEqual(result.attributes.find(item => item.key === 'client.use.lightweight.access.token.enabled'),
    { key: 'client.use.lightweight.access.token.enabled', expectedPresent: true, actualPresent: true,
      matches: false, expectedClass: 'FALSE', actualClass: 'TRUE' });
  assert.deepEqual(result.attributes.find(item => item.key === 'client.secret.creation.time'),
    { key: 'client.secret.creation.time', expectedPresent: false, actualPresent: true,
      matches: false, expectedClass: 'ABSENT', actualClass: 'OTHER' });
  assert.equal(result.unknownExpectedCount, 1); assert.equal(result.unknownActualCount, 1);
  assert.equal(result.unknownValuesMatch, false);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|DIFFERENT/);
  assert.equal(clientAttributeDiagnostic('PRIVATE', {}, {}).clientId, 'OTHER');
});

test('fresh disabled broker accepts only native secret metadata created inside its measured update', async () => {
  const { verifyPreparedClientReadback } = await runtime();
  assert.equal(typeof verifyPreparedClientReadback, 'function');
  const initial = { clientId: 'broker', publicClient: false, bearerOnly: true, attributes: { realm_client: 'false' } };
  const attributes = { realm_client: 'false', 'client.use.lightweight.access.token.enabled': 'false' };
  const effective = { ...initial, protocol: 'openid-connect', enabled: false, standardFlowEnabled: false,
    implicitFlowEnabled: false, directAccessGrantsEnabled: false, serviceAccountsEnabled: false,
    attributes: { ...attributes, 'client.secret.creation.time': '100' } };
  const window = { minimum: 99, maximum: 101 };
  assert.equal(verifyPreparedClientReadback(initial, effective, attributes, window), true);
  const existing = { ...initial, secret: 'existing', attributes: effective.attributes };
  assert.equal(verifyPreparedClientReadback(existing, effective, effective.attributes, window), false);
  for (const value of ['98', '102', '-1', '0100', '100.0', 'PRIVATE', 100]) {
    assert.throws(() => verifyPreparedClientReadback(initial, { ...effective,
      attributes: { ...effective.attributes, 'client.secret.creation.time': value } }, attributes, window));
  }
  for (const mutation of [{ clientId: 'account' }, { publicClient: true }, { bearerOnly: false }, { secret: 'existing' }]) {
    assert.throws(() => verifyPreparedClientReadback({ ...initial, ...mutation }, effective, attributes, window));
  }
  for (const flag of ['enabled', 'standardFlowEnabled', 'implicitFlowEnabled', 'directAccessGrantsEnabled',
    'serviceAccountsEnabled', 'authorizationServicesEnabled']) {
    assert.throws(() => verifyPreparedClientReadback(initial, { ...effective, [flag]: true }, attributes, window));
  }
  for (const extra of [{ unknown: 'PRIVATE' }, { 'client.use.lightweight.access.token.enabled': 'true' }]) {
    assert.throws(() => verifyPreparedClientReadback(initial, { ...effective, attributes: { ...effective.attributes, ...extra } }, attributes, window));
  }
  assert.throws(() => verifyPreparedClientReadback(initial, effective, attributes, { minimum: 0, maximum: 10000 }));
});

test('owned prerequisite preserves the offline scope identity while removing all default assignments', async () => {
  const { retireOfflineScope } = await runtime();
  const definition = { id: 'offline-id', name: 'offline_access', protocol: 'openid-connect',
    description: 'retained', attributes: { 'consent.screen.text': '${offlineAccessScopeConsentText}' }, protocolMappers: [] };
  const roles = [{ id: 'offline-role', name: 'offline_access', composite: false, clientRole: false }];
  let scopes = [definition, { id: 'profile-id', name: 'profile' }];
  let mappings = roles;
  let cacheCleared = false;
  const calls = [];
  await retireOfflineScope(async (path, method = 'GET', body) => {
    calls.push([path, method]);
    if (method === 'DELETE') { assert.equal(path, 'client-scopes/offline-id'); scopes = scopes.slice(1); mappings = []; return; }
    if (method === 'POST' && path === 'client-scopes') { assert.deepEqual(body, definition); scopes.push(structuredClone(body)); return; }
    if (method === 'POST' && path === 'client-scopes/offline-id/scope-mappings/realm') { assert.deepEqual(body, roles); mappings = body; return; }
    if (method === 'POST' && path === 'clear-realm-cache') {
      assert.deepEqual(mappings, roles); assert.ok(scopes.some(scope => scope.id === definition.id)); cacheCleared = true; return;
    }
    assert.equal(method, 'GET');
    if (path === 'client-scopes') return scopes;
    if (path === 'client-scopes/offline-id') return scopes.find(scope => scope.id === 'offline-id');
    if (path === 'client-scopes/offline-id/scope-mappings') return { realmMappings: mappings };
    if (path === 'client-scopes/offline-id/scope-mappings/realm') return mappings;
    assert.ok(['default-default-client-scopes', 'default-optional-client-scopes'].includes(path)); return cacheCleared ? [] : [definition];
  });
  assert.equal(scopes.find(scope => scope.name === 'offline_access').id, 'offline-id');
  assert.deepEqual(calls.filter(([, method]) => method === 'DELETE'), [['client-scopes/offline-id', 'DELETE']]);
  assert.deepEqual(calls.filter(([path]) => path === 'clear-realm-cache'), [['clear-realm-cache', 'POST']]);
  await assert.rejects(retireOfflineScope(async () => [{ id: 'only-id', name: 'offline_access' }]));
  await assert.rejects(retireOfflineScope(async () => [
    { id: 'offline-id', name: 'offline_access' }, { id: 'profile-id', name: 'profile' }]));
});
