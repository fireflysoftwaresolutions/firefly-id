import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';

async function fixture() {
  assert.ok(existsSync(new URL('../tooling/privileged-runtime.mjs', import.meta.url)), 'Privileged virtual-key fixture is not implemented');
  return import('../tooling/privileged-runtime.mjs');
}
const password = 'synthetic-fixture-password-1234!';
const origin = 'https://id.firefly.test:8443';
const callback = 'https://localhost:8448/oidc/callback';

test('privileged fixture refuses master, other origins, and unowned realm names', async () => {
  const { privilegedFixtureRealm } = await fixture();
  for (const name of ['master', 'customers', 'native-privileged-existing', 'native-privileged-123456789abc/../../master']) {
    assert.throws(() => privilegedFixtureRealm(name, password, origin, callback));
  }
  assert.throws(() => privilegedFixtureRealm('native-privileged-123456789abc', password, 'https://production.example.com', callback));
});

test('fixture enrolls two-factor WebAuthn and keeps the guarded sign-in separate', async () => {
  const { privilegedFixtureRealm } = await fixture();
  const realm = privilegedFixtureRealm('native-privileged-123456789abc', password, origin, callback);
  assert.equal(realm.browserFlow, 'fixture-supervised-enrollment');
  assert.equal(realm.loginTheme, 'firefly-id');
  assert.equal(realm.webAuthnPolicyUserVerificationRequirement, 'required');
  assert.equal(realm.webAuthnPolicyPasswordlessPasskeysEnabled, false);
  assert.equal(realm.requiredActions[0].providerId, 'webauthn-register');
  const flow = realm.authenticationFlows.find(value => value.alias === 'fixture-privileged');
  assert.deepEqual(flow.authenticationExecutions.map(value => value.authenticator),
    ['auth-username-password-form', 'firefly-privileged-webauthn']);
  assert.ok(flow.authenticationExecutions.every(value => value.requirement === 'REQUIRED' && !value.authenticatorFlow));
  assert.equal(realm.users[0].requiredActions[0], 'webauthn-register');
  assert.deepEqual(realm.users[1].requiredActions, []);
});

test('owned runtime client has PKCE and no direct, implicit, service, or alternate flow grant', async () => {
  const { privilegedFixtureRealm } = await fixture();
  const realm = privilegedFixtureRealm('native-privileged-123456789abc', password, origin, callback);
  const client = realm.clients[0];
  assert.equal(client.attributes['pkce.code.challenge.method'], 'S256');
  for (const key of ['directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled']) assert.equal(client[key], false);
  assert.deepEqual(client.redirectUris, [callback]);
  assert.deepEqual(client.authenticationFlowBindingOverrides, {});
});


test('assertion inspection distinguishes a genuinely signed missing-UV response from a wrong key', async () => {
  const { assertionProperties } = await fixture();
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const enrolled = { privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64') };
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: 'synthetic', origin }));
  for (const verified of [true, false]) {
    const data = Buffer.alloc(37); data[32] = verified ? 5 : 1;
    const payload = Buffer.concat([data, createHash('sha256').update(client).digest()]);
    const signature = sign('sha256', payload, privateKey);
    const post = new URLSearchParams({ authenticatorData: data.toString('base64url'),
      clientDataJSON: client.toString('base64url'), signature: signature.toString('base64url') });
    assert.deepEqual(assertionProperties(post.toString(), enrolled), { userVerified: verified, signedByEnrolledKey: true });
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    post.set('signature', sign('sha256', payload, other).toString('base64url'));
    assert.deepEqual(assertionProperties(post.toString(), enrolled), { userVerified: verified, signedByEnrolledKey: false });
  }
  assert.throws(() => assertionProperties('authenticatorData=AA', enrolled));
});


test('privileged browser qualification refuses non-hosted or non-Linux ownership before any runtime API', async () => {
  const { qualifyPrivilegedAdministration } = await fixture();
  const previous = Object.fromEntries(['GITHUB_ACTIONS', 'RUNNER_OS', 'RUNNER_ENVIRONMENT'].map(key => [key, process.env[key]]));
  try {
    for (const [runner, os] of [['self-hosted', 'Linux'], ['github-hosted', 'macOS']]) {
      Object.assign(process.env, { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: runner, RUNNER_OS: os });
      await assert.rejects(qualifyPrivilegedAdministration({ origin, callback, pending: new Map() }), /Owned hosted Linux runner required/);
    }
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test('privileged update diagnostics retain only bounded status, known client, categories and boolean controls', async () => {
  const { privilegedWriteDiagnostic } = await fixture();
  assert.equal(typeof privilegedWriteDiagnostic, 'function', 'Bounded administrative update diagnostics are missing');
  const response = new Response(JSON.stringify({ error: 'invalid_input', error_description: 'Root URL is not a valid URL: PRIVATE-RESPONSE',
    secret: 'PRIVATE-RESPONSE' }), { status: 400 });
  const diagnostic = await privilegedWriteDiagnostic(response, { operation: 'CLIENT_UPDATE', clientId: 'account',
    body: { enabled: false, standardFlowEnabled: false, publicClient: true, secret: 'PRIVATE-REQUEST', attributes: { private: 'PRIVATE-REQUEST' } } });
  assert.deepEqual(diagnostic, { status: 400, operation: 'CLIENT_UPDATE', client: 'account',
    controls: { enabled: false, standardFlowEnabled: false, publicClient: true }, categories: ['INVALID_INPUT', 'URL_VALIDATION'] });
  assert.doesNotMatch(JSON.stringify(diagnostic), /PRIVATE|secret|attributes/);
});

test('privileged update diagnostics do not echo unknown clients, operations, fields or response messages', async () => {
  const { privilegedWriteDiagnostic } = await fixture();
  assert.equal(typeof privilegedWriteDiagnostic, 'function');
  const diagnostic = await privilegedWriteDiagnostic(new Response(JSON.stringify({ error: 'PRIVATE-ERROR', errorMessage: 'PRIVATE-BODY' }), { status: 403 }),
    { operation: 'PRIVATE-PATH', clientId: 'PRIVATE-CLIENT', body: { enabled: 'PRIVATE-FIELD', password: 'PRIVATE-PASSWORD' } });
  assert.deepEqual(diagnostic, { status: 403, operation: 'OTHER', client: 'OTHER', controls: {}, categories: ['HTTP_FORBIDDEN', 'UNCLASSIFIED'] });
  assert.doesNotMatch(JSON.stringify(diagnostic), /PRIVATE/);
});

test('privileged update diagnostics stop reading oversized responses and classify malformed JSON safely', async () => {
  const { privilegedWriteDiagnostic } = await fixture();
  assert.equal(typeof privilegedWriteDiagnostic, 'function');
  const oversized = await privilegedWriteDiagnostic(new Response('PRIVATE'.repeat(3000), { status: 500 }), {});
  assert.deepEqual(oversized.categories, ['BODY_TOO_LARGE', 'HTTP_SERVER_ERROR']);
  const malformed = await privilegedWriteDiagnostic(new Response('<html>PRIVATE</html>', { status: 502 }), {});
  assert.deepEqual(malformed.categories, ['BODY_NOT_JSON', 'HTTP_SERVER_ERROR']);
  assert.doesNotMatch(JSON.stringify([oversized, malformed]), /PRIVATE/);
});

function clientInventory() {
  return ['account', 'account-console', 'admin-cli', 'broker', 'realm-management', 'security-admin-console', 'privileged-fixture-browser'].map(clientId => ({
    id: `synthetic-${clientId}`, clientId, protocol: 'openid-connect', enabled: true,
    bearerOnly: clientId === 'realm-management', publicClient: clientId !== 'realm-management',
    standardFlowEnabled: true, directAccessGrantsEnabled: clientId === 'admin-cli',
    implicitFlowEnabled: false, serviceAccountsEnabled: false, authenticationFlowBindingOverrides: {},
    attributes: clientId === 'realm-management' ? { realm_client: 'true' } : {},
  }));
}

test('client transition preserves the internal bearer-only resource without a forbidden PUT and verifies every readback', async () => {
  const { hardenPrivilegedFixtureClients } = await fixture();
  assert.equal(typeof hardenPrivilegedFixtureClients, 'function');
  const inventory = clientInventory();
  const retained = structuredClone(inventory.find(client => client.clientId === 'realm-management'));
  const writes = [];
  await hardenPrivilegedFixtureClients({ read: async () => structuredClone(inventory), write: async (path, body) => {
    writes.push(path); Object.assign(inventory.find(client => path === `clients/${client.id}`), body);
  } });
  assert.equal(writes.length, 6);
  assert.ok(!writes.includes(`clients/${retained.id}`));
  assert.deepEqual(inventory.find(client => client.clientId === 'realm-management'), retained);
  for (const client of inventory.filter(client => client.clientId !== 'realm-management')) {
    assert.equal(client.enabled, client.clientId === 'privileged-fixture-browser');
    assert.equal(client.standardFlowEnabled, client.clientId === 'privileged-fixture-browser');
    assert.equal(client.directAccessGrantsEnabled, false);
  }
});

test('unsafe internal resources and incomplete or ineffective client readbacks refuse transition', async () => {
  const { hardenPrivilegedFixtureClients } = await fixture();
  assert.equal(typeof hardenPrivilegedFixtureClients, 'function');
  for (const mutation of [{ bearerOnly: false }, { publicClient: true }, { serviceAccountsEnabled: true },
    { directAccessGrantsEnabled: true }, { implicitFlowEnabled: true }, { authenticationFlowBindingOverrides: { browser: 'weak' } },
    { attributes: { 'oidc.ciba.grant.enabled': 'true' } }]) {
    const inventory = clientInventory(); Object.assign(inventory[4], mutation); let writes = 0;
    await assert.rejects(hardenPrivilegedFixtureClients({ read: async () => inventory, write: async () => { writes++; } }));
    assert.equal(writes, 0);
  }
  await assert.rejects(hardenPrivilegedFixtureClients({ read: async () => clientInventory(), write: async () => {} }),
    /client controls were not retained/);
  let reads = 0;
  await assert.rejects(hardenPrivilegedFixtureClients({ read: async () => ++reads === 1 ? clientInventory() : clientInventory().slice(1),
    write: async () => {} }), /client inventory changed/);
});
