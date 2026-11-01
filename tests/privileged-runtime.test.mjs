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
