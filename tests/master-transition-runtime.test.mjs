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
  const result = retainedOperations(controls, ['attributes', 'browserFlow', 'directGrantFlow', 'authenticationFlows', 'requiredActions']);
  assert.equal(result.flows.length, 2);
  assert.deepEqual(Object.keys(result.realm).sort(), CONTROL_KEYS.filter(key => !['authenticationFlows', 'requiredActions'].includes(key)).sort());
  const incomplete = { ...controls }; delete incomplete.webAuthnPolicyUserVerificationRequirement;
  assert.throws(() => retainedOperations(incomplete));
  assert.ok(!JSON.stringify(result).includes('must-not'));
  assert.throws(() => retainedOperations({ ...controls, authenticationFlows: [] }, ['browserFlow', 'authenticationFlows']));
});

test('runtime failure diagnostics expose only whitelisted class and owned source positions', async () => {
  const { safeRuntimeFailure } = await runtime();
  assert.equal(typeof safeRuntimeFailure, 'function', 'Safe runtime failure context is missing');
  const error = { name: 'TimeoutError', message: 'PRIVATE-TOKEN', stack: 'TimeoutError PRIVATE-TOKEN\n at start (file:///owned/tooling/master-transition-runtime.mjs:145:21)\n at other (file:///PRIVATE-PATH/file.mjs:12:3)' };
  assert.deepEqual(safeRuntimeFailure(error), { errorKind: 'TimeoutError', sourceFrames: ['master-transition-runtime.mjs:145:21'] });
  assert.deepEqual(safeRuntimeFailure({ name: 'PRIVATE-TYPE', message: 'PRIVATE-TOKEN', stack: 'PRIVATE' }), { errorKind: 'OTHER', sourceFrames: [] });
});
