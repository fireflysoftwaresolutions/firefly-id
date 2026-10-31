import test from 'node:test';
import assert from 'node:assert/strict';
import { consoleErrorGroup, consoleResourceGroup } from '../tooling/console-diagnostics.mjs';

test('console failure categories never retain credential-bearing URL or exception text', () => {
  const secret = 'PRIVATE_SENTINEL';
  for (const address of [
    `http://id.firefly.test:8180/resources/version/account/firefly-id/assets/main.js?token=${secret}`,
    `http://id.firefly.test:8180/realms/sandbox-customers/protocol/openid-connect/token?code=${secret}`,
    `http://id.firefly.test:8180/admin/realms/${secret}/users/${secret}`,
    secret,
  ]) assert.ok(!consoleResourceGroup(address).includes(secret));
  for (const message of [`Web Crypto API unavailable ${secret}`, `Unexpected token ${secret}`, secret]) {
    assert.ok(!consoleErrorGroup(new Error(message)).includes(secret));
  }
});

test('console diagnostics distinguish shared assets, account APIs and initialization failures', () => {
  assert.equal(consoleResourceGroup('http://id.firefly.test:8180/resources/version/common/keycloak/vendor/react.js'), 'shared-asset');
  assert.equal(consoleResourceGroup('http://id.firefly.test:8180/resources/sandbox-customers/account/en'), 'account-messages');
  assert.equal(consoleResourceGroup('http://id.firefly.test:8180/realms/sandbox-customers/account/'), 'account-api');
  assert.equal(consoleErrorGroup(new Error('Web Crypto API is not available')), 'secure-context');
  assert.equal(consoleErrorGroup(new Error('Failed to fetch dynamically imported module')), 'module-loading');
});
