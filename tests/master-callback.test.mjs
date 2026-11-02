import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

async function helper() {
  assert.ok(existsSync(new URL('../tooling/master-callback.mjs', import.meta.url)), 'Exact callback predicate is missing');
  return import('../tooling/master-callback.mjs');
}
const callback = 'https://id.firefly.test:8443/admin/master/console/fixture-return';

test('callback predicate admits exact owned callback with raw or encoded issuer query slashes', async () => {
  const { isMasterCallback } = await helper();
  for (const query of ['?state=synthetic&code=synthetic&iss=https://id.firefly.test:8443/realms/master',
    '?state=synthetic&iss=https%3A%2F%2Fid.firefly.test%3A8443%2Frealms%2Fmaster&code=synthetic', '?error=access_denied']) {
    assert.equal(isMasterCallback(new URL(callback + query)), true);
  }
  for (const value of [callback + '/other', callback.replace('8443', '8444'), callback.replace('https:', 'http:'),
    callback.replace('id.firefly.test', 'production.test'), callback.replace('fixture-return', 'fixture-return-extra'),
    callback.replace('/admin/master/', '/admin/other/'), 'not-a-url', callback.replace('https://', 'https://user@')]) {
    assert.equal(isMasterCallback(value), false);
  }
});

test('navigation diagnostics discard callback codes, errors, issuers and unknown paths', async () => {
  const { masterRouteClass } = await helper();
  assert.equal(masterRouteClass(callback + '?code=PRIVATE&iss=https://PRIVATE'), 'OWNED_CALLBACK');
  assert.equal(masterRouteClass('https://id.firefly.test:8443/realms/master/login-actions/required-action?session_code=PRIVATE'), 'MASTER_REQUIRED_ACTION');
  assert.equal(masterRouteClass('https://id.firefly.test:8443/PRIVATE'), 'OWNED_OTHER');
  assert.equal(masterRouteClass('https://PRIVATE/path'), 'OTHER_ORIGIN');
});

test('redirect-request callback observation requires one exact state before exposing its code', async () => {
  const { masterCallbackResult } = await helper();
  assert.equal(typeof masterCallbackResult, 'function');
  const url = callback + '?state=owned-state&code=synthetic&iss=https://id.firefly.test:8443/realms/master';
  assert.equal(masterCallbackResult(url, 'owned-state').searchParams.get('code'), 'synthetic');
  assert.equal(masterCallbackResult(url, 'wrong-state'), null);
  assert.equal(masterCallbackResult(url + '&state=owned-state', 'owned-state'), null);
  assert.equal(masterCallbackResult(url.replace('id.firefly.test:8443/admin', 'other.test/admin'), 'owned-state'), null);
});

test('callback observer completes once and ignores wrong-state redirect requests', async () => {
  const { masterCallbackObserver } = await helper();
  assert.equal(typeof masterCallbackObserver, 'function');
  const received = []; const observe = masterCallbackObserver('owned-state', value => received.push(value));
  observe(callback + '?state=wrong-state&code=wrong');
  assert.equal(received.length, 0);
  observe(callback + '?state=owned-state&code=real');
  observe(callback + '?state=owned-state&code=replayed');
  assert.equal(received.length, 1); assert.equal(received[0].searchParams.get('code'), 'real');
});
