import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

async function actions() {
  assert.ok(existsSync(new URL('../tooling/master-action-links.mjs', import.meta.url)), 'Owned action-link boundary is missing');
  return import('../tooling/master-action-links.mjs');
}
const origin = 'https://id.firefly.test:8443';
const issuer = origin + '/realms/master';
const subject = 'synthetic-subject';
const now = 1000_000;
function message(overrides = {}, urlOrigin = origin) {
  const claims = { iss: issuer, aud: issuer, sub: subject, typ: 'execute-actions', iat: 1000, exp: 1120,
    rqac: ['UPDATE_PASSWORD'], azp: 'security-admin-console', reduri: origin + '/admin/master/console/fixture-return', ...overrides };
  const compact = [Buffer.from(JSON.stringify({ alg: 'HS512', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify(claims)).toString('base64url'), Buffer.alloc(64).toString('base64url')].join('.');
  return { HTML: '<a href="' + urlOrigin + '/realms/master/login-actions/action-token?key=' + compact + '">Confirm</a>' };
}

test('action fixture admits only bounded owned UPDATE_PASSWORD links and preserves their signed URL', async () => {
  const { parseMasterAction } = await actions();
  const original = message(); const parsed = parseMasterAction(original, subject, now);
  assert.equal(parsed.claims.exp, 1120); assert.ok(original.HTML.includes(parsed.url.href));
  for (const change of [{ iss: 'https://production.test/realms/master' }, { sub: 'other' }, { exp: 5000 },
    { exp: 999 }, { typ: 'verify-email' }, { rqac: ['UPDATE_PASSWORD', 'CONFIGURE_TOTP'] }, { azp: 'account-console' }]) {
    assert.throws(() => parseMasterAction(message(change), subject, now));
  }
  assert.throws(() => parseMasterAction(message({}, 'https://production.test'), subject, now));
});

test('action expiry waiting is bounded and uses original signed expiry, never a reset lifetime', async () => {
  const { actionExpiryWait } = await actions();
  assert.equal(actionExpiryWait([{ iat: 1000, exp: 1120 }], now), 122000);
  assert.equal(actionExpiryWait([{ iat: 1000, exp: 1120 }], 1123_000), 0);
  assert.throws(() => actionExpiryWait([{ iat: 1000, exp: 5000 }], now));
  assert.throws(() => actionExpiryWait([{ iat: 1000, exp: 1120 }], 500_000));
});
