import test from 'node:test';
import assert from 'node:assert/strict';
import { selectNewRecoveryMessage } from '../tooling/recovery-mail.mjs';
import * as recovery from '../tooling/recovery-mail.mjs';

test('recovery polling ignores previous consumed email and other recipients', () => {
  const old = { ID: 'old', To: [{ Address: 'customers@example.invalid' }] };
  const other = { ID: 'other', To: [{ Address: 'workforce@example.invalid' }] };
  const fresh = { ID: 'fresh', To: [{ Address: 'customers@example.invalid' }] };
  assert.equal(selectNewRecoveryMessage([old, other], new Set(['old']), 'customers@example.invalid'), undefined);
  assert.equal(selectNewRecoveryMessage([old, other, fresh], new Set(['old']), 'customers@example.invalid'), fresh);
});

test('reset outcome requires native success or exact fresh callback, never disappearance of the form', () => {
  assert.equal(typeof recovery.passwordResetOutcome, 'function');
  const expected = { issuer: 'http://id.firefly.test:8180/realms/sandbox-customers',
    redirect: 'http://localhost:3000/oidc/callback', state: 'fresh-state' };
  const provider = { url: expected.issuer + '/login-actions/required-action', passwordForm: false, errors: [], success: [] };
  assert.equal(recovery.passwordResetOutcome(provider, expected), 'UNCONFIRMED');
  assert.equal(recovery.passwordResetOutcome({ ...provider, success: ['Your password has been updated.'] }, expected), 'ACCEPTED_MESSAGE');
  assert.equal(recovery.passwordResetOutcome({ ...provider, passwordForm: true, success: ['Your password has been updated.'] }, expected), 'UNCONFIRMED');
  const callback = { ...provider, url: expected.redirect + '?state=fresh-state&code=PRIVATE-CODE' };
  assert.equal(recovery.passwordResetOutcome(callback, expected), 'ACCEPTED_CALLBACK');
  for (const url of [expected.redirect + '?state=old&code=PRIVATE', expected.redirect + '?state=fresh-state',
    expected.redirect + '?state=fresh-state&code=PRIVATE&error=denied',
    expected.redirect + '?state=fresh-state&state=fresh-state&code=PRIVATE',
    expected.redirect + '/extra?state=fresh-state&code=PRIVATE',
    'http://foreign.invalid/oidc/callback?state=fresh-state&code=PRIVATE']) {
    assert.equal(recovery.passwordResetOutcome({ ...callback, url }, expected), 'UNCONFIRMED');
  }
});

test('reset refusal classifies only known messages and never exposes unknown feedback', () => {
  assert.equal(typeof recovery.passwordResetOutcome, 'function');
  const expected = { issuer: 'http://id.firefly.test:8180/realms/sandbox-customers',
    redirect: 'http://localhost:3000/oidc/callback', state: 'fresh-state' };
  const provider = { url: expected.issuer + '/login-actions/required-action', passwordForm: true, success: [] };
  for (const [message, outcome] of [
    ['Invalid password: password is not allowed.', 'REFUSED_DENYLIST'],
    ['Invalid password: must not be equal to any of last 5 passwords.', 'REFUSED_HISTORY'],
    ['Invalid password: minimum length 16.', 'REFUSED_LENGTH'],
    ['Invalid password: must not be equal to the username.', 'REFUSED_IDENTITY'],
    ["Password confirmation doesn't match.", 'REFUSED_CONFIRMATION'],
    ['PRIVATE-PASSWORD PRIVATE-TOKEN', 'REFUSED_OTHER'],
  ]) assert.equal(recovery.passwordResetOutcome({ ...provider, errors: [message] }, expected), outcome);
  assert.equal(recovery.passwordResetOutcome({ ...provider, errors: ['PRIVATE'],
    success: ['Your password has been updated.'], passwordForm: false }, expected), 'REFUSED_OTHER');
});
