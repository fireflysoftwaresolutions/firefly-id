import assert from 'node:assert/strict';
import test from 'node:test';
import { assertPermanentBlock, waitForPermanentBlock } from '../tooling/policy-runtime.mjs';
import * as policy from '../tooling/policy-runtime.mjs';

test('administrative refusal classifies password keys without retaining descriptions or supplied values', async () => {
  assert.equal(typeof policy.readAdminValidation, 'function');
  const result = await policy.readAdminValidation(new Response(JSON.stringify({
    error: 'invalidPasswordBlacklistedMessage', error_description: 'DO-NOT-PRINT password or token',
  }), { status: 400 }));
  assert.deepEqual(result, { categories: ['PASSWORD_DENYLIST'], fields: [] });
  assert.ok(!JSON.stringify(result).includes('DO-NOT-PRINT'));
});

test('administrative profile refusals preserve only fixed field and validation categories', async () => {
  assert.equal(typeof policy.readAdminValidation, 'function');
  const result = await policy.readAdminValidation(new Response(JSON.stringify({ errors: [
    { field: 'username', errorMessage: 'error-invalid-length', params: ['DO-NOT-PRINT', 255] },
    { field: 'email', errorMessage: 'error-invalid-email', params: ['private@example.invalid'] },
    { field: 'DO-NOT-PRINT', errorMessage: 'missingFirstNameMessage' },
  ] }), { status: 400 }));
  assert.deepEqual(result, { categories: ['PROFILE_EMAIL', 'PROFILE_LENGTH', 'PROFILE_REQUIRED'], fields: ['email', 'username'] });
  for (const secret of ['DO-NOT-PRINT', 'private@example.invalid', '255']) assert.ok(!JSON.stringify(result).includes(secret));
});

test('administrative refusal classification does not match untrusted substrings or parameter text', async () => {
  assert.equal(typeof policy.readAdminValidation, 'function');
  const result = await policy.readAdminValidation(new Response(JSON.stringify({
    error: 'invalidPasswordBlacklistedMessage-DO-NOT-PRINT',
    params: ['invalidPasswordHistoryMessage'], error_description: 'Could not create user',
  }), { status: 400 }));
  assert.deepEqual(result, { categories: ['UNKNOWN_ADMIN_VALIDATION'], fields: [] });
});

test('administrative refusal bodies are bounded and malformed bodies remain secret-safe', async () => {
  assert.equal(typeof policy.readAdminValidation, 'function');
  assert.deepEqual(await policy.readAdminValidation(new Response('DO-NOT-PRINT'.repeat(2000))),
    { categories: ['ADMIN_BODY_TOO_LARGE'], fields: [] });
  assert.deepEqual(await policy.readAdminValidation(new Response('DO-NOT-PRINT not JSON')),
    { categories: ['ADMIN_BODY_NOT_JSON'], fields: [] });
  assert.deepEqual(await policy.readAdminValidation(new Response(JSON.stringify(['DO-NOT-PRINT']))),
    { categories: ['UNKNOWN_ADMIN_VALIDATION'], fields: [] });
});

test('administrative refusal read failures never expose exception text', async () => {
  assert.equal(typeof policy.readAdminValidation, 'function');
  const body = new ReadableStream({ start(controller) { controller.error(new Error('DO-NOT-PRINT')); } });
  assert.deepEqual(await policy.readAdminValidation(new Response(body)),
    { categories: ['ADMIN_BODY_UNREADABLE'], fields: [] });
});

test('permanent blocking requires the disabled user and native lock reason, independently of counters', () => {
  assertPermanentBlock({ enabled: false, attributes: { disabledReason: ['permanentLockout'] } });
  assert.throws(() => assertPermanentBlock({ enabled: true, attributes: { disabledReason: ['permanentLockout'] } }));
  assert.throws(() => assertPermanentBlock({ enabled: false, attributes: { disabledReason: ['administrativeHold'] } }));
  assert.throws(() => assertPermanentBlock({ enabled: false, attributes: {} }));
  assert.throws(() => assertPermanentBlock({ enabled: false, attributes: { disabledReason: ['permanentLockout', 'administrativeHold'] } }));
});

test('permanent-state polling waits for both the exact failure count and authoritative disabling', async () => {
  const blocked = { enabled: false, attributes: { disabledReason: ['permanentLockout'] } };
  const samples = [
    { counter: { numFailures: 2, disabled: false }, user: { enabled: true } },
    { counter: { numFailures: 3, disabled: false }, user: blocked },
    { counter: { numFailures: 3, disabled: true }, user: blocked },
  ];
  let reads = 0;
  const observed = await waitForPermanentBlock(async () => samples[reads++],
    { maxPolls: 3, intervalMs: 0 });
  assert.equal(reads, 3);
  assert.equal(observed.counter.numFailures, 3);
  assertPermanentBlock(observed.user);
});

test('permanent-state polling is bounded and cannot accept only a disabled user or only a counter', async () => {
  for (const sample of [
    { counter: { numFailures: 2, disabled: true }, user: { enabled: false, attributes: { disabledReason: ['permanentLockout'] } } },
    { counter: { numFailures: 3, disabled: true }, user: { enabled: true } },
    { counter: { numFailures: 3, disabled: true }, user: { enabled: false, attributes: { disabledReason: ['administrativeHold'] } } },
  ]) {
    let reads = 0;
    await assert.rejects(() => waitForPermanentBlock(async () => { reads++; return sample; },
      { maxPolls: 2, intervalMs: 0 }));
    assert.equal(reads, 2);
  }
});
