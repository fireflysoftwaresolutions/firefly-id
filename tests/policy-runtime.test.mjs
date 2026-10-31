import assert from 'node:assert/strict';
import test from 'node:test';
import { assertPermanentBlock, waitForPermanentBlock } from '../tooling/policy-runtime.mjs';

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
