import test from 'node:test';
import assert from 'node:assert/strict';
import { selectNewRecoveryMessage } from '../tooling/recovery-mail.mjs';

test('recovery polling ignores previous consumed email and other recipients', () => {
  const old = { ID: 'old', To: [{ Address: 'customers@example.invalid' }] };
  const other = { ID: 'other', To: [{ Address: 'workforce@example.invalid' }] };
  const fresh = { ID: 'fresh', To: [{ Address: 'customers@example.invalid' }] };
  assert.equal(selectNewRecoveryMessage([old, other], new Set(['old']), 'customers@example.invalid'), undefined);
  assert.equal(selectNewRecoveryMessage([old, other, fresh], new Set(['old']), 'customers@example.invalid'), fresh);
});
