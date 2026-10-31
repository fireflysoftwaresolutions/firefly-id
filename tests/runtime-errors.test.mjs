import test from 'node:test';
import assert from 'node:assert/strict';
import { reportFailure } from '../tooling/safe-errors.mjs';

test('navigation failure never emits token-bearing message, stack or cause', () => {
  const sentinel = 'SYNTHETIC_TOKEN_MUST_NEVER_BE_LOGGED';
  const failure = new Error(`Navigating https://example.invalid/logout?id_token_hint=${sentinel}`, {
    cause: new Error(sentinel),
  });
  let output = '';
  reportFailure(failure, 'protocol checks', { write: value => { output += value; } });
  assert.ok(!output.includes(sentinel));
  assert.ok(!output.includes('https://'));
  assert.ok(output.includes('protocol checks'));
});

test('untrusted error names cannot leak a token', () => {
  const failure = new Error('private');
  failure.name = 'SYNTHETIC_SECRET_NAME';
  let output = '';
  reportFailure(failure, 'none', { write: value => { output += value; } });
  assert.ok(!output.includes('SYNTHETIC_SECRET_NAME'));
});
