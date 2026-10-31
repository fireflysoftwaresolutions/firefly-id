import test from 'node:test';
import assert from 'node:assert/strict';
import { isAuthorizationRefusal } from '../tooling/protocol-assertions.mjs';

const callback = 'http://localhost:3000/oidc/callback';

test('OAuth refusals support query and fragment response modes', () => {
  assert.equal(isAuthorizationRefusal(400, null, callback), true);
  assert.equal(isAuthorizationRefusal(500, null, callback), false);
  assert.equal(isAuthorizationRefusal(302, `${callback}?error=invalid_request`, callback), true);
  assert.equal(isAuthorizationRefusal(302, `${callback}#error=unauthorized_client`, callback), true);
});

test('OAuth negatives reject success, tokens and alternate callback paths', () => {
  for (const location of [
    `${callback}?code=synthetic`,
    `${callback}#error=invalid_request&access_token=synthetic`,
    `${callback}-other?error=invalid_request`,
    'https://attacker.invalid/callback?error=invalid_request',
  ]) assert.equal(isAuthorizationRefusal(302, location, callback), false);
});
