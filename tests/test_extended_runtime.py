"""Bounded fixture construction and real-deadline guards; hosted CI runs the browser."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ExtendedAuthenticatorFixtureTest(unittest.TestCase):
    def node(self, source):
        result = subprocess.run(['node', '--input-type=module'], input=source,
                                text=True, capture_output=True, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failure_diagnostics_expose_only_fixed_values_and_source_locations(self):
        self.node("""
import assert from 'node:assert/strict';
import { extendedFailureDiagnostics } from './tooling/extended-runtime.mjs';
const error = { actual: 'PRIVATE_SENTINEL', expected: 201,
  stack: 'Error PRIVATE_SENTINEL https://private.invalid/?token=PRIVATE_SENTINEL\\n at run (file:///owned/tooling/extended-runtime.mjs:123:45)' };
const result = extendedFailureDiagnostics(error);
assert.deepEqual(result.sourceFrames, ['extended-runtime.mjs:123:45']);
assert.equal(result.expected, 201);
assert.equal(result.actualType, 'string');
assert.ok(!JSON.stringify(result).includes('PRIVATE_SENTINEL'));
assert.equal(extendedFailureDiagnostics({ actual: false, expected: true }).actual, false);
assert.equal(extendedFailureDiagnostics({ actual: 'localhost', expected: 'required' }).actual, 'localhost');
assert.equal(extendedFailureDiagnostics({ actual: undefined }).actualType, 'undefined');
assert.ok(!Object.hasOwn(extendedFailureDiagnostics({ actual: 123456789 }), 'actual'));
""")

    def test_admin_routes_are_fixed_categories_without_private_url_parts(self):
        self.node("""
import assert from 'node:assert/strict';
import { extendedRouteClass } from './tooling/extended-runtime.mjs';
const root = 'http://id.firefly.test:8180';
assert.equal(extendedRouteClass(root + '/admin/master/console/?token=PRIVATE_SENTINEL'), 'ADMIN_CONSOLE');
assert.equal(extendedRouteClass(root + '/realms/master/protocol/openid-connect/auth?state=PRIVATE_SENTINEL'), 'MASTER_AUTHORIZATION');
assert.equal(extendedRouteClass(root + '/realms/master/login-actions/authenticate?session_code=PRIVATE_SENTINEL'), 'MASTER_LOGIN_ACTION');
assert.equal(extendedRouteClass(root + '/private/PRIVATE_SENTINEL'), 'OTHER_IDENTITY_ROUTE');
assert.equal(extendedRouteClass('https://PRIVATE_SENTINEL.invalid/private'), 'OTHER_ORIGIN');
assert.equal(extendedRouteClass('about:blank'), 'ABOUT_BLANK');
assert.equal(extendedRouteClass('PRIVATE_SENTINEL'), 'INVALID_URL');
""")

    def test_owned_rp_fixture_does_not_modify_existing_realm_or_open_other_origins(self):
        self.node("""
import assert from 'node:assert/strict';
import { authenticatorFixtureRealm } from './tooling/extended-runtime.mjs';
const source = { realm: 'sandbox-customers', clients: [
  { clientId: 'sandbox-web', publicClient: true }, { clientId: 'retained-confidential', secret: 'sentinel' }],
  users: [{ username: 'retained' }], attributes: { retained: 'unchanged' },
  bruteForceProtected: true, permanentLockout: true, failureFactor: 3 };
const original = structuredClone(source);
const fixture = authenticatorFixtureRealm(source, 'sandbox-authenticators-012345abcdef', 'Aa1-fixture-password');
assert.deepEqual(source, original);
assert.equal(fixture.attributes.frontendUrl, 'http://localhost:8180');
assert.equal(fixture.webAuthnPolicyPasswordlessRpId, 'localhost');
assert.equal(fixture.webAuthnPolicyPasswordlessResidentKey, 'required');
assert.equal(fixture.webAuthnPolicyPasswordlessUserVerificationRequirement, 'required');
assert.deepEqual(fixture.webAuthnPolicyPasswordlessExtraOrigins, []);
assert.deepEqual(fixture.clients.map(client => client.clientId), ['sandbox-web']);
assert.equal(fixture.users.length, 2);
assert.ok(fixture.users.every(user => user.username !== 'retained'));
assert.ok(fixture.users.find(user => !user.emailVerified).requiredActions.includes('VERIFY_EMAIL'));
assert.ok(fixture.users.find(user => user.emailVerified).requiredActions.includes('webauthn-register-passwordless'));
assert.equal(fixture.failureFactor, 3);
for (const name of ['master', 'sandbox-customers', 'sandbox-authenticators-../bad']) {
  assert.throws(() => authenticatorFixtureRealm(source, name, 'Aa1-fixture-password'));
}
""")

    def test_expiry_wait_uses_absolute_deadline_and_bounds_real_wait(self):
        self.node("""
import assert from 'node:assert/strict';
import { verificationExpiryDelay } from './tooling/extended-runtime.mjs';
const claims = { iat: 100, exp: 115 };
assert.equal(verificationExpiryDelay(claims, 100000), 17000);
assert.equal(verificationExpiryDelay(claims, 116500), 500);
assert.equal(verificationExpiryDelay(claims, 117000), 0);
assert.deepEqual(claims, { iat: 100, exp: 115 });
for (const invalid of [{}, { iat: 100, exp: 100 }, { iat: 100, exp: 200 },
  { iat: 100.5, exp: 115 }, { iat: 100, exp: '115' }]) {
  assert.throws(() => verificationExpiryDelay(invalid, 100000));
}
assert.throws(() => verificationExpiryDelay({ iat: 1000, exp: 1015 }, 0));
""")
