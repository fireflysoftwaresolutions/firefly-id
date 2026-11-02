import assert from 'node:assert/strict';
import test from 'node:test';
import { assertPermanentBlock, waitForPermanentBlock } from '../tooling/policy-runtime.mjs';
import * as policy from '../tooling/policy-runtime.mjs';

function fixtureSubmission(responses, users = []) {
  const fixture = { username: 'owned-policy-fixture', password: 'initial private random password' };
  const saved = [];
  let posts = 0;
  let reads = 0;
  const options = {
    persist: async () => { saved.push(structuredClone(fixture)); },
    create: async () => {
      assert.equal(saved.at(-1).operations.at(-1).operation, 'create');
      assert.equal(saved.at(-1).password, fixture.password);
      return responses[posts++]();
    },
    readUsers: async () => {
      assert.equal(saved.at(-1).operations.at(-1).operation, 'confirm-absent');
      reads++;
      return users;
    },
    recordValidation: () => {},
  };
  return { fixture, options, saved, counts: () => ({ posts, reads }) };
}
const deniedCreation = () => new Response(JSON.stringify({ error: 'invalidPasswordBlacklistedMessage' }), { status: 400 });
const acceptedCreation = () => new Response(null, { status: 201 });

function passwordReplacement(responses, expectedStatus = 204) {
  const fixture = { password: 'old private password', operations: [] };
  const saved = []; const evidence = [];
  let requests = 0; let regenerations = 0;
  const value = 'a'.repeat(128);
  const options = {
    value, expectedStatus, boundary: 'at-maximum',
    persist: async () => saved.push(structuredClone(fixture)),
    replace: async candidate => {
      assert.equal(saved.at(-1).operations.at(-1).password, candidate);
      return responses[requests++]();
    },
    regenerate: size => { regenerations++; return String.fromCharCode(97 + regenerations).repeat(size); },
    recordValidation: validation => evidence.push(validation),
  };
  return { fixture, options, saved, evidence, counts: () => ({ requests, regenerations }) };
}
const acceptedReplacement = () => new Response(null, { status: 204 });

test('password boundary replacement preserves length and accepted history value after exclusive denylist refusal', async () => {
  const input = passwordReplacement([deniedCreation, acceptedReplacement]);
  const accepted = await policy.replacePolicyPassword(input.fixture, input.options);
  assert.equal(accepted.length, 128);
  assert.notEqual(accepted, input.options.value);
  assert.equal(input.fixture.password, accepted);
  assert.deepEqual(input.counts(), { requests: 2, regenerations: 1 });
  assert.deepEqual(input.evidence.map(item => item.categories), [['PASSWORD_DENYLIST'], []]);
  assert.deepEqual(input.fixture.operations.map(item => item.status), [400, 204]);
});

test('password boundary replacement stops after eight exclusive denylist refusals', async () => {
  const input = passwordReplacement(Array.from({ length: 8 }, () => deniedCreation));
  await assert.rejects(() => policy.replacePolicyPassword(input.fixture, input.options));
  assert.deepEqual(input.counts(), { requests: 8, regenerations: 7 });
  assert.equal(input.evidence.length, 8);
  assert.equal(input.fixture.password, 'old private password');
});

test('password replacement never regenerates other statuses, unknown categories or mixed refusals', async () => {
  for (const [status, body] of [
    [400, { error: 'invalidPasswordMaxLengthMessage' }],
    [400, { error: 'unrecognized private failure' }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: [{ errorMessage: 'invalidPasswordHistoryMessage' }] }],
    [401, { error: 'invalidPasswordBlacklistedMessage' }],
    [500, { error: 'invalidPasswordBlacklistedMessage' }],
  ]) {
    const input = passwordReplacement([() => new Response(JSON.stringify(body), { status })]);
    await assert.rejects(() => policy.replacePolicyPassword(input.fixture, input.options));
    assert.deepEqual(input.counts(), { requests: 1, regenerations: 0 });
    assert.equal(input.evidence[0].status, status);
    assert.ok(input.evidence[0].categories.length);
    assert.equal(input.saved.at(-1).operations[0].status, status);
    assert.equal(input.fixture.password, 'old private password');
  }
});

test('expected password policy refusals are recorded without replacing their probe', async () => {
  const input = passwordReplacement([deniedCreation], 400);
  input.options.boundary = 'denylist';
  assert.equal(await policy.replacePolicyPassword(input.fixture, input.options), input.options.value);
  assert.deepEqual(input.counts(), { requests: 1, regenerations: 0 });
  assert.deepEqual(input.evidence[0].categories, ['PASSWORD_DENYLIST']);
  assert.equal(input.fixture.password, 'old private password');
});

test('negative password boundaries require their exact category and never regenerate another refusal', async () => {
  const categories = {
    'below-minimum': 'invalidPasswordMinLengthMessage', 'above-maximum': 'invalidPasswordMaxLengthMessage',
    denylist: 'invalidPasswordBlacklistedMessage', username: 'invalidPasswordNotUsernameMessage',
    email: 'invalidPasswordNotEmailMessage', history: 'invalidPasswordHistoryMessage',
  };
  for (const [boundary, error] of Object.entries(categories)) {
    const accepted = passwordReplacement([() => new Response(JSON.stringify({ error }), { status: 400 })], 400);
    accepted.options.boundary = boundary;
    await policy.replacePolicyPassword(accepted.fixture, accepted.options);
    assert.deepEqual(accepted.counts(), { requests: 1, regenerations: 0 });
    for (const body of [
      { error: error === categories.denylist ? categories.history : categories.denylist },
      { error, errors: [{ errorMessage: 'unrecognized private failure' }] },
    ]) {
      const refused = passwordReplacement([() => new Response(JSON.stringify(body), { status: 400 })], 400);
      refused.options.boundary = boundary;
      await assert.rejects(() => policy.replacePolicyPassword(refused.fixture, refused.options));
      assert.deepEqual(refused.counts(), { requests: 1, regenerations: 0 });
      assert.equal(refused.evidence[0].status, 400);
      assert.equal(refused.fixture.password, 'old private password');
    }
  }
});

test('replacement refuses changed-length regeneration and unpersisted intent before another write', async () => {
  const input = passwordReplacement([deniedCreation]);
  input.options.regenerate = () => 'short';
  await assert.rejects(() => policy.replacePolicyPassword(input.fixture, input.options));
  assert.equal(input.counts().requests, 1);
  const failedPersistence = passwordReplacement([acceptedReplacement]);
  failedPersistence.options.persist = async () => { throw new Error('unavailable private state'); };
  await assert.rejects(() => policy.replacePolicyPassword(failedPersistence.fixture, failedPersistence.options));
  assert.equal(failedPersistence.counts().requests, 0);
});

test('fixture creation accepts 201 without retrying or checking absence', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  const submission = fixtureSubmission([acceptedCreation]);
  assert.equal((await policy.submitPolicyFixture(submission.fixture, submission.options)).status, 201);
  assert.deepEqual(submission.counts(), { posts: 1, reads: 0 });
});

test('exact denylist refusal regenerates only after persisted absence verification', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  const submission = fixtureSubmission([deniedCreation, deniedCreation, acceptedCreation]);
  assert.equal((await policy.submitPolicyFixture(submission.fixture, submission.options)).status, 201);
  assert.deepEqual(submission.counts(), { posts: 3, reads: 2 });
  const creations = submission.fixture.operations.filter(operation => operation.operation === 'create');
  assert.equal(new Set(creations.map(operation => operation.password)).size, 3);
  assert.deepEqual(submission.fixture.operations.map(operation => operation.operation),
    ['create', 'confirm-absent', 'create', 'confirm-absent', 'create']);
});

test('denylist regeneration is bounded even when every candidate is refused', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  const submission = fixtureSubmission([deniedCreation, deniedCreation, deniedCreation]);
  await assert.rejects(() => policy.submitPolicyFixture(submission.fixture, submission.options));
  assert.deepEqual(submission.counts(), { posts: 3, reads: 3 });
});

test('other statuses and mixed or unknown validation failures never trigger regeneration', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  for (const [status, body] of [
    [400, { error: 'invalidPasswordMinLengthMessage' }],
    [400, { error: 'Could not create user' }],
    [400, { error: 'unrecognized private failure' }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: [{ errorMessage: 'unrecognized private failure' }] }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: [null] }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: [{}] }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: [{ field: 'email' }] }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: 'malformed' }],
    [400, { error: 'invalidPasswordBlacklistedMessage', errors: Array.from({ length: 33 }, () => ({ errorMessage: 'invalidPasswordBlacklistedMessage' })) }],
    [400, { errors: [{ errorMessage: 'invalidPasswordBlacklistedMessage' }, { errorMessage: 'error-invalid-email' }] }],
    [409, { error: 'invalidPasswordBlacklistedMessage' }],
    [500, { error: 'invalidPasswordBlacklistedMessage' }],
    [401, { error: 'invalidPasswordBlacklistedMessage' }],
  ]) {
    const submission = fixtureSubmission([() => new Response(JSON.stringify(body), { status })]);
    await assert.rejects(() => policy.submitPolicyFixture(submission.fixture, submission.options));
    assert.deepEqual(submission.counts(), { posts: 1, reads: 0 });
  }
});

test('a surviving user or an uncertain administrative read prevents regeneration', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  for (const users of [[{ id: 'unexpected-existing-user' }], {}, null]) {
    const submission = fixtureSubmission([deniedCreation], users);
    await assert.rejects(() => policy.submitPolicyFixture(submission.fixture, submission.options));
    assert.deepEqual(submission.counts(), { posts: 1, reads: 1 });
  }
  const submission = fixtureSubmission([deniedCreation]);
  submission.options.readUsers = async () => { throw new Error('private read failure'); };
  await assert.rejects(() => policy.submitPolicyFixture(submission.fixture, submission.options));
  assert.equal(submission.counts().posts, 1);
});

test('baseline probe requires exact denylist refusal and no user, and never regenerates', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  const submission = fixtureSubmission([deniedCreation]);
  assert.equal(await policy.submitPolicyFixture(submission.fixture, { ...submission.options, expectDenylist: true }), null);
  assert.deepEqual(submission.counts(), { posts: 1, reads: 1 });
  assert.equal(submission.fixture.password, 'initial private random password');
  const accepted = fixtureSubmission([acceptedCreation]);
  await assert.rejects(() => policy.submitPolicyFixture(accepted.fixture, { ...accepted.options, expectDenylist: true }));
  assert.deepEqual(accepted.counts(), { posts: 1, reads: 0 });
});

test('fixture operations cannot run when their intent cannot be persisted', async () => {
  assert.equal(typeof policy.submitPolicyFixture, 'function');
  const submission = fixtureSubmission([acceptedCreation]);
  submission.options.persist = async () => { throw new Error('private storage failure'); };
  await assert.rejects(() => policy.submitPolicyFixture(submission.fixture, submission.options));
  assert.deepEqual(submission.counts(), { posts: 0, reads: 0 });
});

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
