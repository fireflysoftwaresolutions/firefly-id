import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { reportFailure } from './safe-errors.mjs';
import { selectNewRecoveryMessage } from './recovery-mail.mjs';

const BASE = 'http://id.firefly.test:8180';
const REDIRECT = 'http://localhost:3000/oidc/callback';
const CLIENT = 'sandbox-web';
const pause = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));

export const normalizePublicText = value => value.replace(/\s+/g, ' ').trim();

export function assertPermanentBlock(user) {
  assert.equal(user.enabled, false, 'Expected a disabled user after permanent blocking');
  assert.deepEqual(user.attributes?.disabledReason, ['permanentLockout'], 'Expected the native permanent-lock reason');
}

export async function waitForPermanentBlock(readState, { maxPolls = 30, intervalMs = 100 } = {}) {
  assert.ok(Number.isInteger(maxPolls) && maxPolls > 0 && maxPolls <= 30, 'Invalid permanent-state polling bound');
  assert.ok(Number.isInteger(intervalMs) && intervalMs >= 0 && intervalMs <= 100, 'Invalid permanent-state polling interval');
  let observed;
  for (let poll = 0; poll < maxPolls; poll++) {
    observed = await readState();
    const { counter, user } = observed;
    if (counter.numFailures === 3 && counter.disabled === true && user.enabled === false
      && user.attributes?.disabledReason?.length === 1 && user.attributes.disabledReason[0] === 'permanentLockout') {
      return observed;
    }
    if (poll + 1 < maxPolls) await pause(intervalMs);
  }
  assert.equal(observed.counter.numFailures, 3, 'Permanent-state deadline did not observe exactly three failures');
  assert.equal(observed.counter.disabled, true, 'Permanent-state deadline did not observe native blocking');
  assertPermanentBlock(observed.user);
  return observed;
}

export function assertNoPublicDisclosure(value) {
  const text = normalizePublicText(value);
  assert.ok(text.length > 0, 'Expected a public acknowledgement');
  assert.ok(!/(?:\b\d+\s+(?:login\s+)?attempts?\b|\battempts?\s+(?:left|remaining)\b|\bremaining\s+(?:login\s+)?attempts?\b|\bremaining\s*:?\s*\d+)/i.test(text),
    'Public response exposes an attempt count');
  assert.ok(!/(?:\bunknown\s+(?:user|account)|\b(?:user|account|email)\b.{0,32}\b(?:not found|disabled|locked|blocked|registered|exists|inactive)\b)/i.test(text),
    'Public response exposes account existence or status');
}

async function assertMaskedPasswordControls(page) {
  const valid = await page.evaluate(() => {
    const visible = element => Boolean(element.getClientRects().length)
      && getComputedStyle(element).visibility !== 'hidden';
    const passwords = [...document.querySelectorAll('input')].filter(input =>
      /^(?:password|password-new|password-confirm|passwordConfirmation)$/.test(input.name || input.id)
      || ['current-password', 'new-password'].includes(input.autocomplete));
    const controls = [...document.querySelectorAll('button, [role="button"]')].filter(button =>
      button.hasAttribute('data-password-toggle')
      || /(?:show|hide|reveal) password/i.test(button.getAttribute('aria-label') || ''));
    return passwords.length > 0 && passwords.every(input => input.type === 'password')
      && controls.every(button => !visible(button) && (button.disabled || button.tabIndex < 0));
  });
  assert.ok(valid, 'Password input is unmasked or a reveal control remains available');
}

async function protectedJson(filename, value) {
  const temporary = `${filename}.next-${randomBytes(8).toString('hex')}`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temporary, filename);
}

async function request(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(15000) });
}

async function main() {
  let browser;
  let server;
  let phase = 'policy setup';
  const results = [];
  const pending = new Map();
  const passed = name => { results.push(name); console.log(`PASS ${name}`); };
  try {
    const stateDir = resolve(process.env.FIREFLY_ID_STATE || '.state/sandbox');
    assert.equal((await stat(stateDir)).mode & 0o077, 0, 'Sandbox state must remain owner-only');
    const ownership = JSON.parse(await readFile(`${stateDir}/ownership.json`, 'utf8'));
    assert.equal(ownership.mode, 'sandbox');
    assert.equal(ownership.created_by, 'firefly-id/scripts/generate.py');
    assert.match(ownership.project, /^firefly-id-sandbox-[a-f0-9]{10}$/);
    const credentials = JSON.parse(await readFile(`${stateDir}/credentials.json`, 'utf8'));
    assert.ok(credentials.policy_customers && credentials.policy_workforce, 'Generate a fresh policy-aware sandbox first');
    const policies = JSON.parse(await readFile(new URL('../config/authentication-policies.json', import.meta.url), 'utf8'));
    assert.equal(policies.schemaVersion, 1);
    assert.equal(policies.defaults.permanentLockout, true);
    assert.equal(policies.defaults.maxTemporaryLockouts, 0);
    assert.equal(policies.defaults.failureFactor, 3);
    assert.equal(policies.defaults.quickLoginCheckMilliSeconds, 0);
    const runId = randomUUID();
    const manifestFile = `${stateDir}/secrets/policy-runtime-${runId}.json`;
    const manifest = { project: ownership.project, runId, createdBy: 'firefly-id/tooling/policy-runtime.mjs', users: [] };
    await protectedJson(manifestFile, manifest);
    server = createServer((incoming, outgoing) => {
      const url = new URL(incoming.url, REDIRECT);
      outgoing.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
      outgoing.end('Synthetic policy callback. No credentials are displayed.');
      if (url.pathname === '/oidc/callback') pending.get(url.searchParams.get('state'))?.(url);
    });
    await new Promise((ok, fail) => server.listen(3000, '127.0.0.1', ok).once('error', fail));
    const { chromium } = await import('playwright');
    browser = await chromium.launch();
    const adminContext = await browser.newContext();
    const adminPage = await adminContext.newPage();
    adminPage.setDefaultTimeout(20000);
    phase = 'browser administrative authentication';
    const authenticatedRequest = adminPage.waitForResponse(async response => {
      if (!new URL(response.url()).pathname.startsWith('/admin/realms') || response.status() !== 200) return false;
      return (await response.request().allHeaders()).authorization?.startsWith('Bearer ');
    }, { timeout: 40000 });
    authenticatedRequest.catch(() => {});
    await adminPage.goto(`${BASE}/admin/master/console/`);
    await adminPage.locator('#username').fill('sandbox-bootstrap');
    await assertMaskedPasswordControls(adminPage);
    await adminPage.locator('#password').fill((await readFile(`${stateDir}/secrets/admin-password`, 'utf8')).trim());
    await adminPage.locator('#kc-login').click();
    const browserApiResponse = await authenticatedRequest;
    let authorization = (await browserApiResponse.request().allHeaders()).authorization;
    assert.ok(authorization?.startsWith('Bearer '), 'Actual browser administrative token required');
    const api = (population, path = '') => `${BASE}/admin/realms/${population === 'master' ? 'master' : `sandbox-${population}`}${path}`;
    async function admin(url, method = 'GET', body) {
      const claims = JSON.parse(Buffer.from(authorization.slice(7).split('.')[1], 'base64url'));
      assert.ok(typeof claims.exp === 'number', 'Administrative token expiry missing');
      if (claims.exp < Date.now() / 1000 + 30) {
        const renewed = adminPage.waitForResponse(async response => response.status() === 200
          && new URL(response.url()).pathname.startsWith('/admin/realms')
          && (await response.request().allHeaders()).authorization?.startsWith('Bearer '));
        renewed.catch(() => {});
        await adminPage.reload();
        authorization = (await (await renewed).request().allHeaders()).authorization;
      }
      return request(url, { method,
        headers: { Authorization: authorization, Accept: 'application/json',
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    }
    async function adminJson(url) {
      const response = await admin(url);
      assert.equal(response.status, 200, 'Authenticated administrative read refused');
      return response.json();
    }
    async function permanentState(fixture) {
      return waitForPermanentBlock(async () => ({
        counter: await adminJson(api(fixture.population, `/attack-detection/brute-force/users/${fixture.id}`)),
        user: await adminJson(api(fixture.population, `/users/${fixture.id}`)),
      }));
    }
    const expectedPolicy = population => ({ ...policies.defaults, ...policies.profiles[population].realmSettings });
    function assertPolicy(actual, expected) {
      for (const [name, value] of Object.entries(expected)) assert.deepEqual(actual[name], value, 'Effective realm policy differs from selected profile');
    }

    phase = 'master policy application through authenticated Admin REST API';
    const masterPolicy = expectedPolicy('administrators');
    assert.equal((await admin(api('master'), 'PUT', masterPolicy)).status, 204, 'Master policy application refused');
    assertPolicy(await adminJson(api('master')), masterPolicy);
    passed('master password and three-failure policy applied and read back through browser-authenticated Admin REST');

    phase = 'effective imported population policies';
    for (const population of ['customers', 'workforce', 'institutions']) {
      const actual = await adminJson(api(population));
      assertPolicy(actual, expectedPolicy(population));
      if (population === 'workforce') {
        assert.equal(actual.browserFlow, 'firefly-workforce-browser');
        const executions = await adminJson(api(population, '/authentication/flows/firefly-workforce-browser/executions'));
        assert.ok(executions.some(execution => execution.providerId === 'auth-otp-form' && execution.requirement === 'REQUIRED'),
          'Workforce browser OTP is not mandatory');
      }
    }
    passed('actual customer, workforce and institutional policies match selected profiles; workforce OTP required');

    async function freshFixture(population, purpose, enabled = true) {
      assert.ok(credentials[`policy_${population}`], 'Missing separate fixture seed');
      const username = `${credentials[`policy_${population}`].username}-${purpose}-${runId}`;
      const fixture = { population, username, email: `policy-${runId.replaceAll('-', '')}-${manifest.users.length}@example.invalid`,
        password: randomBytes(36).toString('base64url'), enabled };
      // Persist intent before creation so an interrupted response does not orphan an unrecorded fixture.
      manifest.users.push(fixture);
      await protectedJson(manifestFile, manifest);
      const response = await admin(api(population, '/users'), 'POST', {
        username, email: fixture.email, enabled, emailVerified: true,
        firstName: 'Synthetic', lastName: 'Policy qualification', requiredActions: [],
        attributes: { tenant_id: ['synthetic-tenant'],
          [population === 'workforce' ? 'staff_actor_id' : 'party_id']: [randomUUID()] },
        credentials: [{ type: 'password', value: fixture.password, temporary: false }],
      });
      assert.equal(response.status, 201, 'Fresh synthetic policy fixture creation refused');
      assert.ok(response.headers.get('location'), 'Created fixture has no resource location');
      const location = new URL(response.headers.get('location'), BASE);
      assert.equal(location.origin, BASE);
      assert.ok(location.pathname.startsWith(`/admin/realms/sandbox-${population}/users/`));
      fixture.id = location.pathname.split('/').at(-1);
      assert.match(fixture.id, /^[a-f0-9-]{36}$/);
      await protectedJson(manifestFile, manifest);
      return fixture;
    }

    const metadataCache = new Map();
    async function begin(population) {
      if (!metadataCache.has(population)) {
        const issuer = `${BASE}/realms/sandbox-${population}`;
        const response = await request(`${issuer}/.well-known/openid-configuration`);
        assert.equal(response.status, 200);
        const metadata = await response.json();
        assert.equal(metadata.issuer, issuer);
        metadataCache.set(population, metadata);
      }
      const metadata = metadataCache.get(population);
      const context = await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(20000);
      const verifier = randomBytes(48).toString('base64url');
      const state = randomBytes(24).toString('base64url');
      const nonce = randomBytes(24).toString('base64url');
      let callbackUrl;
      pending.set(state, url => { callbackUrl = url; });
      const url = new URL(metadata.authorization_endpoint);
      url.search = new URLSearchParams({ client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid profile email', state, nonce, code_challenge_method: 'S256',
        code_challenge: createHash('sha256').update(verifier).digest('base64url') });
      try {
        await page.goto(url.href);
        await page.locator('#username').waitFor();
        await page.locator('#ffid-access-policy').waitFor({ state: 'visible' });
        assert.ok(await page.evaluate(() => document.querySelector('#ffid-access-policy').getBoundingClientRect().bottom
          <= document.querySelector('#username').getBoundingClientRect().top), 'Advance warning must precede credential entry');
        await assertMaskedPasswordControls(page);
      } catch (error) { pending.delete(state); await context.close(); throw error; }
      return { context, page, get callback() { return callbackUrl; },
        async submit(username, password) {
          await page.locator('#username').fill(username);
          await page.locator('#password').fill(password);
          const submitted = page.waitForResponse(response => response.request().method() === 'POST'
            && new URL(response.url()).pathname.startsWith(`/realms/sandbox-${population}/login-actions/authenticate`));
          submitted.catch(() => {});
          await page.locator('#kc-login').click();
          return (await submitted).status();
        },
        async finish() {
          await page.waitForURL(value => value.origin === new URL(REDIRECT).origin && value.pathname === new URL(REDIRECT).pathname);
          assert.ok(callbackUrl, 'No received browser callback');
          assert.equal(callbackUrl.searchParams.get('state'), state);
          assert.ok(callbackUrl.searchParams.get('code') && !callbackUrl.searchParams.has('error'), 'Authentication refused');
          const response = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
            grant_type: 'authorization_code', client_id: CLIENT, redirect_uri: REDIRECT,
            code: callbackUrl.searchParams.get('code'), code_verifier: verifier }) });
          assert.equal(response.status, 200, 'Browser authorization code and PKCE exchange refused');
          const tokens = await response.json();
          const [header, payload, signature] = tokens.id_token.split('.');
          const decodedHeader = JSON.parse(Buffer.from(header, 'base64url'));
          const claims = JSON.parse(Buffer.from(payload, 'base64url'));
          assert.equal(decodedHeader.alg, 'RS256');
          const keyResponse = await request(metadata.jwks_uri);
          assert.equal(keyResponse.status, 200);
          const { keys } = await keyResponse.json();
          const jwk = keys.find(key => key.kid === decodedHeader.kid && key.use === 'sig');
          assert.ok(jwk, 'Issuer signature key missing');
          assert.ok(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`),
            createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(signature, 'base64url')), 'ID token signature refused');
          assert.equal(claims.iss, metadata.issuer);
          assert.ok([claims.aud].flat().includes(CLIENT));
          assert.equal(claims.nonce, nonce);
          assert.ok(claims.exp > Date.now() / 1000 && claims.sub);
          return tokens;
        },
        async close() { pending.delete(state); await context.close(); },
      };
    }

    async function publicMessage(page) {
      const selector = '[id^="input-error"], .kc-feedback-text, #kc-error-message';
      await page.waitForFunction(selector => [...document.querySelectorAll(selector)]
        .some(element => element.getClientRects().length && element.textContent.trim()), selector);
      const text = await page.evaluate(selector => [...new Set([...document.querySelectorAll(selector)]
        .filter(element => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden')
        .map(element => element.textContent.trim()).filter(Boolean))].join(' '), selector);
      assertNoPublicDisclosure(text);
      const visible = normalizePublicText(await page.locator('main').innerText());
      assertNoPublicDisclosure(visible);
      return visible;
    }

    async function refused(fixture, password = 'wrong synthetic password which is never a credential') {
      const flow = await begin(fixture.population);
      try {
        const status = await flow.submit(fixture.username, password);
        assert.ok(status >= 200 && status < 500, 'Provider error is not an authentication refusal');
        const text = await publicMessage(flow.page);
        assert.ok(!flow.callback, 'Refused authentication issued a code');
        await assertMaskedPasswordControls(flow.page);
        return { status, text };
      } finally { await flow.close(); }
    }

    phase = 'public known, unknown and disabled-account responses';
    const known = await freshFixture('customers', 'known');
    const disabled = await freshFixture('customers', 'disabled', false);
    const baseline = await refused(known);
    assert.deepEqual(await refused({ population: 'customers', username: `unknown-policy-${runId}` }), baseline,
      'Unknown-account public response differs');
    assert.deepEqual(await refused(disabled, disabled.password), baseline, 'Disabled-account public response differs');
    passed('known, unknown and disabled-account failures have equal normalized visible main content and HTTP status; no public counts or reveal controls');

    phase = 'first, second and third failure enforcement on fresh fixtures';
    for (const attempts of [1, 2, 3]) {
      const fixture = await freshFixture('customers', `failures-${attempts}`);
      for (let attempt = 0; attempt < attempts; attempt++) assert.deepEqual(await refused(fixture), baseline);
      let counter;
      for (let poll = 0; poll < 30; poll++) {
        counter = await adminJson(api(fixture.population, `/attack-detection/brute-force/users/${fixture.id}`));
        if (counter.numFailures === attempts) break;
        await pause(100);
      }
      assert.equal(counter.numFailures, attempts, 'Server did not record the expected fresh failure count');
      if (attempts < 3) {
        assert.equal(counter.disabled, false, 'Lock began before the third failure');
        const actualUser = await adminJson(api(fixture.population, `/users/${fixture.id}`));
        assert.equal(actualUser.enabled, true, 'User disabled before the third failure');
        const flow = await begin(fixture.population);
        try { await flow.submit(fixture.username, fixture.password); await flow.finish(); }
        finally { await flow.close(); }
        const reset = await adminJson(api(fixture.population, `/attack-detection/brute-force/users/${fixture.id}`));
        assert.equal(reset.numFailures, 0, 'Successful login did not reset failure state');
      } else {
        assertPermanentBlock((await permanentState(fixture)).user);
        assert.deepEqual(await refused(fixture, fixture.password), baseline, 'Locked-account public response differs');
      }
    }
    passed('real first and second failures permit correct browser login; third failure disables the customer with the native permanent-lock reason');

    phase = 'separate workforce permanent third-failure blocking';
    const blockedEmployee = await freshFixture('workforce', 'permanent-block');
    const employeeFailure = await refused(blockedEmployee);
    for (let attempt = 1; attempt < 3; attempt++) assert.deepEqual(await refused(blockedEmployee), employeeFailure);
    assertPermanentBlock((await permanentState(blockedEmployee)).user);
    assert.deepEqual(await refused(blockedEmployee, blockedEmployee.password), employeeFailure);
    passed('separate workforce user is permanently disabled by the third failure and correct password cannot bypass the block');

    phase = 'generic recovery acknowledgement through synthetic SMTP sink';
    const recovery = await freshFixture('customers', 'recovery');
    const mailboxResponse = await request('http://localhost:8025/api/v1/messages');
    assert.equal(mailboxResponse.status, 200);
    const prior = new Set(((await mailboxResponse.json()).messages || []).map(message => message.ID));
    async function recoveryAcknowledgement(username) {
      const flow = await begin('customers');
      try {
        await flow.page.getByRole('link', { name: 'Forgot Password?' }).click();
        await flow.page.getByLabel('Username or email').fill(username);
        const submitted = flow.page.waitForResponse(response => response.request().method() === 'POST'
          && new URL(response.url()).pathname.startsWith('/realms/sandbox-customers/login-actions/reset-credentials'));
        submitted.catch(() => {});
        await flow.page.getByRole('button', { name: 'Submit' }).click();
        const status = (await submitted).status();
        assert.ok(status >= 200 && status < 500, 'Recovery provider failure');
        return { status, text: await publicMessage(flow.page) };
      } finally { await flow.close(); }
    }
    const recoveryBaseline = await recoveryAcknowledgement(recovery.username);
    assert.deepEqual(await recoveryAcknowledgement(`unknown-recovery-${runId}`), recoveryBaseline);
    assert.deepEqual(await recoveryAcknowledgement(disabled.username), recoveryBaseline);
    let delivered;
    for (let attempt = 0; attempt < 30; attempt++) {
      const response = await request('http://localhost:8025/api/v1/messages');
      assert.equal(response.status, 200);
      delivered = selectNewRecoveryMessage((await response.json()).messages || [], prior, recovery.email);
      if (delivered) break;
      await pause(250);
    }
    assert.ok(delivered, 'No fresh synthetic recovery mail arrived in the local sink');
    passed('known, unknown and disabled recovery acknowledgements match; fresh synthetic mail arrives in the local sink');

    phase = 'old recovery link and refresh token cannot bypass permanent blocking';
    const mailResponse = await request(`http://localhost:8025/api/v1/message/${delivered.ID}`);
    assert.equal(mailResponse.status, 200);
    const mail = await mailResponse.json();
    const matched = mail.HTML.match(/href="([^"\s]*\/login-actions\/action-token[^"\s]*)"/);
    assert.ok(matched, 'Fresh server recovery action missing');
    const oldAction = new URL(matched[1].replaceAll('&amp;', '&'));
    assert.equal(oldAction.origin, BASE);
    assert.ok(oldAction.pathname.startsWith('/realms/sandbox-customers/login-actions/action-token'));
    const beforeBlock = await begin('customers');
    let previouslyIssued;
    try {
      await beforeBlock.submit(recovery.username, recovery.password);
      previouslyIssued = await beforeBlock.finish();
    } finally { await beforeBlock.close(); }
    assert.ok(previouslyIssued.refresh_token, 'Actual browser-issued refresh token required');
    const issuedAccess = JSON.parse(Buffer.from(previouslyIssued.access_token.split('.')[1], 'base64url'));
    assert.equal(issuedAccess.iss, metadataCache.get('customers').issuer);
    assert.equal(issuedAccess.client_id, CLIENT);
    assert.ok(typeof issuedAccess.exp === 'number' && issuedAccess.exp > Date.now() / 1000);
    assert.ok(credentials.customers.backend_client_secret, 'Confidential introspection client required');
    const introspectionEndpoint = new URL(metadataCache.get('customers').introspection_endpoint);
    assert.equal(introspectionEndpoint.origin, BASE);
    assert.equal(introspectionEndpoint.pathname, '/realms/sandbox-customers/protocol/openid-connect/token/introspect');
    async function introspectPreviouslyIssuedAccess() {
      const response = await request(introspectionEndpoint.href, { method: 'POST', body: new URLSearchParams({
        client_id: 'sandbox-backend', client_secret: credentials.customers.backend_client_secret,
        token: previouslyIssued.access_token, token_type_hint: 'access_token',
      }) });
      assert.equal(response.status, 200, 'Authenticated native introspection refused');
      const result = await response.json();
      if (result.iss !== undefined) assert.equal(result.iss, issuedAccess.iss);
      if (result.client_id !== undefined) assert.equal(result.client_id, CLIENT);
      if (result.sub !== undefined) assert.equal(result.sub, issuedAccess.sub);
      return result;
    }
    assert.equal((await introspectPreviouslyIssuedAccess()).active, true, 'Fresh browser-issued access token is not active');
    for (let attempt = 0; attempt < 3; attempt++) assert.deepEqual(await refused(recovery), baseline);
    const recoveryUserUrl = api('customers', `/users/${recovery.id}`);
    assertPermanentBlock((await permanentState(recovery)).user);
    const blockedIntrospection = await introspectPreviouslyIssuedAccess();
    assert.ok(issuedAccess.exp > Date.now() / 1000, 'Access token expired before the disabled-user introspection check');
    assert.equal(blockedIntrospection.active, false, 'Native introspection accepted the disabled user');
    passed('native confidential-client introspection changes from active to inactive after permanent blocking while the browser-issued access token remains unexpired');
    const refresh = await request(metadataCache.get('customers').token_endpoint, {
      method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', client_id: CLIENT,
        refresh_token: previouslyIssued.refresh_token }),
    });
    assert.equal(refresh.status, 400, 'A previously issued refresh token bypassed permanent blocking');
    assert.equal((await refresh.json()).error, 'invalid_grant');
    const blockedActionContext = await browser.newContext();
    try {
      const actionPage = await blockedActionContext.newPage();
      const response = await actionPage.goto(oldAction.href);
      assert.ok(response && response.status() >= 400 && response.status() < 500, 'Old recovery action was not refused');
      await publicMessage(actionPage);
      assert.equal(await actionPage.locator('#password-new, #password-confirm').count(), 0,
        'An old recovery action exposed password replacement for a blocked user');
      assert.ok(!actionPage.url().startsWith(REDIRECT), 'Old recovery action issued an authentication callback');
    } finally { await blockedActionContext.close(); }
    assertPermanentBlock(await adminJson(recoveryUserUrl));
    passed('a pre-block browser refresh token and pre-block reset link cannot issue new authentication or remove the native permanent block');

    phase = 'counter clearing and password replacement cannot re-enable a permanently blocked fixture';
    assert.equal((await admin(api('customers', `/attack-detection/brute-force/users/${recovery.id}`), 'DELETE')).status, 204,
      'Owned fixture counter-clear probe refused');
    // The counter endpoint can report an empty record; the user enabled flag remains authoritative.
    assertPermanentBlock(await adminJson(recoveryUserUrl));
    assert.deepEqual(await refused(recovery, recovery.password), baseline, 'Counter clearing re-enabled the fixture');
    const replacement = randomBytes(36).toString('base64url');
    recovery.pendingPassword = replacement;
    await protectedJson(manifestFile, manifest);
    assert.equal((await admin(api('customers', `/users/${recovery.id}/reset-password`), 'PUT',
      { type: 'password', value: replacement, temporary: false })).status, 204, 'Owned disabled-fixture password replacement refused');
    recovery.password = replacement;
    delete recovery.pendingPassword;
    await protectedJson(manifestFile, manifest);
    assertPermanentBlock(await adminJson(recoveryUserUrl));
    assert.deepEqual(await refused(recovery, replacement), baseline, 'Password replacement removed permanent blocking');
    passed('clearing only the fresh owned fixture counter and replacing its password both leave enabled=false and the permanent-lock reason intact');

    phase = 'real password length, denylist, identity and history policies';
    const denied = (await readFile(new URL('../config/password-blacklist.txt', import.meta.url), 'utf8')).trim().split('\n');
    for (const population of ['customers', 'workforce']) {
      const fixture = await freshFixture(population, 'passwords');
      const policy = policies.profiles[population].realmSettings.passwordPolicy;
      const minimum = Number(policy.match(/(?:^| and )length\((\d+)\)/)?.[1]);
      const maximum = Number(policy.match(/(?:^| and )maxLength\((\d+)\)/)?.[1]);
      assert.ok(minimum >= 16 && maximum === 128);
      async function replacePassword(value, expectedStatus) {
        const response = await admin(api(population, `/users/${fixture.id}/reset-password`), 'PUT',
          { type: 'password', value, temporary: false });
        assert.equal(response.status, expectedStatus, 'Password policy response differs from expected boundary');
        if (expectedStatus === 204) {
          fixture.password = value;
          await protectedJson(manifestFile, manifest);
        }
      }
      const phrase = size => (`${randomBytes(7).toString('hex')} ${'calm words '.repeat(20)}`).slice(0, size);
      await replacePassword(phrase(minimum - 1), 400);
      const minimumPassword = phrase(minimum);
      await replacePassword(minimumPassword, 204);
      const maximumPassword = phrase(maximum);
      await replacePassword(maximumPassword, 204);
      await replacePassword(phrase(maximum + 1), 400);
      const deniedPassword = denied.find(value => value.length >= minimum && value.length <= maximum);
      assert.ok(deniedPassword, 'No denylist entry exercises this population boundary');
      await replacePassword(deniedPassword, 400);
      await replacePassword(fixture.username, 400);
      await replacePassword(fixture.email, 400);
      await replacePassword(minimumPassword, 400);
      const flow = await begin(population);
      try {
        await flow.submit(fixture.username, maximumPassword);
        if (population === 'customers') await flow.finish();
        else {
          await flow.page.locator('#totpSecret').waitFor({ state: 'attached' });
          assert.ok(!flow.callback, 'Workforce password alone issued an authorization code');
        }
      } finally { await flow.close(); }
    }
    passed('actual Admin REST enforces customer and employee minimum/maximum lengths, denylist, username/email exclusion and history; employee password alone stops at OTP enrollment');

    phase = 'administrative password form masking';
    const uiFixture = manifest.users.find(user => user.population === 'customers' && user.id);
    await adminPage.goto(`${BASE}/admin/master/console/#/sandbox-customers/users/${uiFixture.id}/credentials`);
    await adminPage.getByRole('button', { name: /^(?:Reset|Set) password$/i }).first().click();
    await adminPage.getByRole('dialog').waitFor();
    await assertMaskedPasswordControls(adminPage);
    passed('actual administrative credential dialog keeps passwords masked and exposes no available reveal control');

    const evidence = resolve('.work/policy-runtime');
    await mkdir(evidence, { recursive: true });
    await writeFile(`${evidence}/summary.json`, JSON.stringify({ results,
      pending: ['permanent-lock retention across restart and clock advance', 'concurrent lockout races',
        'timing side-channel analysis', 'workforce passkeys and lost-factor recovery',
        'permanent administrator phishing-resistant MFA and bootstrap removal',
        'independent knowledge-plus-enrolled-possession recovery and assisted proofing',
        'immediate receiver enforcement for existing access tokens and application sessions',
        'production compromised-password feed and retained-realm migration'],
      scope: 'Synthetic provider policies and visible-response/status equality only; no universal EU-compliance or production acceptance.' }, null, 2) + '\n');
  } catch (error) {
    reportFailure(error, phase);
    process.exitCode = 1;
  } finally {
    pending.clear();
    try {
      if (browser) await browser.close();
      if (server?.listening) await new Promise(ok => server.close(ok));
    } catch (error) { reportFailure(error, 'policy cleanup'); process.exitCode = 1; }
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await main();
