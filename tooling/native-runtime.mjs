import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { totpCode } from './extended-runtime.mjs';
import { reportFailure } from './safe-errors.mjs';

const directory = resolve(process.env.FIREFLY_NATIVE_STATE || '');
assert.ok(process.env.GITHUB_ACTIONS === 'true' && directory.includes('/.state/native-'), 'Owned hosted native state required');
const credentials = JSON.parse(await readFile(`${directory}/credentials.json`, 'utf8'));
const output = resolve('.work/native-integration');
await mkdir(output, { recursive: true });
const origin = 'https://id.firefly.test:8443';
const callback = 'https://localhost:8448/oidc/callback';
const pending = new Map();
const results = [];
const factors = new Map();
const fontEvidence = [];
let phase = 'owned-native-runtime-ready';
let currentStage = 'initialization';
let lastPage;
let lastHttpStatus;
const stage = value => { currentStage = value; };
let browser;
let server;
const passed = label => { phase = label; results.push(label); console.log(`PASS ${label}`); };
const delay = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));
const nativeTool = (action, population) => execFileSync('python3', ['tooling/native_integration_fixture.py', action,
  ...(population ? ['--population', population] : [])], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const snapshot = population => JSON.parse(nativeTool('snapshot', population));
async function request(url, options = {}) { return fetch(url, { ...options, signal: AbortSignal.timeout(20000) }); }
async function adminToken() {
  const response = await request(`${origin}/realms/master/protocol/openid-connect/token`, { method: 'POST',
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'native-bootstrap', password: credentials.admin }) });
  assert.equal(response.status, 200, 'Owned bootstrap administrator unavailable');
  return (await response.json()).access_token;
}
async function admin(profile, suffix, options = {}) {
  return request(`${origin}/admin/realms/${profile.realm}/${suffix}`, { ...options,
    headers: { Authorization: `Bearer ${await adminToken()}`, ...(options.headers || {}) } });
}
async function user(profile, manual = false) {
  const response = await admin(profile, `users/${manual ? profile.manual.id : profile.person.id}`);
  assert.equal(response.status, 200, 'Owned user state unavailable'); return response.json();
}
async function nextCode(profile) {
  const factor = factors.get(profile.kind); assert.ok(factor, 'Previously enrolled native TOTP required');
  let counter = Math.floor(Date.now() / 30000);
  if (counter <= factor.lastCounter) { await delay((factor.lastCounter + 1) * 30000 - Date.now() + 300); counter = Math.floor(Date.now() / 30000); }
  factor.lastCounter = counter; return totpCode(factor.secret, counter * 30);
}
async function authenticate(profile, context, wrong = false, enroll = false) {
  const state = randomBytes(20).toString('base64url'), verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const url = new URL(`${profile.issuer}/protocol/openid-connect/auth`);
  url.search = new URLSearchParams({ client_id: 'native-browser', redirect_uri: callback, response_type: 'code',
    scope: 'openid profile email offline_access', code_challenge: challenge, code_challenge_method: 'S256', state,
    nonce: randomBytes(16).toString('hex'), prompt: 'login' }).toString();
  stage(`${profile.kind}-ordinary-new-page`);
  const page = await context.newPage(); lastPage = page; page.setDefaultTimeout(20000);
  let fulfill;
  const returned = new Promise(ok => { fulfill = ok; pending.set(state, ok); });
  stage(`${profile.kind}-ordinary-oidc-navigation`);
  lastHttpStatus = (await page.goto(url.href))?.status();
  stage(`${profile.kind}-ordinary-recovery-entry-count`);
  assert.equal(await page.locator(`a[href="${profile.issuer}/firefly-recovery"]`).count(), 1, 'Opted-in native login must expose recovery');
  stage(`${profile.kind}-ordinary-password-submit`);
  await page.locator('#username').fill(profile.person.username);
  await page.locator('#password').fill(wrong ? 'synthetic-invalid-password-2468!' : profile.person.password);
  await page.locator('#kc-login').click();
  if (wrong) { await page.locator('#password').waitFor(); pending.delete(state); await page.close(); return null; }
  stage(`${profile.kind}-ordinary-otp-or-enrollment-selector`);
  await page.locator('#totpSecret, #otp').first().waitFor({ state: 'attached' });
  if (await page.locator('#totpSecret').count()) {
    assert.ok(enroll, 'Recovery must not enroll a new factor');
    stage(`${profile.kind}-ordinary-enrollment-secret-selector`);
    if (await page.locator('#mode-manual').count()) await page.locator('#mode-manual').click();
    const secret = (await page.locator('#kc-totp-secret-key').innerText()).replace(/\s/g, '');
    factors.set(profile.kind, { secret, lastCounter: -1 });
    await writeFile(`${directory}/secrets/totp-${profile.kind}.json`, JSON.stringify({ secret }), { mode: 0o600, flag: 'wx' });
    await page.locator('#totp').fill(await nextCode(profile));
    if (await page.locator('#userLabel').count()) await page.locator('#userLabel').fill('Pre-enrolled native fixture authenticator');
    stage(`${profile.kind}-ordinary-enrollment-save`);
    await page.locator('#saveTOTPBtn').click();
  } else {
    await page.locator('#otp').fill(await nextCode(profile));
    await page.locator('#kc-login').click();
  }
  if (await page.locator('#kc-oauth-consent-form').count()) await page.locator('input[name="accept"], button[name="accept"]').click();
  stage(`${profile.kind}-ordinary-callback-wait`);
  const response = await Promise.race([returned, delay(25000).then(() => { throw new Error('Owned authorization callback missing'); })]);
  pending.delete(state);
  assert.equal(response.searchParams.get('state'), state); const code = response.searchParams.get('code'); assert.ok(code);
  stage(`${profile.kind}-ordinary-token-exchange`);
  const token = await request(`${profile.issuer}/protocol/openid-connect/token`, { method: 'POST', body: new URLSearchParams({
    client_id: 'native-browser', grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: callback }) });
  assert.equal(token.status, 200, 'Genuine ordinary sign-in token exchange failed');
  await page.close(); return token.json();
}
async function recovery(profile, context, username, password) {
  stage(`${profile.kind}-native-new-page`);
  const page = await context.newPage(); lastPage = page; page.setDefaultTimeout(25000);
  stage(`${profile.kind}-native-password-navigation`);
  lastHttpStatus = (await page.goto(`${profile.issuer}/firefly-recovery?kc_locale=es`))?.status();
  assert.equal(await page.locator('#password').getAttribute('type'), 'password');
  stage(`${profile.kind}-native-password-submit`);
  await page.locator('#username').fill(username); await page.locator('#password').fill(password);
  await page.locator('#ffid-recovery-continue').click();
  await page.locator('#otp').waitFor();
  await assertNativeFont(page, `${profile.kind}-masked-native-factor-form`);
  if ([profile.person.username, profile.person.email].includes(username)) {
    const reserved = snapshot(profile.kind);
    await page.reload(); await page.locator('#otp').waitFor();
    assert.equal(await page.locator('#username').count(), 0, 'Reload must preserve the completed password stage');
    assert.ok((await page.locator('html').getAttribute('lang')).startsWith('es'), 'Native recovery must preserve Spanish locale');
    assert.equal(snapshot(profile.kind).core[0].attempts, reserved.core[0].attempts, 'Reload must not reserve another verification');
    passed(`${profile.kind}-spanish-reload-preserves-native-progress-and-core-budget`);
  }
  return page;
}
async function expectCsrfRefusal(profile) {
  const context = await browser.newContext(); const page = await context.newPage();
  await page.goto(`${profile.issuer}/firefly-recovery`);
  const response = await context.request.post(`${profile.issuer}/firefly-recovery`, { headers: { Origin: origin },
    form: { username: profile.person.username, password: profile.person.password, csrf: 'synthetic-forged-csrf' } });
  assert.equal(response.status(), 400);
  await context.close(); passed(`${profile.kind}-native-csrf-refused`);
}
async function assertNativeFont(page, label) {
  await page.evaluate(() => document.fonts.ready);
  const measured = await page.evaluate(() => ({
    faces: [...document.fonts].filter(face => face.family.replace(/["']/g, '').toLowerCase() === 'manrope').map(face => ({ family: face.family, status: face.status })),
    samples: ['#kc-page-title', '.ffid-native-journey p', '.ffid-native-journey label', '.ffid-native-journey input[type="password"]', '.ffid-credential-status dd']
      .flatMap(selector => [...document.querySelectorAll(selector)].filter(element => element.getClientRects().length)
        .slice(0, 1).map(element => ({ selector, family: getComputedStyle(element).fontFamily }))),
    token: getComputedStyle(document.documentElement).getPropertyValue('--ffid-font-family').trim(),
    request: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname.endsWith('/manrope.woff2'))?.name,
  }));
  assert.ok(measured.faces.some(face => face.status === 'loaded'), 'Loaded actual Manrope FontFace is required');
  assert.ok(measured.samples.length >= 2 && measured.samples.every(sample => /Manrope/i.test(sample.family)), 'Actual native title/form/status text must use Manrope');
  assert.ok(/Manrope/i.test(measured.token), 'Canonical font token must remain Manrope');
  assert.ok(measured.request, 'Actual Manrope WOFF2 request must be observable');
  const response = await page.request.get(measured.request); assert.equal(response.status(), 200);
  const bytes = await response.body(); assert.equal(bytes.subarray(0, 4).toString('ascii'), 'wOF2');
  const canonical = await readFile(resolve('dist/themes/firefly-id/login/resources/fonts/manrope.woff2'));
  const sha = value => createHash('sha256').update(value).digest('hex');
  assert.equal(sha(bytes), sha(canonical), 'Native Manrope bytes must match the generated canonical artifact');
  fontEvidence.push({ label, faces: measured.faces, samples: measured.samples, token: measured.token,
    requestPath: new URL(measured.request).pathname, status: response.status(), sha256: sha(bytes) });
  await writeFile(`${output}/fonts.json`, JSON.stringify(fontEvidence, null, 2));
}
async function captureSafeJourney(page, name) {
  assert.equal(await page.locator('input[type="password"], #kc-totp-secret-key').count(), 0, 'Credential-bearing surfaces must not be captured');
  await assertNativeFont(page, name);
  for (const [width, height] of [[1440, 1000], [390, 844]]) {
    await page.setViewportSize({ width, height });
    for (const mode of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: mode });
      await page.waitForFunction(dark => document.documentElement.classList.contains('pf-v5-theme-dark') === dark, mode === 'dark');
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Native journey has horizontal clipping');
      await page.screenshot({ path: `${output}/${name}-${width}-${mode}.png`, fullPage: true });
    }
  }
}

async function supportPin(profile, context) {
  for (const [suffix, pin, expected] of [['set', '70934628', true], ['set', '84173059', true], ['revoke', null, false]]) {
    const page = await context.newPage(); await page.goto(`${profile.issuer}/firefly-recovery/support-pin/${suffix}`);
    await page.locator('#password').fill(profile.person.password); await page.locator('#otp').fill(await nextCode(profile));
    if (pin) { await page.locator('#pin').fill(pin); await page.locator('#pinConfirm').fill(pin); }
    await page.locator('#ffid-pin-save').click();
    await page.locator('#ffid-support-pin').waitFor({ state: 'detached' });
    assert.equal(snapshot(profile.kind).native.pinActive, expected, 'Actual native PIN lifecycle state differs');
    assert.equal(await page.locator('input[type="password"]').count(), 0, 'Credential field must not enter status capture');
    await captureSafeJourney(page, `customers-pin-${suffix}-${results.length}`);
    await page.close(); passed(`customers-pin-${pin ? 'set-or-rotate' : 'revoke'}-${results.length}`);
  }
}

try {
  stage('owned-callback-server-create');
  server = createServer({ pfx: await readFile(`${directory}/tls/server.p12`), passphrase: credentials.store }, (incoming, response) => {
    const url = new URL(incoming.url, callback); response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    response.end('Owned native fixture sign-in callback.'); pending.get(url.searchParams.get('state'))?.(url);
  });
  stage('owned-callback-server-listen');
  await new Promise((ok, fail) => server.listen(8448, '127.0.0.1', ok).once('error', fail));
  stage('owned-chromium-launch');
  browser = await chromium.launch();
  for (const profile of credentials.profiles) {
    const previousSession = await browser.newContext();
    const tokens = await authenticate(profile, previousSession, false, true);
    assert.ok(tokens.refresh_token, 'Real refresh/offline session required for retirement check');
    passed(`${profile.kind}-pre-existing-password-and-native-totp-enrolled`);
    for (const endpoint of [profile.core, profile.domain]) {
      const body = endpoint === profile.core ? JSON.stringify({ binding: { issuer: profile.issuer,
        tenant: 'synthetic-tenant', clientId: 'native-browser', delegatingClientId: null, actorSubject: profile.person.id,
        targetIssuer: profile.issuer, targetRealm: profile.realm, targetSubject: profile.person.id, population: profile.population,
        purpose: 'PERMANENT_AUTHENTICATION_UNLOCK', lockGeneration: 'not-authorized-synthetic-generation' },
        idempotencyKey: 'ordinary-token-negative' }) : undefined;
      const response = await request(`${endpoint}/api/v1/sca/recovery-operations`, { method: 'POST',
        headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' }, body });
      assert.ok([401, 403].includes(response.status), 'Valid request shape with ordinary authentication must not admit recovery');
    }
    passed(`${profile.kind}-ordinary-token-not-recovery-authority`);
    for (let attempt = 0; attempt < 3; attempt++) {
      const context = await browser.newContext(); await authenticate(profile, context, true); await context.close();
      const state = await user(profile); assert.equal(state.enabled, attempt < 2, 'Permanent lock threshold differs');
    }
    let before = snapshot(profile.kind); assert.equal(before.native.locked, true); assert.ok(before.native.generation);
    passed(`${profile.kind}-third-failure-captured-durable-native-generation`);
    await admin(profile, `users/${profile.person.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: true }) });
    assert.equal((await user(profile)).enabled, false, 'Generic Admin REST must not clear a protected block');
    passed(`${profile.kind}-generic-admin-enable-cannot-clear-block`);
    nativeTool('restart');
    assert.equal(snapshot(profile.kind).native.generation, before.native.generation, 'Restart lost lock generation');
    assert.equal((await user(profile)).enabled, false); passed(`${profile.kind}-native-restart-preserves-lock`);
    await expectCsrfRefusal(profile);
    const unknown = await browser.newContext({ locale: 'es-ES' }); const unknownPage = await recovery(profile, unknown, 'synthetic-unknown-person', profile.person.password);
    const unknownText = await unknownPage.locator('.ffid-native-journey').innerText(); await unknown.close();
    const manual = await browser.newContext({ locale: 'es-ES' }); const heldPage = await recovery(profile, manual, profile.manual.username, profile.person.password);
    assert.equal(await heldPage.locator('.ffid-native-journey').innerText(), unknownText, 'Manual hold reveals eligibility');
    await heldPage.locator('#otp').fill('000000'); await heldPage.locator('#ffid-recovery-continue').click();
    assert.equal((await user(profile, true)).enabled, false); await manual.close();
    passed(`${profile.kind}-unknown-and-manual-hold-generic-unavailable`);
    const context = await browser.newContext({ locale: 'es-ES' }); const page = await recovery(profile, context, profile.population === 'HUMAN' ? profile.person.email : profile.person.username, profile.person.password);
    assert.equal(await page.locator('.ffid-native-journey').innerText(), unknownText, 'Known recovery reveals existence');
    before = snapshot(profile.kind); assert.equal(before.core.length, 1); assert.equal(before.core[0].attempts, 1);
    const permitted = new Set([-30, 0, 30].map(offset => totpCode(factors.get(profile.kind).secret, Date.now() / 1000 + offset)));
    let invalid = 0; while (permitted.has(String(invalid).padStart(6, '0'))) invalid++;
    await page.locator('#otp').fill(String(invalid).padStart(6, '0')); await page.locator('#ffid-recovery-continue').click();
    await page.locator('[role="alert"]').waitFor();
    let rejected = snapshot(profile.kind); assert.equal(rejected.core[0].attempts, 2); assert.equal(rejected.native.possession, 1);
    assert.equal(rejected.native.maximumChecksPerReservation, 1); assert.equal((await user(profile)).enabled, false);
    passed(`${profile.kind}-wrong-totp-persists-native-and-core-attempts`);
    const csrf = await page.locator('input[name="csrf"]').inputValue();
    await page.locator('#otp').fill(await nextCode(profile)); await page.locator('#ffid-recovery-continue').click();
    await page.locator('#ffid-native-recovery').waitFor({ state: 'detached' });
    assert.equal((await user(profile)).enabled, true, 'Native password+TOTP recovery did not unlock');
    const after = snapshot(profile.kind); assert.equal(after.native.executions, 1); assert.equal(after.native.maximumChecksPerReservation, 1);
    assert.equal(after.core[0].attempts, 3); assert.equal(after.core[0].state, 'CONSUMED'); assert.equal(after.core[0].outcome, 'SUCCEEDED');
    assert.equal(await page.locator('input[type="password"]').count(), 0);
    await captureSafeJourney(page, `${profile.kind}-complete`);
    passed(`${profile.kind}-real-native-two-factor-unlock-and-owning-execution-journal`);
    const replay = await context.request.post(`${profile.issuer}/firefly-recovery`, { headers: { Origin: origin }, form: { csrf, otp: '000000' } });
    assert.equal(replay.status(), 400); assert.equal(snapshot(profile.kind).native.executions, 1);
    passed(`${profile.kind}-browser-replay-does-not-create-another-execution`);
    const refresh = await request(`${profile.issuer}/protocol/openid-connect/token`, { method: 'POST',
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'native-browser', refresh_token: tokens.refresh_token }) });
    assert.equal(refresh.status, 400); const sessions = await admin(profile, `users/${profile.person.id}/sessions`);
    assert.equal((await sessions.json()).length, 0); passed(`${profile.kind}-old-refresh-and-online-sessions-retired`);
    const fresh = await browser.newContext(); await authenticate(profile, fresh);
    passed(`${profile.kind}-fresh-password-and-pre-enrolled-mfa-required-after-unlock`);
    const account = await fresh.newPage(); await account.goto(`${profile.issuer}/account/`);
    await account.locator('main').waitFor();
    const pinLink = account.locator(`a[href="${profile.issuer}/firefly-recovery/support-pin"]`);
    if (profile.population === 'HUMAN') {
      await pinLink.waitFor({ state: 'visible' }); await pinLink.click();
      assert.equal(await account.locator('input[type="password"]').count(), 0, 'PIN status entry must not request a secret');
      passed('customers-native-account-exposes-support-pin-status');
      await supportPin(profile, fresh);
    } else {
      assert.equal(await pinLink.count(), 0, 'Workforce account must not offer the customer support PIN');
      const refusedPin = await fresh.request.get(`${profile.issuer}/firefly-recovery/support-pin`);
      assert.equal(refusedPin.status(), 403); passed('workforce-customer-pin-surface-refused');
    }
    await account.close();
    await fresh.close(); await context.close(); await previousSession.close();
    const serviceClient = 'untracked-fixture-service-' + profile.kind;
    const clientCreated = await admin(profile, 'clients', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: serviceClient, protocol: 'openid-connect', enabled: true, publicClient: false,
        secret: randomBytes(32).toString('base64url'), standardFlowEnabled: false, implicitFlowEnabled: false,
        directAccessGrantsEnabled: false, serviceAccountsEnabled: true, fullScopeAllowed: false, defaultClientScopes: [], optionalClientScopes: [] }) });
    assert.equal(clientCreated.status, 201);
    const clients = await (await admin(profile, `clients?clientId=${encodeURIComponent(serviceClient)}`)).json(); assert.equal(clients.length, 1);
    const serviceUser = await (await admin(profile, `clients/${clients[0].id}/service-account-user`)).json(); assert.ok(serviceUser.id);
    const updated = await admin(profile, `users/${serviceUser.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ firstName: 'Untracked synthetic service principal' }) });
    assert.equal(updated.status, 204, 'An untracked service-account update must not be vetoed by recovery');
    passed(`${profile.kind}-untracked-service-account-update-is-available`);
    const removed = await admin(profile, `users/${profile.person.id}`, { method: 'DELETE' });
    assert.equal(removed.status, 204, 'Explicit tracked-fixture deletion must complete');
    assert.equal((await admin(profile, `users/${profile.person.id}`)).status, 404);
    const tombstone = snapshot(profile.kind); assert.equal(tombstone.native.hold, true); assert.equal(tombstone.native.executions, 1);
    assert.equal(tombstone.core[0].state, 'CONSUMED');
    passed(`${profile.kind}-explicit-fixture-user-deletion-preserves-native-tombstone-and-core-evidence`);
  }
  await writeFile(`${output}/summary.json`, JSON.stringify({ status: 'PASSED', passed: results,
    pending: ['true simultaneous native execution requests', 'post-commit network response-loss injection', 'expired ceremony and swapped private attestation references',
      'support PIN BPO/case/delegation owner acceptance', 'production/regulatory approval'],
    scope: 'Owned synthetic HTTPS native Keycloak/Core PostgreSQL/actual generated-SDK Domain acceptance only.' }, null, 2));
} catch (error) {
  reportFailure(error, phase);
  const allowedNames = new Set(['AssertionError', 'Error', 'TypeError', 'TimeoutError']);
  const frames = String(error?.stack || '').split('\n').flatMap(line => {
    const match = line.match(/tooling\/native-runtime\.mjs:(\d+):(\d+)/);
    return match ? [`native-runtime.mjs:${match[1]}:${match[2]}`] : [];
  }).slice(0, 6);
  let inventory = {};
  if (lastPage && !lastPage.isClosed()) {
    try {
      for (const selector of ['#username', '#password', '#otp', '#totpSecret', '#kc-totp-secret-key', '.ffid-recovery-entry', '#ffid-native-recovery', '#ffid-support-pin']) {
        inventory[selector] = await lastPage.locator(selector).count();
      }
      const path = new URL(lastPage.url()).pathname;
      inventory.canonicalPath = path.endsWith('/protocol/openid-connect/auth') ? 'oidc-authorize'
        : path.includes('/login-actions/') ? 'native-login-action' : path.endsWith('/firefly-recovery') ? 'native-recovery'
        : path.includes('/support-pin') ? 'native-pin' : path === '/oidc/callback' ? 'owned-callback' : 'other';
    } catch { inventory = {}; }
  }
  await writeFile(`${output}/summary.json`, JSON.stringify({ status: 'FAILED', passed: results, lastCompleted: phase,
    currentStage, errorKind: allowedNames.has(error?.name) ? error.name : 'Error', sourceFrames: frames,
    lastHttpStatus, inventory, scope: 'Partial native integration; uncompleted stages are not qualified.' }, null, 2));
  process.exitCode = 1;
} finally {
  pending.clear(); if (browser) await browser.close(); if (server) await new Promise(ok => server.close(ok));
}
