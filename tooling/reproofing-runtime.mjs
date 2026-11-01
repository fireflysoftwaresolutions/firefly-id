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
assert.ok(process.env.GITHUB_ACTIONS === 'true' && directory.includes('/.state/native-'), 'Owned hosted fixture required');
const credentials = JSON.parse(await readFile(`${directory}/credentials.json`, 'utf8'));
const profile = credentials.profiles[0];
const secrets = credentials.reproofing;
const output = resolve('.work/reproofing-integration');
await mkdir(output, { recursive: true });
const origin = 'https://id.firefly.test:8443';
const root = `${profile.issuer}/firefly-recovery/lost-credentials`;
const callback = 'https://localhost:8448/oidc/callback';
const gates = [];
const fonts = [];
const pending = new Map();
const factors = new Map();
let phase = 'initialization';
let browser;
let callbackServer;
const delay = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));
const passed = value => { gates.push(value); console.log(`PASS ${value}`); };
const fixture = action => JSON.parse(execFileSync('python3', ['tooling/reproofing_integration_fixture.py', action], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
const basic = (client, secret) => `Basic ${Buffer.from(`${client}:${secret}`).toString('base64')}`;
async function request(url, options = {}) {
  return fetch(url, { ...options, headers: { Connection: 'close', ...options.headers }, signal: AbortSignal.timeout(20000) });
}
async function jsonPost(url, body, authorization) {
  return request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(authorization ? { Authorization: authorization } : {}) }, body: JSON.stringify(body) });
}
async function admin(suffix, options = {}, selected = profile) {
  const response = await request(`${origin}/realms/master/protocol/openid-connect/token`, { method: 'POST', body: new URLSearchParams({
    client_id: 'admin-cli', grant_type: 'password', username: 'native-bootstrap', password: credentials.admin }) });
  assert.equal(response.status, 200, 'Owned administrator unavailable');
  const token = (await response.json()).access_token;
  return request(`${origin}/admin/realms/${selected.realm}/${suffix}`, { ...options, headers: { Authorization: `Bearer ${token}`, ...options.headers } });
}
async function currentUser(person) {
  const response = await admin(`users/${person.id}`); assert.equal(response.status, 200); return response.json();
}
async function code(person, secret) {
  const key = `${person.id}:${secret}`;
  const now = Math.floor(Date.now() / 30000);
  const last = factors.get(key) ?? -1;
  if (now <= last) await delay((last + 1) * 30000 - Date.now() + 300);
  factors.set(key, Math.floor(Date.now() / 30000));
  return totpCode(secret);
}
async function authenticate(person, context, { password = person.password, secret, enroll = false, offline = false, refusePassword = false, refuseOtp = false, exactOtp } = {}) {
  const state = randomBytes(20).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const url = new URL(`${profile.issuer}/protocol/openid-connect/auth`);
  url.search = new URLSearchParams({ client_id: 'native-browser', redirect_uri: callback, response_type: 'code',
    scope: offline ? 'openid profile email offline_access' : 'openid profile email', code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256', state, nonce: randomBytes(16).toString('hex'), prompt: 'login' });
  const returned = new Promise(ok => pending.set(state, ok));
  const page = await context.newPage(); page.setDefaultTimeout(20000);
  try {
    await page.goto(url.href);
    await page.locator('#username').fill(person.username);
    await page.locator('#password').fill(password);
    await page.locator('#kc-login').click();
    if (refusePassword) { await page.locator('#password').waitFor(); return null; }
    await page.locator('#totpSecret, #otp').first().waitFor({ state: 'attached' });
    if (await page.locator('#totpSecret').count()) {
      assert.ok(enroll, 'Existing factor unexpectedly absent');
      if (await page.locator('#mode-manual').count()) await page.locator('#mode-manual').click();
      secret = (await page.locator('#kc-totp-secret-key').innerText()).replace(/\s/g, '');
      await page.locator('#totp').fill(await code(person, secret));
      if (await page.locator('#userLabel').count()) await page.locator('#userLabel').fill('Owned qualification authenticator');
      await page.locator('#saveTOTPBtn').click();
    } else {
      assert.ok(secret, 'Pre-existing possession proof required');
      await page.locator('#otp').fill(exactOtp || await code(person, secret));
      await page.locator('#kc-login').click();
      if (refuseOtp) { await page.locator('#otp').waitFor(); return null; }
    }
    if (await page.locator('#kc-oauth-consent-form').count()) await page.locator('input[name="accept"], button[name="accept"]').click();
    const responseUrl = await Promise.race([returned, delay(25000).then(() => { throw new Error('Owned authorization callback missing'); })]);
    assert.equal(responseUrl.searchParams.get('state'), state);
    const authorizationCode = responseUrl.searchParams.get('code'); assert.ok(authorizationCode);
    const token = await request(`${profile.issuer}/protocol/openid-connect/token`, { method: 'POST', body: new URLSearchParams({
      client_id: 'native-browser', grant_type: 'authorization_code', code: authorizationCode, code_verifier: verifier, redirect_uri: callback }) });
    assert.equal(token.status, 200, 'Actual ordinary token exchange refused');
    return { tokens: await token.json(), secret };
  } finally { pending.delete(state); await page.close(); }
}
async function refresh(refreshToken) {
  const response = await request(`${profile.issuer}/protocol/openid-connect/token`, { method: 'POST', body: new URLSearchParams({
    client_id: 'native-browser', grant_type: 'refresh_token', refresh_token: refreshToken }) });
  return response.status;
}
async function nativeStage(page) { return page.locator('.ffid-native-journey').getAttribute('data-stage'); }
async function submit(page) {
  const posted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === root);
  await page.locator('#ffid-lost-continue').click();
  const response = await posted;
  assert.equal(response.status(), 303, 'Native form must use PRG');
  const headers = await response.request().allHeaders();
  assert.equal(headers.origin, origin, 'Actual browser Origin must remain same-origin');
  await page.waitForURL(root);
  await page.locator('.ffid-native-journey').waitFor();
}
async function translated(page, language) {
  const select = page.locator('#login-select-toggle');
  assert.equal(await select.count(), 1, 'Actual quiet native locale footer required');
  const options = await select.locator('option').evaluateAll(items => items.map(option => ({ value: option.value, language: new URL(option.value).searchParams.get('kc_locale') })));
  const option = options.find(item => item.language === language); assert.ok(option);
  await select.selectOption(option.value);
  await page.locator('.ffid-native-journey').waitFor();
  assert.ok((await page.locator('html').getAttribute('lang')).startsWith(language));
}
async function capture(page, name, { enrollment = false } = {}) {
  for (const input of await page.locator('input:not([type=hidden])').all()) assert.equal(await input.inputValue(), '', 'Capture fields must be empty');
  const masks = enrollment ? [page.locator('#ffid-lost-enrollment-secret')] : [];
  if (!enrollment) assert.equal(await page.locator('#ffid-lost-enrollment-secret').count(), 0, 'Unmasked enrollment secret forbidden');
  await page.evaluate(() => document.fonts.ready);
  const measured = await page.evaluate(() => ({
    loaded: [...document.fonts].some(face => face.family.replace(/["']/g, '').toLowerCase() === 'manrope' && face.status === 'loaded'),
    families: ['#kc-page-title', '.ffid-native-journey p', '.ffid-native-journey label'].flatMap(selector => [...document.querySelectorAll(selector)].filter(node => node.getClientRects().length).slice(0, 1).map(node => getComputedStyle(node).fontFamily)),
    request: performance.getEntriesByType('resource').find(entry => new URL(entry.name).pathname.endsWith('/manrope.woff2'))?.name,
  }));
  assert.ok(measured.loaded && measured.families.length >= 2 && measured.families.every(value => /Manrope/i.test(value)), 'Actual rendered Manrope required');
  assert.ok(measured.request);
  const font = await page.request.get(measured.request); assert.equal(font.status(), 200);
  const canonical = await readFile(resolve('dist/themes/firefly-id/login/resources/fonts/manrope.woff2'));
  const hash = value => createHash('sha256').update(value).digest('hex');
  assert.equal(hash(await font.body()), hash(canonical));
  fonts.push({ name, canonicalFontHash: hash(canonical), loaded: measured.loaded, families: measured.families });
  await writeFile(`${output}/fonts.json`, JSON.stringify(fonts, null, 2));
  for (const [width, height] of [[1440, 1000], [390, 844]]) {
    await page.setViewportSize({ width, height });
    for (const mode of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: mode });
      await page.waitForFunction(dark => document.documentElement.classList.contains('pf-v5-theme-dark') === dark, mode === 'dark');
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Actual journey clips horizontally');
      const links = await page.locator('a.ffid-journey-return').evaluateAll(items => items.filter(item => item.getClientRects().length).map(item => item.getBoundingClientRect().height));
      assert.ok(links.every(height => height >= 43.5), 'Return links require 44px targets');
      await page.screenshot({ path: `${output}/${name}-${width}-${mode}.png`, fullPage: true, mask: masks, maskColor: '#272820' });
    }
  }
}
async function startRecovery(username, language = 'en') {
  const context = await browser.newContext();
  const page = await context.newPage(); page.setDefaultTimeout(25000);
  await page.goto(`${root}?kc_locale=${language}`);
  assert.equal(await nativeStage(page), 'IDENTIFY');
  assert.equal(await page.locator('input[type=password]').count(), 0, 'Previous password must never be requested');
  await page.locator('[name=username]').fill(username);
  await submit(page);
  assert.equal(await nativeStage(page), 'VERIFY');
  const provider = page.locator('#ffid-lost-provider');
  assert.equal(await provider.getAttribute('target'), '_blank');
  assert.ok((await provider.getAttribute('rel')).includes('noopener'));
  const href = await provider.getAttribute('href'); assert.equal(new URL(href).origin, profile.domain);
  const sessionId = decodeURIComponent(new URL(href).pathname.split('/').pop());
  return { context, page, sessionId };
}
async function providerResult(journey, mode) {
  const response = await jsonPost(`${profile.domain}/fixture/reproofing/sessions/${encodeURIComponent(journey.sessionId)}`, { mode }, basic(secrets.fixture_client, secrets['fixture-control']));
  assert.ok(response.ok, 'Owned proofing fixture control unavailable');
}
async function enrollment(journey, mode = 'APPROVED') {
  await providerResult(journey, mode);
  await submit(journey.page);
  assert.equal(await nativeStage(journey.page), 'ENROLL', 'Independently approved exact proofing case must permit enrollment');
  const secret = (await journey.page.locator('#ffid-lost-enrollment-secret').innerText()).replace(/\s/g, '');
  assert.ok(/^[A-Z2-7]+$/.test(secret), 'Native enrollment secret unavailable');
  return secret;
}
async function replace(journey, person, secret, password) {
  const remaining = 30000 - Date.now() % 30000;
  if (remaining < 18000) await delay(remaining + 300);
  await journey.page.locator('[name=password]').fill(password);
  await journey.page.locator('[name=passwordConfirm]').fill(password);
  const otp = await code(person, secret);
  await journey.page.locator('[name=otp]').fill(otp);
  await submit(journey.page);
  assert.equal(await nativeStage(journey.page), 'COMPLETE');
  return otp;
}
async function receiverControls() {
  for (const base of [profile.core, profile.domain]) {
    for (const suffix of ['', '/00000000-0000-0000-0000-000000000001/confirm', '/00000000-0000-0000-0000-000000000001/authorizations/consume']) {
      const response = await jsonPost(`${base}/api/v1/identity-recovery/cases${suffix}`, {});
      assert.equal(response.status, 403, 'Unauthenticated receiving boundary must deny');
    }
  }
  const verifier = await jsonPost(`${profile.domain}/internal/identity-recovery/evidence`, {}, basic(secrets.native_client, secrets['native-domain']));
  assert.equal(verifier.status, 403, 'Native workload cannot verify its own evidence');
  for (const route of ['prepare', 'admit', 'journal', 'dispatch']) {
    const response = await jsonPost(`${root}/rpc/${route}`, {}); assert.equal(response.status, 403);
  }
  const staff = credentials.profiles[1];
  const response = await request(`${staff.issuer}/firefly-recovery/lost-credentials`);
  assert.equal(response.status, 400, 'Customer authority must not recover workforce');
  passed('receiving-services-and-native-rpc-deny-missing-or-wrong-purpose-workload');
  passed('customer-proofing-authority-does-not-recover-workforce');
}
async function csrfControls() {
  const context = await browser.newContext(); const page = await context.newPage();
  await page.goto(root);
  const csrf = await page.locator('[name=csrf]').inputValue();
  for (const supplied of ['null', 'https://foreign.example.invalid']) {
    const response = await context.request.post(root, { headers: { Origin: supplied }, form: { csrf, username: profile.person.username } });
    assert.equal(response.status(), 400);
  }
  const response = await context.request.post(root, { headers: { Origin: origin }, form: { csrf: 'forged-csrf', username: profile.person.username } });
  assert.equal(response.status(), 400);
  await context.close(); passed('native-real-cookie-csrf-and-null-or-foreign-origin-refused');
}

try {
  callbackServer = createServer({ key: await readFile(`${directory}/tls/proxy.key`), cert: await readFile(`${directory}/tls/server.crt`) }, (incoming, response) => {
    const url = new URL(incoming.url, callback);
    response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    response.end('Owned qualification callback.');
    if (url.pathname === '/oidc/callback') pending.get(url.searchParams.get('state'))?.(url);
  });
  await new Promise((ok, fail) => callbackServer.listen(8448, '127.0.0.1', ok).once('error', fail));
  browser = await chromium.launch();
  phase = 'receiving-boundaries'; await receiverControls(); await csrfControls();
  phase = 'initial-identification-design';
  const designContext = await browser.newContext(); const design = await designContext.newPage();
  await design.goto(`${root}?kc_locale=en`); await capture(design, 'identify-en-empty-form');
  await translated(design, 'es'); await capture(design, 'identify-es-empty-form');
  await design.goto(root); assert.ok((await design.locator('html').getAttribute('lang')).startsWith('es'));
  await designContext.close(); passed('manrope-bilingual-light-dark-mobile-desktop-identification-and-clean-url-locale');
  phase = 'positive-preexisting-sessions';
  const onlineContext = await browser.newContext();
  const initial = await authenticate(profile.person, onlineContext, { enroll: true });
  const oldSecret = initial.secret;
  const offlineContext = await browser.newContext();
  const offline = await authenticate(profile.person, offlineContext, { secret: oldSecret, offline: true });
  assert.equal(await refresh(initial.tokens.refresh_token), 200); assert.equal(await refresh(offline.tokens.refresh_token), 200);
  passed('real-previous-password-enrolled-totp-and-online-offline-refreshes-positive');
  phase = 'generic-unknown-and-administrative-hold';
  for (const username of ['unknown-owned-subject', profile.manual.username]) {
    const journey = await startRecovery(username);
    await providerResult(journey, 'APPROVED'); await submit(journey.page);
    assert.equal(await nativeStage(journey.page), 'VERIFY');
    assert.equal(await journey.page.locator('[name=password]').count(), 0);
    await journey.context.close();
  }
  assert.equal((await currentUser(profile.person)).enabled, true);
  passed('unknown-and-held-identities-share-provider-journey-but-never-grant-or-disable-victim');
  phase = 'provider-forgery-reference-replay-and-expiry';
  for (const mode of ['FORGED', 'WRONG_REFERENCE', 'REPLAYED', 'EXPIRED', 'UNAVAILABLE']) {
    const journey = await startRecovery(profile.person.username);
    await providerResult(journey, mode); await submit(journey.page);
    assert.equal(await nativeStage(journey.page), 'VERIFY');
    await journey.context.close();
  }
  passed('forged-wrong-reference-replayed-expired-and-unavailable-proofing-never-replace');
  phase = 'enabled-account-credential-loss';
  const recovery = await startRecovery(profile.person.email, 'en');
  await capture(recovery.page, 'provider-en-empty-form');
  await translated(recovery.page, 'es'); await capture(recovery.page, 'provider-es-empty-form');
  const newSecret = await enrollment(recovery);
  await capture(recovery.page, 'enrollment-es-empty-form', { enrollment: true });
  await translated(recovery.page, 'en'); await capture(recovery.page, 'enrollment-en-empty-form', { enrollment: true });
  const newPassword = randomBytes(30).toString('base64url') + 'aA9!';
  const enrollmentCode = await replace(recovery, profile.person, newSecret, newPassword);
  assert.equal(await refresh(initial.tokens.refresh_token), 400); assert.equal(await refresh(offline.tokens.refresh_token), 400);
  assert.equal((await currentUser(profile.person)).enabled, true);
  const sessions = await admin(`users/${profile.person.id}/sessions`); assert.equal(sessions.status, 200); assert.equal((await sessions.json()).length, 0);
  passed('enabled-user-replaces-credentials-without-old-password-and-retires-preexisting-sessions');
  phase = 'superseded-credentials-refused';
  const enrollmentReplayContext = await browser.newContext();
  assert.equal(totpCode(newSecret), enrollmentCode, 'Enrollment replay probe must retain a genuine live-code precondition');
  await authenticate(profile.person, enrollmentReplayContext, { password: newPassword, secret: newSecret, exactOtp: enrollmentCode, refuseOtp: true });
  passed('native-enrollment-code-cannot-authenticate-again');
  await enrollmentReplayContext.close();
  const freshSignIn = async () => {
    const context = await browser.newContext();
    await authenticate(profile.person, context, { password: newPassword, secret: newSecret });
    await context.close();
  };
  // Each positive sign-in restores a genuine normal admission between negative
  // probes; three distinct tests must not accidentally trigger permanent lock.
  await freshSignIn();
  const oldPasswordContext = await browser.newContext(); await authenticate(profile.person, oldPasswordContext, { refusePassword: true }); await oldPasswordContext.close();
  await freshSignIn();
  const oldFactorContext = await browser.newContext(); await authenticate(profile.person, oldFactorContext, { password: newPassword, secret: oldSecret, refuseOtp: true }); await oldFactorContext.close();
  await freshSignIn();
  passed('old-password-and-old-totp-refused-new-password-and-fresh-totp-sign-in');
  await capture(recovery.page, 'replacement-en-complete');
  await translated(recovery.page, 'es'); await capture(recovery.page, 'replacement-es-complete');
  phase = 'native-notification-dispatch';
  const dispatched = await jsonPost(`${root}/rpc/dispatch`, {}, basic('reproofing-core-owner', secrets['core-native']));
  assert.equal(dispatched.status, 200); assert.ok((await dispatched.json()).processed >= 1);
  const messages = await request('http://127.0.0.1:8025/api/v1/messages'); assert.equal(messages.status, 200);
  const mail = await messages.json();
  assert.ok(mail.messages.some(message => message.To?.some(to => to.Address === profile.person.email)), 'Actual replacement notice must reach previous verified destination');
  passed('durable-native-notification-dispatch-delivers-to-previous-verified-channel');
  phase = 'permanently-locked-account-credential-loss';
  const lockedPerson = profile.locked;
  const lockedContext = await browser.newContext(); await authenticate(lockedPerson, lockedContext, { enroll: true });
  await lockedContext.close();
  for (let attempt = 0; attempt < 3; attempt++) {
    const context = await browser.newContext();
    await authenticate(lockedPerson, context, { password: 'owned-wrong-password-probe', refusePassword: true });
    await context.close();
  }
  for (let probe = 0; probe < 15 && (await currentUser(lockedPerson)).enabled; probe++) await delay(1000);
  assert.equal((await currentUser(lockedPerson)).enabled, false, 'Real permanent lock must precede replacement');
  const lockedRecovery = await startRecovery(lockedPerson.username, 'es');
  const lockedSecret = await enrollment(lockedRecovery);
  const lockedPassword = randomBytes(30).toString('base64url') + 'aA9!';
  await replace(lockedRecovery, lockedPerson, lockedSecret, lockedPassword);
  assert.equal((await currentUser(lockedPerson)).enabled, true);
  const lockedFresh = await browser.newContext(); await authenticate(lockedPerson, lockedFresh, { password: lockedPassword, secret: lockedSecret });
  await lockedFresh.close(); await lockedRecovery.context.close();
  passed('real-permanent-authentication-lock-and-lost-credentials-replaced-before-fresh-mfa');
  phase = 'changed-current-state-after-proofing';
  const heldPerson = profile['held-after-proof'];
  const heldContext = await browser.newContext(); await authenticate(heldPerson, heldContext, { enroll: true }); await heldContext.close();
  const heldRecovery = await startRecovery(heldPerson.username);
  const heldSecret = await enrollment(heldRecovery);
  const heldResponse = await admin(`users/${heldPerson.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: false }) });
  assert.equal(heldResponse.status, 204);
  await heldRecovery.page.locator('[name=password]').fill(randomBytes(30).toString('base64url') + 'aA9!');
  await heldRecovery.page.locator('[name=passwordConfirm]').fill(await heldRecovery.page.locator('[name=password]').inputValue());
  await heldRecovery.page.locator('[name=otp]').fill(totpCode(heldSecret));
  await heldRecovery.page.locator('#ffid-lost-continue').click();
  assert.equal((await currentUser(heldPerson)).enabled, false, 'An approved proof must never override a later administrative hold');
  await heldRecovery.context.close();
  passed('administrative-disable-after-proofing-refuses-activation');
  phase = 'literal-completion-reload'; await recovery.page.reload(); assert.equal(await nativeStage(recovery.page), 'COMPLETE');
  await recovery.context.close(); await onlineContext.close(); await offlineContext.close();
  passed('literal-completion-reload-preserves-execution-and-requires-fresh-sign-in');
  await writeFile(`${output}/summary.json`, JSON.stringify({ scope: 'Actual native/Core/customer Domain with test-only proofing adapter; real provider, workforce recovery, receiver-wide JWT revocation and production acceptance excluded', gates, failed: [], fontMeasurements: fonts.length }, null, 2));
} catch (error) {
  await writeFile(`${output}/summary.json`, JSON.stringify({ scope: 'Incomplete actual native/customer proofing qualification', gates, failed: [{ phase, kind: error instanceof assert.AssertionError ? 'assertion' : 'runtime' }] }, null, 2));
  reportFailure(error, phase);
  process.exitCode = 1;
} finally {
  await browser?.close();
  await new Promise(ok => callbackServer ? callbackServer.close(ok) : ok());
}
