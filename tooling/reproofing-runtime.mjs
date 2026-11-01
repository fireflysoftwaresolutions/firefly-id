import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { totpCode } from './extended-runtime.mjs';
import { reportFailure } from './safe-errors.mjs';
import { assertIdentityArtworkReady } from './identity-artwork.mjs';

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
const diagnostics = {};
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
const monitorUrl = `${profile.core}/internal/identity-recovery/notifications`;
const notificationMetricsUrl = `${monitorUrl}/metrics`;
const monitorAuthorization = () => basic(secrets.monitor_client, secrets['notification-monitor']);
async function notificationMetrics() {
  const response = await request(notificationMetricsUrl, { headers: { Authorization: monitorAuthorization() } });
  assert.equal(response.status, 200, 'Notification metrics require the private monitor receiver');
  assert.match(response.headers.get('content-type') || '', /text\/plain|application\/openmetrics-text/);
  const metrics = await response.text();
  const samples = metrics.split('\n').filter(line => line.trim() && !line.startsWith('#'));
  assert.ok(samples.length > 0 && samples.every(line => line.startsWith('firefly_reproofing_notifications_')),
    'The notification monitor must not acquire unrelated application metrics');
  assert.doesNotMatch(metrics, /(?:subject|email|case_id|execution_id|nonce|tenant_id)\s*=/);
  diagnostics.notificationMetricSamples = samples.length;
  return metrics;
}
async function notificationMonitor() {
  const response = await request(monitorUrl, { headers: { Authorization: monitorAuthorization() } });
  assert.equal(response.status, 200, 'Private notification monitor must be available to its own workload');
  const snapshot = await response.json();
  assert.deepEqual(Object.keys(snapshot).sort(), ['state', 'activeCycle', 'lastAttemptAt', 'lastSuccessAt', 'consecutiveFailures', 'queue'].sort());
  assert.ok(['STARTING', 'HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'STALE'].includes(snapshot.state));
  if (snapshot.queue !== null) {
    assert.deepEqual(Object.keys(snapshot.queue).sort(), ['observedAt', 'pending', 'sending', 'retrying', 'delivered', 'failed', 'invalid', 'due', 'oldestDueDelaySeconds'].sort());
    assert.equal(typeof snapshot.queue.observedAt, 'string');
    assert.ok(Number.isFinite(Date.parse(snapshot.queue.observedAt)));
    for (const key of ['pending', 'sending', 'retrying', 'delivered', 'failed', 'invalid', 'due', 'oldestDueDelaySeconds']) {
      assert.ok(Number.isSafeInteger(snapshot.queue[key]) && snapshot.queue[key] >= 0);
    }
    diagnostics.notificationQueue = snapshot.queue;
  }
  diagnostics.notificationMonitorState = snapshot.state;
  return snapshot;
}
async function waitNotificationMonitor(predicate, timeout = 90000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const snapshot = await notificationMonitor();
    if (predicate(snapshot)) return snapshot;
    await delay(1000);
  }
  throw new Error('Owned notification supervision condition timed out');
}
async function notificationControls() {
  for (const authorization of [undefined, basic(secrets.domain_client, secrets['domain-core']), basic(secrets.notification_client, secrets['core-notification'])]) {
    for (const url of [monitorUrl, notificationMetricsUrl]) {
      const response = await request(url, { headers: authorization ? { Authorization: authorization } : {} });
      assert.equal(response.status, 403, 'Only the separate monitor workload may observe the queue or its metrics');
    }
  }
  assert.equal((await jsonPost(monitorUrl, {}, monitorAuthorization())).status, 403);
  assert.equal((await jsonPost(notificationMetricsUrl, {}, monitorAuthorization())).status, 403);
  assert.equal((await request(`${monitorUrl}/unexpected`, { headers: { Authorization: monitorAuthorization() } })).status, 403);
  assert.equal((await jsonPost(`${profile.core}/api/v1/identity-recovery/cases`, {}, monitorAuthorization())).status, 403);
  const healthy = await waitNotificationMonitor(value => value.state === 'HEALTHY' && value.queue !== null);
  assert.equal(healthy.queue.pending, 0); assert.equal(healthy.queue.failed, 0);
  await notificationMetrics();
  const globalMetrics = await request(`${profile.core}/actuator/prometheus`);
  if (globalMetrics.status === 200) {
    assert.doesNotMatch(await globalMetrics.text(), /firefly_reproofing_notifications_/,
      'Private notification series must not leak through the pre-existing global registry');
  } else {
    assert.ok([401, 403, 404].includes(globalMetrics.status));
  }
  passed('notification-metrics-remain-private-and-absent-from-the-global-registry');
  for (const route of ['dispatch', 'notification-status']) {
    for (const authorization of [basic('reproofing-core-owner', secrets['core-native']), basic('reproofing-domain-owner', secrets['domain-native'])]) {
      assert.equal((await jsonPost(`${root}/rpc/${route}`, {}, authorization)).status, 403);
    }
  }
  for (const route of ['prepare', 'admit', 'journal']) {
    assert.equal((await jsonPost(`${root}/rpc/${route}`, {}, basic(secrets.notification_client, secrets['core-notification']))).status, 403);
  }
  passed('private-notification-monitor-and-dedicated-worker-cannot-acquire-case-or-ceremony-authority');
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
  if (response.status !== 200) return { status: response.status };
  const value = await response.json();
  assert.ok(value.refresh_token, 'Positive refresh must retain its current replacement token');
  return { status: response.status, refreshToken: value.refresh_token };
}
async function nativeStage(page) { return page.locator('.ffid-native-journey').getAttribute('data-stage'); }
async function submit(page) {
  diagnostics.nativeStage = await nativeStage(page);
  const posted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === root);
  const landed = page.waitForNavigation({ waitUntil: 'domcontentloaded' });
  await page.locator('#ffid-lost-continue').click();
  const response = await posted;
  diagnostics.nativePostStatus = response.status();
  const headers = await response.request().allHeaders();
  diagnostics.nativeOrigin = headers.origin === origin ? 'same' : headers.origin === 'null' ? 'null' : 'other';
  diagnostics.nativeCookiePresent = (headers.cookie || '').split(';').some(value => value.trim().startsWith('FF_REPROOFING='));
  const submitted = new URLSearchParams(response.request().postData() || '');
  diagnostics.nativeCsrfPresent = Boolean(submitted.get('csrf'));
  diagnostics.nativeFieldCount = [...submitted.keys()].length;
  diagnostics.nativeBodyBytes = Buffer.byteLength(response.request().postData() || '');
  diagnostics.declaredContentLength = /^[0-9]+$/.test(headers['content-length'] || '') ? Number(headers['content-length']) : 'absent';
  assert.equal(response.status(), 303, 'Native form must use PRG');
  assert.equal(headers.origin, origin, 'Actual browser Origin must remain same-origin');
  await landed;
  assert.equal(page.url(), root);
  await page.locator('.ffid-native-journey').waitFor();
}
async function translated(page, language) {
  const select = page.locator('#login-select-toggle');
  assert.equal(await select.count(), 1, 'Actual quiet native locale footer required');
  const options = await select.locator('option').evaluateAll(items => items.map(option => ({ value: option.value, language: new URL(option.value, location.href).searchParams.get('kc_locale') })));
  const option = options.find(item => item.language === language); assert.ok(option);
  const [navigated] = await Promise.all([page.waitForNavigation({ waitUntil: "domcontentloaded" }), select.selectOption(option.value)]);
  assert.equal(navigated.status(), 200);
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
      await assertIdentityArtworkReady(page, mode);
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
  diagnostics.enrollmentPhase = 'external-provider-tab';
  const originalNativeUrl = journey.page.url();
  assert.equal(new URL(originalNativeUrl).origin + new URL(originalNativeUrl).pathname, root);
  const popupOpened = journey.context.waitForEvent('page');
  await journey.page.locator('#ffid-lost-provider').click();
  const popup = await popupOpened;
  await popup.waitForLoadState('domcontentloaded');
  assert.equal(new URL(popup.url()).origin, profile.domain);
  assert.equal(await popup.evaluate(() => window.opener === null), true, 'External provider must not control the native tab');
  await popup.close();
  assert.equal(journey.page.url(), originalNativeUrl, 'The original strict-cookie native tab and selected locale must remain unchanged');
  const cookie = (await journey.context.cookies([root])).find(value => value.name === 'FF_REPROOFING');
  assert.ok(cookie && cookie.httpOnly && cookie.secure && cookie.sameSite === 'Strict');
  diagnostics.enrollmentPhase = 'independent-provider-result';
  await providerResult(journey, mode);
  await submit(journey.page);
  assert.equal(await nativeStage(journey.page), 'ENROLL', 'Independently approved exact proofing case must permit enrollment');
  diagnostics.enrollmentPhase = 'fresh-authenticator-setup';
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
  for (const route of ['prepare', 'admit', 'journal', 'dispatch', 'notification-status']) {
    const response = await jsonPost(`${root}/rpc/${route}`, {}); assert.equal(response.status, 403);
  }
  const staff = credentials.profiles[1];
  const response = await request(`${staff.issuer}/firefly-recovery/lost-credentials`);
  assert.equal(response.status, 400, 'Customer authority must not recover workforce');
  passed('receiving-services-and-native-rpc-deny-missing-or-wrong-purpose-workload');
  passed('customer-proofing-authority-does-not-recover-workforce');
  await notificationControls();
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

async function seedSupportPin(context, oldSecret) {
  const page = await context.newPage();
  await page.goto(`${profile.issuer}/firefly-recovery/support-pin/set?kc_locale=en`);
  await page.locator('#ffid-support-pin').waitFor();
  await page.locator('#password').fill(profile.person.password);
  await page.locator('#otp').fill(await code(profile.person, oldSecret));
  let pin;
  do { pin = [...randomBytes(8)].map(value => String(value % 10)).join(''); }
  while (/^(\d)\1{7}$/.test(pin) || pin.slice(0, 4) === pin.slice(4) || pin.slice(0, 2).repeat(4) === pin
    || '01234567890123456789'.includes(pin) || '98765432109876543210'.includes(pin));
  await page.locator('#pin').fill(pin); await page.locator('#pinConfirm').fill(pin);
  const posted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === `${profile.issuer}/firefly-recovery/support-pin`);
  const landed = page.waitForNavigation({ waitUntil: 'domcontentloaded' });
  await page.locator('#ffid-pin-save').click();
  assert.equal((await posted).status(), 303); await landed;
  await page.locator('#ffid-support-pin').waitFor({ state: 'detached' });
  const state = fixture('snapshot').native;
  assert.equal(state.pinStored, 1); assert.equal(state.pinAuthority.credentialPresent, true); assert.equal(state.pinAuthority.held, false);
  await page.close(); return state.pinAuthority;
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
  const onlineProbe = await refresh(initial.tokens.refresh_token);
  const offlineProbe = await refresh(offline.tokens.refresh_token);
  assert.equal(onlineProbe.status, 200); assert.equal(offlineProbe.status, 200);
  initial.tokens.refresh_token = onlineProbe.refreshToken;
  offline.tokens.refresh_token = offlineProbe.refreshToken;
  const clients = await admin('clients?clientId=native-browser'); assert.equal(clients.status, 200);
  const internalClient = (await clients.json())[0].id;
  const offlinePath = `users/${profile.person.id}/offline-sessions/${internalClient}`;
  const onlineSessions = await admin(`users/${profile.person.id}/sessions`);
  const offlineSessions = await admin(offlinePath);
  assert.equal(onlineSessions.status, 200); assert.ok((await onlineSessions.json()).length > 0);
  assert.equal(offlineSessions.status, 200); assert.ok((await offlineSessions.json()).length > 0);
  passed('real-previous-password-enrolled-totp-and-online-offline-refreshes-positive');
  phase = 'real-support-pin-before-credential-loss';
  const previousPin = await seedSupportPin(onlineContext, oldSecret);
  passed('real-customer-support-pin-created-with-password-and-enrolled-totp-before-recovery');
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
  const negativeState = fixture('snapshot');
  assert.equal(negativeState.core.grants, 0, 'Negative journeys must not secretly issue a Core grant');
  assert.equal(negativeState.core.verifiedGrantTotal, 0, 'Unverified/forged journeys cannot debit a victim grant ledger');
  assert.equal(negativeState.native.executions, 0, 'Negative journeys must not mutate credentials');
  passed('forged-wrong-reference-replayed-expired-and-unavailable-proofing-never-replace');
  phase = 'authenticated-case-refusal-budget';
  const grantsBeforeRejection = fixture('snapshot').core.grants;
  const rejected = await startRecovery(profile.person.username);
  await providerResult(rejected, 'REJECTED');
  for (let attempt = 0; attempt < 3; attempt++) {
    await submit(rejected.page); assert.equal(await nativeStage(rejected.page), 'VERIFY');
    assert.doesNotMatch(await rejected.page.locator('.ffid-native-journey').innerText(), /\b[0-3]\s+(?:attempt|intento)/i);
  }
  await providerResult(rejected, 'APPROVED'); await submit(rejected.page);
  assert.equal(await nativeStage(rejected.page), 'VERIFY');
  const rejectionState = fixture('snapshot');
  assert.equal(rejectionState.core.grants, grantsBeforeRejection);
  assert.equal(rejectionState.core.verifiedGrantTotal, 0);
  assert.ok(rejectionState.core.cases.some(value => value.status === 'DENIED' && value.failures === 3));
  await rejected.context.close();
  passed('three-authenticated-case-refusals-preserved-without-target-grant-budget-or-public-count');
  phase = 'enabled-account-credential-loss';
  const recovery = await startRecovery(profile.person.email, 'en');
  await capture(recovery.page, 'provider-en-empty-form');
  await translated(recovery.page, 'es'); await capture(recovery.page, 'provider-es-empty-form');
  const newSecret = await enrollment(recovery);
  await capture(recovery.page, 'enrollment-es-empty-form', { enrollment: true });
  await translated(recovery.page, 'en'); await capture(recovery.page, 'enrollment-en-empty-form', { enrollment: true });
  const newPassword = randomBytes(30).toString('base64url') + 'aA9!';
  const currentOnline = await refresh(initial.tokens.refresh_token); assert.equal(currentOnline.status, 200); initial.tokens.refresh_token = currentOnline.refreshToken;
  const currentOffline = await refresh(offline.tokens.refresh_token); assert.equal(currentOffline.status, 200); offline.tokens.refresh_token = currentOffline.refreshToken;
  diagnostics.notificationPhase = 'stop-owned-transport-before-replacement';
  fixture('mail-stop');
  fixture('arm-record-loss');
  const enrollmentCode = await replace(recovery, profile.person, newSecret, newPassword);
  assert.equal(fixture('fault-status').recordResponseDropped, true, 'Actual committed Domain/Core response loss required');
  assert.equal((await refresh(initial.tokens.refresh_token)).status, 400); assert.equal((await refresh(offline.tokens.refresh_token)).status, 400);
  assert.equal((await currentUser(profile.person)).enabled, true);
  const sessions = await admin(`users/${profile.person.id}/sessions`); assert.equal(sessions.status, 200); assert.equal((await sessions.json()).length, 0);
  const retiredOffline = await admin(offlinePath); assert.equal(retiredOffline.status, 200); assert.equal((await retiredOffline.json()).length, 0);
  const retiredPin = fixture('snapshot').native;
  assert.equal(retiredPin.pinStored, 0); assert.equal(retiredPin.pinAuthority.credentialPresent, false); assert.equal(retiredPin.pinAuthority.held, true);
  assert.equal(retiredPin.pinAuthority.revoked, true); assert.notEqual(retiredPin.pinAuthority.generation, previousPin.generation);
  assert.equal(retiredPin.pinAuthority.failures, previousPin.failures); assert.equal(retiredPin.pinAuthority.reserved, previousPin.reserved);
  passed('credential-replacement-retires-real-support-pin-and-preserves-its-existing-budgets');
  passed('enabled-user-replaces-credentials-without-old-password-and-retires-preexisting-sessions');
  phase = 'superseded-credentials-refused';
  const enrollmentReplayContext = await browser.newContext();
  assert.equal(totpCode(newSecret), enrollmentCode, 'Enrollment replay probe must retain a genuine live-code precondition');
  await authenticate(profile.person, enrollmentReplayContext, { password: newPassword, secret: newSecret, exactOtp: enrollmentCode, refuseOtp: true });
  passed('native-enrollment-code-cannot-authenticate-again');
  await enrollmentReplayContext.close();
  diagnostics.notificationPhase = 'observe-automatic-failed-delivery';
  await waitNotificationMonitor(value => value.state === 'DEGRADED' && value.queue?.retrying > 0, 30000);
  const beforeWorkerRestart = fixture('snapshot');
  assert.equal(beforeWorkerRestart.native.notifications.length, 1, 'One real replacement notice must precede worker restart');
  assert.ok(beforeWorkerRestart.native.notifications.some(value => value.status === 'PENDING' && value.attempts >= 1));
  diagnostics.notificationPhase = 'restart-only-owned-core-poller';
  const restartedAt = Date.now();
  fixture('restart-core');
  const reobserved = await waitNotificationMonitor(value => value.state === 'DEGRADED' && value.queue?.retrying > 0
    && typeof value.lastSuccessAt === 'string' && Date.parse(value.lastSuccessAt) >= restartedAt - 1000, 45000);
  assert.ok(Date.parse(reobserved.queue.observedAt) >= restartedAt - 1000);
  const afterWorkerRestart = fixture('snapshot');
  assert.equal(afterWorkerRestart.native.notifications.length, 1);
  assert.equal(afterWorkerRestart.native.executions, beforeWorkerRestart.native.executions);
  for (const field of ['cases', 'grants', 'verifiedGrantTotal', 'consumedAudits', 'executedAudits']) assert.deepEqual(afterWorkerRestart.core[field], beforeWorkerRestart.core[field]);
  assert.ok(afterWorkerRestart.native.notifications.some(value => value.attempts >= beforeWorkerRestart.native.notifications[0].attempts));
  passed('automatic-poller-failure-and-core-restart-preserve-native-queue-attempts-and-original-recovery');
  fixture('mail-start');
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
  diagnostics.notificationPhase = 'await-automatic-backoff-delivery';
  await waitNotificationMonitor(value => value.state === 'HEALTHY' && value.queue?.delivered >= 1 && value.queue.retrying === 0, 180000);
  diagnostics.notificationStates = fixture('snapshot').native.notifications;
  const messages = await request('http://127.0.0.1:8025/api/v1/messages'); assert.equal(messages.status, 200);
  const mail = await messages.json();
  diagnostics.notificationPhase = 'confirm-previous-verified-destination';
  diagnostics.notificationMessageCount = mail.messages.length;
  assert.ok(mail.messages.some(message => message.To?.some(to => to.Address === profile.person.email)), 'Actual replacement notice must reach previous verified destination');
  assert.ok(fixture('snapshot').native.notifications.some(value => value.status === 'DELIVERED' && value.attempts >= 2));
  passed('automatic-notification-poller-retries-transport-failure-without-manual-dispatch-or-new-recovery');
  passed('supervised-poller-delivers-to-previous-verified-channel-and-reports-healthy');
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
  phase = 'verified-grant-budget-and-enabled-only-identity-invalidation';
  const changedPerson = profile.changed;
  const changedContext = await browser.newContext(); await authenticate(changedPerson, changedContext, { enroll: true }); await changedContext.close();
  const changedJourneys = [];
  for (let issuance = 0; issuance < 3; issuance++) {
    const journey = await startRecovery(changedPerson.username);
    changedJourneys.push({ ...journey, secret: await enrollment(journey) });
  }
  const exhausted = await startRecovery(changedPerson.username);
  await providerResult(exhausted, 'APPROVED'); await submit(exhausted.page);
  assert.equal(await nativeStage(exhausted.page), 'VERIFY');
  await exhausted.context.close();
  const beforeIdentityChange = fixture('snapshot');
  assert.equal(beforeIdentityChange.native.changedLegacyStates, 0, 'Enabled-only invalidation must not rely on legacy permanent-lock state');
  assert.equal(beforeIdentityChange.core.changedLiveGrants, 3, 'All original grant expiries must remain live before changing identity');
  const changedUser = await currentUser(changedPerson);
  const changedResponse = await admin(`users/${changedPerson.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attributes: { ...changedUser.attributes, party_id: [randomUUID()] } }) });
  assert.equal(changedResponse.status, 204);
  const stale = changedJourneys[0];
  const stalePassword = randomBytes(30).toString('base64url') + 'aA9!';
  await stale.page.locator('[name=password]').fill(stalePassword);
  await stale.page.locator('[name=passwordConfirm]').fill(stalePassword);
  await stale.page.locator('[name=otp]').fill(totpCode(stale.secret));
  await submit(stale.page); assert.notEqual(await nativeStage(stale.page), 'COMPLETE');
  const afterIdentityChange = fixture('snapshot');
  assert.equal(afterIdentityChange.native.executions, beforeIdentityChange.native.executions);
  assert.ok(afterIdentityChange.native.changedInvalidationAudits > beforeIdentityChange.native.changedInvalidationAudits);
  assert.equal(afterIdentityChange.native.epochs.find(value => value.subject === changedPerson.id).epoch,
    beforeIdentityChange.native.epochs.find(value => value.subject === changedPerson.id).epoch, 'Administrative invalidation must preserve recovery epoch and budgets');
  for (const journey of changedJourneys) await journey.context.close();
  passed('three-verified-grants-span-cases-without-reset-and-enabled-only-party-change-invalidates-live-work');
  phase = 'previous-verified-contact-change';
  const contactPerson = profile.contact;
  const contactContext = await browser.newContext(); await authenticate(contactPerson, contactContext, { enroll: true }); await contactContext.close();
  const contactJourney = await startRecovery(contactPerson.username);
  const contactSecret = await enrollment(contactJourney);
  const beforeContact = fixture('snapshot').native.executions;
  const contactResponse = await admin(`users/${contactPerson.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'changed-destination@example.invalid', emailVerified: true }) });
  assert.equal(contactResponse.status, 204);
  const contactPassword = randomBytes(30).toString('base64url') + 'aA9!';
  await contactJourney.page.locator('[name=password]').fill(contactPassword);
  await contactJourney.page.locator('[name=passwordConfirm]').fill(contactPassword);
  await contactJourney.page.locator('[name=otp]').fill(totpCode(contactSecret));
  await submit(contactJourney.page); assert.notEqual(await nativeStage(contactJourney.page), 'COMPLETE');
  assert.equal(fixture('snapshot').native.executions, beforeContact);
  await contactJourney.context.close();
  passed('previously-verified-destination-change-invalidates-unexecuted-replacement');
  phase = 'credential-loss-before-original-factor-enrollment';
  const unconfigured = profile['never-enrolled'];
  const unconfiguredCredentials = await admin(`users/${unconfigured.id}/credentials`); assert.equal(unconfiguredCredentials.status, 200);
  assert.equal((await unconfiguredCredentials.json()).filter(value => value.type === 'otp').length, 0, 'Never-enrolled scenario requires genuine absence of the old OTP');
  const unconfiguredUser = await currentUser(unconfigured);
  assert.ok(unconfiguredUser.requiredActions.includes('CONFIGURE_TOTP') && unconfiguredUser.requiredActions.includes('UPDATE_PASSWORD'));
  const firstEnrollment = await startRecovery(unconfigured.username);
  const firstSecret = await enrollment(firstEnrollment);
  const firstPassword = randomBytes(30).toString('base64url') + 'aA9!';
  await replace(firstEnrollment, unconfigured, firstSecret, firstPassword);
  const activatedUser = await currentUser(unconfigured);
  assert.ok(!activatedUser.requiredActions.includes('CONFIGURE_TOTP') && !activatedUser.requiredActions.includes('UPDATE_PASSWORD'));
  const firstSignIn = await browser.newContext(); await authenticate(unconfigured, firstSignIn, { password: firstPassword, secret: firstSecret });
  await firstSignIn.close(); await firstEnrollment.context.close();
  passed('missing-original-factor-recovers-and-completes-only-fulfilled-required-actions');
  phase = 'literal-completion-reload';
  const beforeReload = fixture('snapshot');
  assert.ok(beforeReload.native.oldestExecutedGrantSeconds < 0, 'Natural consumed authorization expiry must precede audit-only recovery');
  assert.ok(beforeReload.native.recordedExecutions < beforeReload.native.executions, 'Lost response must leave a real pending native recording');
  fixture('restart-native');
  await recovery.page.reload(); assert.equal(await nativeStage(recovery.page), 'COMPLETE');
  await submit(recovery.page);
  assert.equal(await nativeStage(recovery.page), 'COMPLETE');
  const afterReload = fixture('snapshot');
  assert.equal(afterReload.native.executions, beforeReload.native.executions);
  assert.equal(afterReload.native.recordedExecutions, beforeReload.native.recordedExecutions + 1);
  for (const field of ['cases', 'grants', 'verifiedGrantTotal', 'consumedAudits', 'executedAudits']) assert.deepEqual(afterReload.core[field], beforeReload.core[field]);
  await recovery.context.close(); await onlineContext.close(); await offlineContext.close();
  passed('committed-response-loss-restart-and-natural-receipt-expiry-reconcile-only-original-execution');
  phase = 'notification-database-aggregation-and-terminal-supervision';
  await waitNotificationMonitor(value => value.state === 'HEALTHY' && value.queue?.pending === 0 && value.queue.sending === 0);
  const messagesBeforeProbe = await (await request('http://127.0.0.1:8025/api/v1/messages')).json();
  const probe = fixture('notification-probes');
  assert.ok(probe.foreignRealmFailureRetained && probe.expiredFinalLeaseCreated && probe.invalidStatusRejected && probe.nullStatusRejected);
  const terminal = await waitNotificationMonitor(value => value.state === 'DEGRADED' && value.queue?.failed === 1 && value.queue.invalid === 0 && value.queue.due === 0, 30000);
  assert.equal(terminal.queue.sending, 0);
  const terminalMetrics = await notificationMetrics();
  const failedGauge = terminalMetrics.match(/^firefly_reproofing_notifications_queue\{[^}]*kind="failed"[^}]*\}\s+(\S+)/m);
  assert.ok(failedGauge && Number(failedGauge[1]) === 1, 'Private metric must report the actual retained terminal failure');
  const retained = fixture('notification-probe-status');
  assert.deepEqual(retained, { terminalStatus: 'FAILED', terminalAttempts: 8, leaseCleared: true, foreignFailureRetained: true });
  const messagesAfterProbe = await (await request('http://127.0.0.1:8025/api/v1/messages')).json();
  assert.equal(messagesAfterProbe.messages.length, messagesBeforeProbe.messages.length, 'Expired final lease cannot trigger a ninth send');
  passed('actual-database-realm-scoping-state-constraints-and-expired-eighth-lease-remain-supervised-without-send');
  await writeFile(`${output}/summary.json`, JSON.stringify({ scope: 'Actual native/Core/customer Domain with test-only proofing adapter; real provider, workforce recovery, receiver-wide JWT revocation and production acceptance excluded', gates, failed: [], fontMeasurements: fonts.length }, null, 2));
} catch (error) {
  await writeFile(`${output}/summary.json`, JSON.stringify({ scope: 'Incomplete actual native/customer proofing qualification', gates, failed: [{ phase, kind: error instanceof assert.AssertionError ? 'assertion' : 'runtime', diagnostics }] }, null, 2));
  reportFailure(error, phase);
  process.exitCode = 1;
} finally {
  await browser?.close();
  await new Promise(ok => callbackServer ? callbackServer.close(ok) : ok());
}
