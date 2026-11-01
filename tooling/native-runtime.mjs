import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
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
const failedGates = [];
const accountEvidence = {};
const sessionEvidence = {};
const factors = new Map();
const privateProofs = new Map();
const accountAssertions = new Map();
const transportFaults = process.env.FIREFLY_NATIVE_TRANSPORT_FAULTS === 'true';
const fontEvidence = [];
let phase = 'owned-native-runtime-ready';
let currentStage = 'initialization';
let lastPage;
let lastHttpStatus;
let lastNativeSubmission;
let activePopulation;
let accountAssetStatuses = {};
let accountErrorKinds = [];
let accountNavigations = [];
let lastAccountInventory;
let lastPinProtection;
const stage = value => { currentStage = value; };
let browser;
let server;
const passed = label => { phase = label; results.push(label); console.log(`PASS ${label}`); };
const failed = (gate, reason) => { failedGates.push({ gate, reason }); console.log(`FAIL ${gate}`); };
const delay = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));
const nativeTool = (action, population, input) => execFileSync('python3', ['tooling/native_integration_fixture.py', action,
  ...(population ? ['--population', population] : [])], { encoding: 'utf8', input: input ? JSON.stringify(input) : undefined,
  stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
const snapshot = population => JSON.parse(nativeTool('snapshot', population));
const faultStatus = population => JSON.parse(nativeTool('fault_status', population));
const pinDiagnostics = () => {
  try { return JSON.parse(nativeTool('pin_diagnostics')); }
  catch { return { unavailable: true }; }
};
async function request(url, options = {}) {
  const headers = new Headers(options.headers); headers.set('Connection', 'close');
  return fetch(url, { ...options, headers, signal: AbortSignal.timeout(20000) });
}
async function adminToken() {
  const response = await request(`${origin}/realms/master/protocol/openid-connect/token`, { method: 'POST',
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'native-bootstrap', password: credentials.admin }) });
  assert.equal(response.status, 200, 'Owned bootstrap administrator unavailable');
  return (await response.json()).access_token;
}
async function admin(profile, suffix, options = {}) {
  return request(`${origin}/admin/realms/${profile.realm}${suffix ? '/' + suffix : ''}`, { ...options,
    headers: { Authorization: `Bearer ${await adminToken()}`, ...(options.headers || {}) } });
}
async function user(profile, manual = false) {
  const response = await admin(profile, `users/${manual ? profile.manual.id : profile.person.id}`);
  assert.equal(response.status, 200, 'Owned user state unavailable'); return response.json();
}
async function cookieMetadata(context, profile) {
  const cookies = await context.cookies([`${profile.issuer}/account/`, `${profile.issuer}/firefly-recovery/support-pin`]);
  const names = ['KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION', 'KEYCLOAK_IDENTITY_LEGACY', 'KEYCLOAK_SESSION_LEGACY',
    'AUTH_SESSION_ID', 'KC_RESTART', 'FF_NATIVE_RECOVERY', 'FF_NATIVE_PIN'];
  return Object.fromEntries(names.map(name => {
    const cookie = cookies.find(value => value.name === name);
    return [name, cookie ? { present: true, secure: cookie.secure, httpOnly: cookie.httpOnly,
      sameSite: ['Strict', 'Lax', 'None'].includes(cookie.sameSite) ? cookie.sameSite : 'other',
      expiry: cookie.expires === -1 ? 'session' : cookie.expires > Date.now() / 1000 ? 'future' : 'expired',
      realmPath: cookie.path.startsWith(`/realms/${profile.realm}`) } : { present: false }];
  }));
}
async function sessionAuthority(profile) {
  const evidence = {};
  try {
    evidence.enabled = (await user(profile)).enabled === true;
    const sessions = await admin(profile, `users/${profile.person.id}/sessions`);
    if (sessions.status === 200) evidence.onlineSessionCount = (await sessions.json()).length;
    for (const [clientId, key] of [['account', 'accountRoles'], ['realm-management', 'realmManagementRoles']]) {
      const clients = await admin(profile, `clients?clientId=${clientId}`);
      if (clients.status !== 200) continue;
      const entries = await clients.json(); if (entries.length !== 1) continue;
      const roles = await admin(profile, `users/${profile.person.id}/role-mappings/clients/${entries[0].id}/composite`);
      if (roles.status !== 200) continue;
      const assigned = await roles.json();
      evidence[key] = key === 'accountRoles' ? { manageAccount: assigned.some(role => role.name === 'manage-account'),
        viewProfile: assigned.some(role => role.name === 'view-profile') } : { present: assigned.length > 0 };
    }
  } catch { evidence.incomplete = true; }
  return evidence;
}
function navigationClass(value, profile) {
  const url = new URL(value);
  if (url.origin === new URL(callback).origin && url.pathname === '/oidc/callback') return 'owned-callback';
  if (url.origin !== origin) return 'other-origin';
  if (url.pathname === `/realms/${profile.realm}/account` || url.pathname.startsWith(`/realms/${profile.realm}/account/`)) return 'account';
  if (url.pathname.includes('/protocol/openid-connect/auth')) return 'oidc-authorize';
  if (url.pathname.includes('/login-actions/')) return 'login-action';
  if (url.pathname.includes('/firefly-recovery/support-pin')) return 'native-pin';
  if (url.pathname.endsWith('/firefly-recovery/complete')) return 'native-completion';
  if (url.pathname.endsWith('/firefly-recovery')) return 'native-recovery';
  return 'other';
}
async function nextCode(profile) {
  const factor = factors.get(profile.kind); assert.ok(factor, 'Previously enrolled native TOTP required');
  let counter = Math.floor(Date.now() / 30000);
  if (counter <= factor.lastCounter) { await delay((factor.lastCounter + 1) * 30000 - Date.now() + 300); counter = Math.floor(Date.now() / 30000); }
  factor.lastCounter = counter; return totpCode(factor.secret, counter * 30);
}
async function submitNativeForm(page, profile, selector, path = '', redirectPath = path) {
  const source = `${profile.issuer}/firefly-recovery${path}`;
  const target = `${profile.issuer}/firefly-recovery${redirectPath}`;
  const submitted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === source);
  const document = page.waitForResponse(response => response.request().isNavigationRequest()
    && response.request().method() === 'GET' && response.url() === target)
    .then(response => ({ response }), error => ({ error }));
  await page.locator(selector).click();
  const post = await submitted; const headers = await post.request().allHeaders();
  const form = new URLSearchParams(post.request().postData() || '');
  const expectedCookieName = path.startsWith('/support-pin') ? 'FF_NATIVE_PIN' : 'FF_NATIVE_RECOVERY';
  lastNativeSubmission = { status: post.status(),
    originClass: headers.origin === origin ? 'same' : headers.origin === 'null' ? 'null' : headers.origin ? 'other' : 'absent',
    nativeCookiePresent: (headers.cookie || '').split(';').some(cookie => cookie.trim().startsWith(`${expectedCookieName}=`)),
    csrfPresent: Boolean(form.get('csrf')) };
  lastHttpStatus = post.status();
  assert.equal(headers.origin, origin, 'Actual native browser form must send the exact trusted Origin');
  assert.equal(post.status(), 303, 'Valid native form processing must redirect after POST');
  assert.equal(new URL(await post.headerValue('location'), post.url()).href, target, 'Native POST must redirect only to its exact canonical owner GET');
  const final = await document; if (final.error) throw final.error;
  assert.equal(final.response.status(), 200); assert.equal(final.response.request().method(), 'GET');
  assert.equal(final.response.request().redirectedFrom()?.method(), 'POST');
  assert.equal(final.response.request().redirectedFrom()?.url(), source);
  assert.equal(page.url(), target, 'The current document must be the canonical GET, without credential POST history');
  lastNativeSubmission.documentStatus = final.response.status(); lastNativeSubmission.documentMethod = 'GET';
  lastHttpStatus = final.response.status();
  return post;
}
async function resumeNativePage(page, profile, path = '') {
  const response = await page.goto(`${profile.issuer}/firefly-recovery${path}`);
  lastHttpStatus = response.status();
  assert.equal(response.request().method(), 'GET', 'Native resume must use the cookie GET endpoint');
  assert.equal(response.status(), 200, 'Native cookie GET must resume the preserved ceremony');
}
async function authenticate(profile, context, wrong = false, enroll = false, offlineRequested = false) {
  const state = randomBytes(20).toString('base64url'), verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const url = new URL(`${profile.issuer}/protocol/openid-connect/auth`);
  url.search = new URLSearchParams({ client_id: 'native-browser', redirect_uri: callback, response_type: 'code',
    scope: offlineRequested ? 'openid profile email offline_access' : 'openid profile email', code_challenge: challenge, code_challenge_method: 'S256', state,
    nonce: randomBytes(16).toString('hex'), prompt: 'login' }).toString();
  stage(`${profile.kind}-ordinary-new-page`);
  const page = await context.newPage(); lastPage = page; page.setDefaultTimeout(20000);
  let fulfill;
  const returned = new Promise(ok => { fulfill = ok; pending.set(state, ok); });
  stage(`${profile.kind}-ordinary-oidc-navigation`);
  lastHttpStatus = (await page.goto(url.href))?.status();
  stage(`${profile.kind}-ordinary-recovery-entry-count`);
  const recoveryEntry = page.locator('a.ffid-recovery-entry');
  assert.equal(await recoveryEntry.count(), 1, 'Opted-in native login must expose one recovery entry');
  assert.equal(await recoveryEntry.evaluate(anchor => anchor.href), `${profile.issuer}/firefly-recovery`, 'Recovery entry must resolve to the exact trusted native owner');
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
  sessionEvidence[profile.kind] = { loginPhase: offlineRequested ? 'offline-retirement-probe' : enroll ? 'initial-enrollment' : 'fresh-after-unlock',
    beforeAuthenticationPageClose: await cookieMetadata(context, profile) };
  await page.close(); return token.json();
}
async function recovery(profile, context, username, password) {
  stage(`${profile.kind}-native-new-page`);
  const page = await context.newPage(); lastPage = page; page.setDefaultTimeout(25000);
  stage(`${profile.kind}-native-password-navigation`);
  lastHttpStatus = (await page.goto(`${profile.issuer}/firefly-recovery?kc_locale=es`))?.status();
  assert.equal(await page.locator('#password').getAttribute('type'), 'password');
  const known = [profile.person.username, profile.person.email].includes(username);
  if (known) await captureEmptyNativeForm(page, `${profile.kind}-recovery-password-es`);
  stage(`${profile.kind}-native-password-submit`);
  await page.locator('#username').fill(username); await page.locator('#password').fill(password);
  await submitNativeForm(page, profile, '#ffid-recovery-continue');
  try { lastNativeSubmission.ceremony = JSON.parse(nativeTool('ceremony_state', profile.kind)); }
  catch { lastNativeSubmission.ceremony = { stage: 'unavailable' }; }
  await page.locator('#otp').waitFor();
  await assertNativeFont(page, `${profile.kind}-masked-native-factor-form`);
  if (known) {
    await captureEmptyNativeForm(page, `${profile.kind}-recovery-totp-es`);
    const reserved = snapshot(profile.kind);
    stage(`${profile.kind}-native-literal-browser-reload-after-prg`);
    const reloaded = await page.reload(); lastHttpStatus = reloaded.status();
    assert.equal(reloaded.request().method(), 'GET'); assert.equal(reloaded.status(), 200);
    await page.locator('#otp').waitFor();
    assert.equal(await page.locator('#username').count(), 0, 'Literal browser reload must preserve the completed password stage');
    assert.ok((await page.locator('html').getAttribute('lang')).startsWith('es'), 'Native recovery must preserve Spanish locale');
    assert.deepEqual(snapshot(profile.kind), reserved, 'Literal browser reload must not change native/Core evidence or budgets');
    passed(`${profile.kind}-prg-literal-spanish-browser-reload-preserves-native-progress-and-core-budget`);
  }
  return page;
}
async function expectCsrfRefusal(profile) {
  const context = await browser.newContext(); const page = await context.newPage();
  await page.goto(`${profile.issuer}/firefly-recovery?kc_locale=en`);
  await assertTranslation(page, 'en', 'ffidRecoveryTitle');
  await captureEmptyNativeForm(page, `${profile.kind}-recovery-password-en`);
  const before = snapshot(profile.kind);
  const csrf = await page.locator('input[name="csrf"]').inputValue();
  const response = await context.request.post(`${profile.issuer}/firefly-recovery`, { headers: { Origin: origin },
    form: { username: profile.person.username, password: profile.person.password, csrf: 'synthetic-forged-csrf' } });
  assert.equal(response.status(), 400);
  for (const supplied of ['null', 'https://foreign-origin.example.invalid']) {
    stage(`${profile.kind}-valid-csrf-disallowed-origin-refusal`);
    const refused = await context.request.post(`${profile.issuer}/firefly-recovery`, { headers: { Origin: supplied },
      form: { username: profile.person.username, password: profile.person.password, csrf } });
    assert.equal(refused.status(), 400, 'Valid cookie and real CSRF must not admit a null or foreign Origin');
    const ceremony = JSON.parse(nativeTool('ceremony_state', profile.kind));
    assert.equal(ceremony.stage, 'PASSWORD');
    for (const key of ['hasSubject', 'hasBinding', 'hasOperation']) assert.equal(ceremony[key], false);
    for (const key of ['bootstrapRejected', 'bootstrapReserved', 'bootstrapAdmitted']) assert.equal(ceremony[key], 0);
    assert.deepEqual(snapshot(profile.kind), before, 'Origin rejection must not spend or reset native/Core budgets');
  }
  await context.close(); passed(`${profile.kind}-native-csrf-refused`);
  passed(`${profile.kind}-real-csrf-null-and-foreign-origin-refused-before-bootstrap`);
}
async function sourceMessage(language, key) {
  const messages = await readFile(resolve(`themes/firefly-id/login/messages/messages_${language}.properties`), 'utf8');
  const entry = messages.split(/\r?\n/).find(line => line.startsWith(`${key}=`)); assert.ok(entry);
  return entry.slice(key.length + 1);
}
async function accountInventory(page) {
  const inventory = await page.evaluate(() => {
    const footer = document.getElementById('ffid-copyright');
    const link = document.getElementById('ffid-support-pin-link');
    return { bodyPageId: document.body?.dataset.pageId === 'account' ? 'account' : 'other',
      bodyPageClass: ['account', 'login-login', 'login-error', 'login-login-totp', 'login-login-config-totp'].includes(document.body?.dataset.pageId)
        ? document.body.dataset.pageId : 'other',
      hasLoginForm: Boolean(document.querySelector('#kc-form-login')), hasUsernameInput: Boolean(document.querySelector('#username')),
      hasPasswordInput: Boolean(document.querySelector('#password')), hasErrorContainer: Boolean(document.querySelector('#kc-error-message')),
      hasAccountApp: Boolean(document.querySelector('#app')), hasAccountPage: Boolean(document.querySelector('.pf-v5-c-page')),
      footerCount: document.querySelectorAll('#ffid-copyright').length,
      linkCount: document.querySelectorAll('#ffid-support-pin-link').length,
      linkVisible: Boolean(link?.getClientRects().length),
      attributionRawMatches: footer?.querySelector('a')?.getAttribute('href') === 'https://www.keycloak.org',
      attributionResolvedMatches: footer?.querySelector('a')?.href === 'https://www.keycloak.org/',
      mainCount: document.querySelectorAll('main').length,
      loadingCount: document.querySelectorAll('.keycloak__loading-container').length,
      scripts: Object.fromEntries(['copyright.js', 'presentation-policy.js', 'native-account-links.js'].map(name =>
        [name, [...document.scripts].some(script => new URL(script.src || location.href).pathname.endsWith('/' + name))])) };
  });
  return { ...inventory, assetStatuses: accountAssetStatuses, errorKinds: accountErrorKinds,
    navigation: accountNavigations.slice(-12) };
}
async function assertTranslation(page, language, key) {
  assert.ok((await page.locator('html').getAttribute('lang')).startsWith(language));
  assert.equal((await page.locator('#kc-page-title').innerText()).trim(), await sourceMessage(language, key));
}
async function selectNativeLocale(page, language, key) {
  const current = new URL(page.url());
  const selector = page.locator('#login-select-toggle');
  const options = await selector.locator('option').evaluateAll((entries, selected) => entries
    .filter(option => new URL(option.value, location.href).searchParams.get('kc_locale') === selected).map(option => option.value), language);
  assert.equal(options.length, 1, 'Actual native footer must expose one supported locale selection');
  const target = new URL(options[0], current);
  assert.equal(target.origin, origin); assert.equal(target.pathname, current.pathname);
  const [navigated] = await Promise.all([page.waitForNavigation({ waitUntil: 'load' }), selector.selectOption(options[0])]);
  assert.equal(navigated.request().method(), 'GET'); assert.equal(navigated.status(), 200);
  await assertTranslation(page, language, key);
}
async function privateReferenceRefusals(profile) {
  stage(`${profile.kind}-locked-private-proof-positive-control`);
  const before = snapshot(profile.kind);
  assert.equal(before.native.locked, true); assert.equal(before.native.executions, 0);
  assert.equal(before.native.attestations, 1); assert.equal(before.core[0].attempts, 1);
  const proof = JSON.parse(nativeTool('private_proof', profile.kind));
  const secret = (await readFile(profile.core_secret_file, 'utf8')).trim();
  const call = body => request(`${profile.issuer}/firefly-recovery/rpc/verify`, {
    method: 'POST', headers: { Authorization: `Basic ${Buffer.from(`native-core-owner:${secret}`).toString('base64')}`,
      'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  const positive = async () => {
    const response = await call(proof); assert.equal(response.status, 200);
    const accepted = await response.json();
    for (const key of ['operationId', 'challengeId', 'reservationId', 'providerChallengeId', 'category']) assert.equal(accepted[key], proof[key]);
    assert.deepEqual(accepted.binding, proof.binding); assert.equal(accepted.attestationId, proof.attestation);
    assert.equal(accepted.providerId, 'firefly-keycloak-native-v1'); assert.equal(accepted.accepted, true);
    assert.ok(new Date(accepted.expiresAt).getTime() > Date.now());
  };
  await positive();
  const other = credentials.profiles.find(value => value.kind !== profile.kind);
  const bindings = { issuer: other.issuer, tenant: 'synthetic-other-tenant', clientId: 'native-domain-owner',
    delegatingClientId: 'native-browser', actorSubject: profile.manual.id, targetIssuer: other.issuer,
    targetRealm: other.realm, targetSubject: profile.manual.id, population: other.population,
    purpose: 'PASSWORD_RESET', lockGeneration: randomUUID() };
  const foreign = [...privateProofs.values()][0];
  const references = { operationId: foreign?.operationId ?? randomUUID(), challengeId: foreign?.challengeId ?? randomUUID(),
    reservationId: foreign?.reservationId ?? randomUUID(), providerChallengeId: foreign?.providerChallengeId ?? randomBytes(32).toString('base64url'),
    category: 'POSSESSION', attestation: foreign?.attestation ?? randomBytes(32).toString('base64url') };
  for (const [key, value] of Object.entries(bindings)) {
    stage(`${profile.kind}-locked-private-proof-refused-binding-${key}`);
    assert.equal((await call({ ...proof, binding: { ...proof.binding, [key]: value } })).status, 403);
  }
  for (const [key, value] of Object.entries(references)) {
    stage(`${profile.kind}-locked-private-proof-refused-reference-${key}`);
    assert.equal((await call({ ...proof, [key]: value })).status, 403);
  }
  await positive();
  assert.deepEqual(snapshot(profile.kind), before, 'Private proof checks must not create proof, execution, consume or spend/reset any budget');
  privateProofs.set(profile.kind, proof);
  passed(`${profile.kind}-live-locked-private-proof-positive-controls-and-binding-reference-swaps-refused`);
}
async function expiredServerCeremony(profile) {
  stage(`${profile.kind}-isolated-server-ceremony-expiry-profile`);
  const original = await admin(profile, ''); assert.equal(original.status, 200);
  const attributes = (await original.json()).attributes;
  assert.ok(attributes['firefly.native-recovery.ttl-seconds']);
  const before = snapshot(profile.kind);
  const context = await browser.newContext();
  const serverCookie = async response => {
    const cookies = (await response.headersArray()).filter(header => header.name.toLowerCase() === 'set-cookie')
      .flatMap(header => { const match = header.value.match(/^FF_NATIVE_RECOVERY=([^;,\s]+)/); return match ? [match[1]] : []; });
    assert.equal(cookies.length, 1, 'Actual native response must set exactly one owned recovery cookie');
    return { name: 'FF_NATIVE_RECOVERY', value: cookies[0] };
  };
  try {
    const changed = await admin(profile, '', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attributes: { ...attributes, 'firefly.native-recovery.ttl-seconds': '1' } }) });
    assert.equal(changed.status, 204);
    const page = await context.newPage(); lastPage = page;
    const navigation = await page.goto(`${profile.issuer}/firefly-recovery`); assert.equal(navigation.status(), 200);
    const cookie = await serverCookie(navigation);
    const csrf = await page.locator('input[name="csrf"]').inputValue();
    stage(`${profile.kind}-isolated-server-ceremony-natural-expiry`);
    await delay(1600);
    const headers = { Origin: origin, Cookie: `${cookie.name}=${cookie.value}` };
    const refused = await context.request.post(`${profile.issuer}/firefly-recovery`, { headers,
      form: { csrf, username: 'synthetic-expired-ceremony', password: 'synthetic-unavailable-secret' } });
    assert.equal(refused.status(), 400, 'Server must reject the actual expired ceremony even when its original cookie is forced');
    const resumed = await context.request.get(`${profile.issuer}/firefly-recovery`, { headers }); assert.equal(resumed.status(), 200);
    const replacement = await serverCookie(resumed);
    assert.notEqual(replacement.value, cookie.value, 'Expired cookie GET must create a new PASSWORD ceremony');
    const passwordStage = await page.evaluate(html => {
      const document = new DOMParser().parseFromString(html, 'text/html');
      return Boolean(document.querySelector('#username') && document.querySelector('#password') && !document.querySelector('#otp'));
    }, await resumed.text());
    assert.equal(passwordStage, true); assert.deepEqual(snapshot(profile.kind), before);
  } finally {
    const restored = await admin(profile, '', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ attributes }) });
    assert.equal(restored.status, 204); await context.close();
  }
  passed(`${profile.kind}-natural-server-ceremony-expiry-rejects-forced-old-cookie-and-restarts-password`);
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
      const returns = await page.locator('a.ffid-journey-return').evaluateAll(links => links.filter(link => link.getClientRects().length)
        .map(link => { const box = link.getBoundingClientRect(); return { left: box.left, right: box.right, top: box.top, bottom: box.bottom, height: box.height }; }));
      assert.ok(returns.every(box => box.height >= 43.5), 'Native return links must retain 44px touch targets');
      for (let index = 1; index < returns.length; index++) {
        assert.ok(returns[index].top >= returns[index - 1].bottom + 3.5, 'Adjacent native return links must stack with 4px separation');
      }
      await page.screenshot({ path: `${output}/${name}-${width}-${mode}.png`, fullPage: true });
    }
  }
}

async function captureEmptyNativeForm(page, name) {
  const empty = async () => {
    assert.equal(await page.locator('#kc-totp-secret-key, #totpSecret').count(), 0, 'Enrollment secrets must never enter form captures');
    assert.equal(await page.locator('.ffid-native-journey form').count(), 1, 'Actual native form must be present');
    assert.equal(await page.locator('.ffid-native-journey input:not([type="hidden"]):not([type="submit"]):not([type="button"])')
      .evaluateAll(inputs => inputs.length > 0 && inputs.every(input => input.value === '')), true, 'Every visible credential and username field must be empty before capture');
  };
  await empty(); await assertNativeFont(page, `${name}-empty-form`);
  for (const [width, height] of [[1440, 1000], [390, 844]]) {
    await page.setViewportSize({ width, height });
    for (const mode of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: mode });
      await page.waitForFunction(dark => document.documentElement.classList.contains('pf-v5-theme-dark') === dark, mode === 'dark');
      await empty();
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Actual empty native form has horizontal clipping');
      await page.screenshot({ path: `${output}/${name}-empty-form-${width}-${mode}.png`, fullPage: true });
    }
  }
}

async function reconcileLostRecord(profile, page, committed) {
  stage(`${profile.kind}-committed-record-response-loss-check`);
  assert.equal(faultStatus(profile.kind).recordLossSpent, true, 'Actual Domain record204 must precede the injected response loss');
  assert.equal(committed.native.recorded, false); assert.equal(committed.native.recordAttempts, 1);
  assert.equal(committed.core[0].successAudits, 1);
  assert.equal(committed.native.executionId, committed.core[0].executionId);
  nativeTool('restart');
  stage(`${profile.kind}-committed-record-restart-resume`);
  await resumeNativePage(page, profile, '/complete'); await page.locator('#ffid-recovery-audit-retry').waitFor();
  assert.equal(await page.locator('input[type="password"], #otp, #username').count(), 0, 'Audit-only resume must not ask for factors');
  const fields = await page.locator('#ffid-recovery-audit-retry input').evaluateAll(inputs => inputs.map(input => input.name));
  assert.deepEqual(fields, ['csrf'], 'Audit reconciliation must send only fresh CSRF');
  const retained = snapshot(profile.kind);
  assert.equal(retained.native.executionId, committed.native.executionId);
  assert.equal(retained.core[0].attempts, committed.core[0].attempts);
  stage(`${profile.kind}-committed-record-csrf-only-reconciliation`);
  await submitNativeForm(page, profile, '#ffid-recovery-audit-retry button[type="submit"]', '', '/complete');
  await page.locator('#ffid-recovery-audit-retry').waitFor({ state: 'detached' });
  const reconciled = snapshot(profile.kind);
  assert.equal(reconciled.native.recorded, true); assert.equal(reconciled.native.recordAttempts, 2);
  assert.equal(reconciled.native.executions, 1); assert.equal(reconciled.native.executionId, committed.native.executionId);
  assert.equal(reconciled.native.unlockAudits, 1); assert.equal(reconciled.native.recordAudits, 1);
  for (const key of ['bootstrap', 'knowledge', 'possession', 'maximumChecksPerReservation']) assert.equal(reconciled.native[key], committed.native[key]);
  assert.deepEqual(reconciled.core, committed.core, 'Reconciliation must preserve the same consumed receipt, budgets, outcome and single success audit');
  passed(`${profile.kind}-actual-committed-record-response-loss-restart-csrf-only-reconciliation`);
}

async function concurrentExecution(profile, context, page, csrf) {
  nativeTool('arm_verify_race', profile.kind);
  const code = await nextCode(profile);
  const submit = token => context.request.post(`${profile.issuer}/firefly-recovery`, {
    headers: { Origin: origin }, form: { csrf: token, otp: code }, timeout: 20000, maxRedirects: 0,
  }).then(response => ({ response }), error => ({ error }));
  stage(`${profile.kind}-first-genuine-online-verification`);
  const first = submit(csrf);
  const deadline = Date.now() + 2200;
  while (faultStatus(profile.kind).verifyRaceArrivals === 0 && Date.now() < deadline) await delay(25);
  assert.equal(faultStatus(profile.kind).verifyRaceArrivals, 1, 'First request must reach accepted real online verification before racing');
  // Cookie GET is the actual interrupted-delivery resume path: it rotates CSRF and reuses committed proof.
  stage(`${profile.kind}-concurrent-cookie-resume-fresh-csrf`);
  await resumeNativePage(page, profile); await page.locator('#otp').waitFor();
  const freshCsrf = await page.locator('input[name="csrf"]').inputValue();
  assert.notEqual(freshCsrf, csrf);
  stage(`${profile.kind}-second-genuine-online-verification`);
  const both = await Promise.all([first, submit(freshCsrf)]);
  for (const result of both) {
    if (result.error) throw result.error; assert.equal(result.response.status(), 303);
    const target = new URL(result.response.headers().location, result.response.url()).href;
    assert.equal(target, `${profile.issuer}/firefly-recovery/complete`, 'Each concurrent request must take the genuine committed completion redirect');
    const document = await context.request.get(target); assert.equal(document.status(), 200);
    const complete = await page.evaluate(({ html, title }) => {
      const document = new DOMParser().parseFromString(html, 'text/html');
      return document.querySelector('#kc-page-title')?.textContent.trim() === title
        && !document.querySelector('#ffid-native-recovery, .ffid-native-journey [role="alert"]');
    }, { html: await document.text(), title: await sourceMessage('es', 'ffidRecoveryCompleteTitle') });
    assert.equal(complete, true, 'Each genuine concurrent response must report COMPLETE without a recovery failure alert');
  }
  const barrier = faultStatus(profile.kind);
  assert.equal(barrier.verifyRaceArrivals, 2); assert.equal(barrier.verifyRaceSpent, true);
  await resumeNativePage(page, profile, '/complete');
  assert.equal(await page.locator('#otp, #password').count(), 0, 'Both actual native requests must settle on the same completed journal');
  const settled = snapshot(profile.kind);
  assert.equal(settled.native.executions, 1); assert.equal(settled.native.executionId, settled.core[0].executionId);
  assert.equal(settled.native.unlockAudits, 1); assert.equal(settled.native.recordAudits, 1);
  assert.equal(settled.native.maximumChecksPerReservation, 1); assert.equal(settled.native.knowledge, 1); assert.equal(settled.native.possession, 2);
  assert.equal(settled.core.length, 1); assert.equal(settled.core[0].attempts, 3); assert.equal(settled.core[0].challenges, 2);
  assert.equal(settled.core[0].state, 'CONSUMED'); assert.equal(settled.core[0].outcome, 'SUCCEEDED'); assert.equal(settled.core[0].successAudits, 1);
  passed(`${profile.kind}-two-real-online-verifications-one-native-execution-and-core-success-audit`);
}

async function protectedPinAccountDeletionRefusal(profile) {
  stage('customers-native-pin-account-credentials-positive-control');
  const assertion = accountAssertions.get(profile.kind);
  if (!assertion) {
    failed('customers-real-account-credentials-positive-control', 'actual-react-accepted-account-bearer-unavailable');
    return;
  }
  const pin = JSON.parse(nativeTool('private_pin', profile.kind));
  assert.equal(pin.active, true); assert.equal(pin.stored, 1); assert.ok(pin.credentialId);
  const endpoint = `${profile.issuer}/account/credentials`;
  const listed = await request(endpoint, { headers: { Authorization: assertion, Accept: 'application/json' } });
  lastPinProtection = { accountCredentialsStatus: listed.status };
  assert.equal(listed.status, 200, 'Actual Account bearer must be accepted by the credentials owner');
  assert.equal(JSON.stringify(await listed.json()).includes(pin.credentialId), false, 'Generic Account credential inventory must omit the native support PIN');
  const refused = await request(`${endpoint}/${encodeURIComponent(pin.credentialId)}`, { method: 'DELETE',
    headers: { Authorization: assertion, Accept: 'application/json' } });
  lastPinProtection.accountDeleteStatus = refused.status;
  assert.equal(refused.status, 404, 'Generic Account delete must not address a native support PIN');
  assert.deepEqual(JSON.parse(nativeTool('private_pin', profile.kind)), pin, 'Account delete refusal must preserve the same active stored PIN');
  lastPinProtection.accountPinPreserved = true;
  passed('customers-native-pin-hidden-from-generic-account-and-protected-from-account-deletion');
}

async function administrativePinRevocation(profile, page) {
  stage('customers-native-pin-administrative-revocation');
  const master = { realm: 'master' };
  const realm = await admin(master, ''); assert.equal(realm.status, 200); const actorRealm = (await realm.json()).id; assert.ok(actorRealm);
  const clients = await admin(master, 'clients?clientId=admin-cli'); assert.equal(clients.status, 200);
  const actorClients = await clients.json(); assert.equal(actorClients.length, 1);
  const users = await admin(master, 'users?username=native-bootstrap&exact=true'); assert.equal(users.status, 200);
  const actorUsers = await users.json(); assert.equal(actorUsers.length, 1);
  const pin = JSON.parse(nativeTool('private_pin', profile.kind)); assert.equal(pin.active, true); assert.equal(pin.stored, 1);
  assert.equal(JSON.parse(nativeTool('private_credential_exists', profile.kind, { credentialId: pin.credentialId })).stored, 1);
  const before = snapshot(profile.kind);
  const revoked = await admin(profile, `users/${profile.person.id}/credentials/${encodeURIComponent(pin.credentialId)}`, { method: 'DELETE' });
  lastPinProtection = { ...lastPinProtection, adminDeleteStatus: revoked.status }; assert.equal(revoked.status, 204);
  const retired = JSON.parse(nativeTool('private_pin', profile.kind));
  assert.equal(JSON.parse(nativeTool('private_credential_exists', profile.kind, { credentialId: pin.credentialId })).stored, 0);
  assert.equal(retired.credentialId, null); assert.equal(retired.stored, 0); assert.equal(retired.active, false);
  assert.equal(retired.revoked, true); assert.equal(retired.held, true); assert.notEqual(retired.generation, pin.generation);
  assert.equal(retired.failures, pin.failures); assert.equal(retired.reserved, pin.reserved); assert.equal(retired.adminAuditCount, 1);
  const audit = retired.adminAudit; assert.ok(audit);
  lastPinProtection.actorRealmMatches = audit.actorRealmId === actorRealm;
  lastPinProtection.actorSubjectMatches = audit.actorSubject === actorUsers[0].id;
  lastPinProtection.actorClientMatches = audit.actorClientId === actorClients[0].id;
  lastPinProtection.eventActorMatches = audit.eventActorMatches === true;
  lastPinProtection.eventRealmMatches = audit.eventRealmMatches === true;
  lastPinProtection.eventActionMatches = audit.eventActionMatches === true;
  lastPinProtection.auditGenerationMatches = audit.generationMatches === true;
  lastPinProtection.eventPathMatches = audit.resourcePath === `users/${profile.person.id}/credentials/${pin.credentialId}`;
  for (const key of ['actorRealmMatches', 'actorSubjectMatches', 'actorClientMatches', 'eventActorMatches', 'eventRealmMatches',
    'eventActionMatches', 'auditGenerationMatches', 'eventPathMatches']) assert.equal(lastPinProtection[key], true, 'Administrative PIN audit must bind the actual current administrator and Keycloak event');
  assert.match(audit.eventId, /^[0-9a-f-]{36}$/);
  const after = snapshot(profile.kind); assert.equal(after.native.pinActive, false);
  assert.deepEqual({ ...after, native: { ...after.native, pinActive: true } }, before, 'PIN-only administrative revocation must preserve login, recovery, journal and all existing budgets');
  lastPinProtection.pinRetired = true; lastPinProtection.recoveryBudgetsPreserved = true;
  await page.goto(`${profile.issuer}/firefly-recovery/support-pin?kc_locale=en`); await assertTranslation(page, 'en', 'ffidPinTitle');
  assert.equal(await page.locator('input[type="password"]').count(), 0);
  await captureSafeJourney(page, 'customers-pin-administratively-revoked');
  passed('customers-privileged-pin-revocation-is-atomic-actor-audited-and-preserves-recovery-budgets');
}

async function supportPin(profile, context) {
  let created = false;
  let extraPin;
  do { extraPin = [...randomBytes(8)].map(value => String(value % 10)).join(''); }
  while (/^(\d)\1{7}$/.test(extraPin) || extraPin.slice(0, 4) === extraPin.slice(4)
    || extraPin.slice(0, 2).repeat(4) === extraPin || '01234567890123456789'.includes(extraPin) || '98765432109876543210'.includes(extraPin));
  for (const [suffix, pin, expected, administrativelyRevoke] of [['set', '70934628', true], ['set', '84173059', true], ['revoke', null, false], ['set', extraPin, true, true]]) {
    stage(`customers-pin-${suffix}-navigation`);
    const page = await context.newPage(); lastPage = page;
    lastHttpStatus = (await page.goto(`${profile.issuer}/firefly-recovery/support-pin/${suffix}?kc_locale=en`)).status();
    await assertTranslation(page, 'en', suffix === 'revoke' ? 'ffidPinRevokeTitle' : 'ffidPinTitle');
    await captureEmptyNativeForm(page, `customers-pin-${suffix}-en-${results.length}`);
    await page.locator('#password').fill(profile.person.password); await page.locator('#otp').fill(await nextCode(profile));
    if (pin) { await page.locator('#pin').fill(pin); await page.locator('#pinConfirm').fill(pin); }
    stage(`customers-pin-${suffix}-actual-stepup-submit`);
    await submitNativeForm(page, profile, '#ffid-pin-save', '/support-pin');
    await page.locator('#ffid-support-pin').waitFor({ state: 'detached' });
    assert.equal(snapshot(profile.kind).native.pinActive, expected, 'Actual native PIN lifecycle state differs');
    if (pin && !created) await protectedPinAccountDeletionRefusal(profile);
    const retained = snapshot(profile.kind);
    const reloaded = await page.reload(); assert.equal(reloaded.request().method(), 'GET'); assert.equal(reloaded.status(), 200);
    assert.equal(await page.locator('#ffid-support-pin, input[type="password"]').count(), 0);
    assert.deepEqual(snapshot(profile.kind), retained, 'PIN status reload must not repeat a credential operation');
    assert.equal(await page.locator('input[type="password"]').count(), 0, 'Credential field must not enter status capture');
    stage(`customers-pin-${suffix}-english-status-translation`);
    await assertTranslation(page, 'en', 'ffidPinTitle');
    await captureSafeJourney(page, `customers-pin-${suffix}-${results.length}`);
    const beforeLocale = snapshot(profile.kind);
    stage(`customers-pin-${suffix}-actual-footer-spanish-selection`);
    await selectNativeLocale(page, 'es', 'ffidPinTitle');
    stage(`customers-pin-${suffix}-spanish-literal-reload`);
    const spanishReload = await page.reload(); assert.equal(spanishReload.request().method(), 'GET'); assert.equal(spanishReload.status(), 200);
    await assertTranslation(page, 'es', 'ffidPinTitle');
    stage(`customers-pin-${suffix}-canonical-get-locale-cookie-persistence`);
    const canonical = await page.goto(`${profile.issuer}/firefly-recovery/support-pin`);
    assert.equal(canonical.request().method(), 'GET'); assert.equal(canonical.status(), 200);
    await assertTranslation(page, 'es', 'ffidPinTitle');
    assert.deepEqual(snapshot(profile.kind), beforeLocale, 'Actual footer locale selection and reload must preserve PIN state and Native/Core budgets');
    stage(`customers-pin-${suffix}-localized-last-changed-date`);
    await page.waitForFunction(() => {
        const time = document.querySelector('time[data-ffid-local-date]');
        return time && time.textContent === new Intl.DateTimeFormat(document.documentElement.lang,
          { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(time.dateTime));
      });
    if (pin) created = true;
    assert.equal(snapshot(profile.kind).native.pinActive, expected, 'Localized status GET must not change PIN lifecycle state');
    await captureSafeJourney(page, `customers-pin-${suffix}-es-${results.length}`);
    if (administrativelyRevoke) await administrativePinRevocation(profile, page);
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
    activePopulation = profile.kind;
    const previousSession = await browser.newContext();
    const tokens = await authenticate(profile, previousSession, false, true);
    assert.ok(tokens.refresh_token, 'Real online refresh session required for retirement check');
    assert.equal(tokens.scope?.split(' ').includes('offline_access'), false, 'Online SSO enrollment must not request first offline access');
    const initialOnline = await admin(profile, `users/${profile.person.id}/sessions`); assert.equal(initialOnline.status, 200);
    assert.ok((await initialOnline.json()).length > 0, 'A genuine online SSO session must exist before the independent offline probe');
    // Keycloak retires the current online session on first offline access; isolate that probe from the original SSO session.
    const offlineSession = await browser.newContext();
    const offlineTokens = await authenticate(profile, offlineSession, false, false, true);
    assert.ok(offlineTokens.refresh_token); assert.ok(offlineTokens.scope?.split(' ').includes('offline_access'));
    const browserClients = await (await admin(profile, 'clients?clientId=native-browser')).json(); assert.equal(browserClients.length, 1);
    const offlinePath = `users/${profile.person.id}/offline-sessions/${browserClients[0].id}`;
    const previousOffline = await admin(profile, offlinePath); assert.equal(previousOffline.status, 200);
    assert.ok((await previousOffline.json()).length > 0, 'Real offline session must exist before the native lock');
    const onlineAfterOffline = await admin(profile, `users/${profile.person.id}/sessions`); assert.equal(onlineAfterOffline.status, 200);
    assert.ok((await onlineAfterOffline.json()).length > 0, 'Independent offline access must leave the separate original online SSO session live');
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
    stage(`${profile.kind}-owned-native-restart`);
    nativeTool('restart');
    stage(`${profile.kind}-postrestart-persisted-generation-read`);
    assert.equal(snapshot(profile.kind).native.generation, before.native.generation, 'Restart lost lock generation');
    stage(`${profile.kind}-postrestart-current-administrator-state-read`);
    assert.equal((await user(profile)).enabled, false); passed(`${profile.kind}-native-restart-preserves-lock`);
    await expectCsrfRefusal(profile);
    const unknown = await browser.newContext({ locale: 'es-ES' }); const unknownPage = await recovery(profile, unknown, 'synthetic-unknown-person', profile.person.password);
    const unknownText = await unknownPage.locator('.ffid-native-journey').innerText(); await unknown.close();
    const manual = await browser.newContext({ locale: 'es-ES' }); const heldPage = await recovery(profile, manual, profile.manual.username, profile.person.password);
    assert.equal(await heldPage.locator('.ffid-native-journey').innerText(), unknownText, 'Manual hold reveals eligibility');
    await heldPage.locator('#otp').fill('000000'); await submitNativeForm(heldPage, profile, '#ffid-recovery-continue');
    assert.equal((await user(profile, true)).enabled, false); await manual.close();
    passed(`${profile.kind}-unknown-and-manual-hold-generic-unavailable`);
    if (transportFaults) await expiredServerCeremony(profile);
    const context = await browser.newContext({ locale: 'es-ES' }); const page = await recovery(profile, context, profile.population === 'HUMAN' ? profile.person.email : profile.person.username, profile.person.password);
    assert.equal(await page.locator('.ffid-native-journey').innerText(), unknownText, 'Known recovery reveals existence');
    before = snapshot(profile.kind); assert.equal(before.core.length, 1); assert.equal(before.core[0].attempts, 1);
    if (transportFaults) await privateReferenceRefusals(profile);
    const permitted = new Set([-30, 0, 30].map(offset => totpCode(factors.get(profile.kind).secret, Date.now() / 1000 + offset)));
    let invalid = 0; while (permitted.has(String(invalid).padStart(6, '0'))) invalid++;
    await page.locator('#otp').fill(String(invalid).padStart(6, '0')); await submitNativeForm(page, profile, '#ffid-recovery-continue');
    await page.locator('[role="alert"]').waitFor();
    let rejected = snapshot(profile.kind); assert.equal(rejected.core[0].attempts, 2); assert.equal(rejected.native.possession, 1);
    assert.equal(rejected.native.maximumChecksPerReservation, 1); assert.equal((await user(profile)).enabled, false);
    passed(`${profile.kind}-wrong-totp-persists-native-and-core-attempts`);
    const onlineBeforeUnlock = await admin(profile, `users/${profile.person.id}/sessions`); assert.equal(onlineBeforeUnlock.status, 200);
    const offlineBeforeUnlock = await admin(profile, offlinePath); assert.equal(offlineBeforeUnlock.status, 200);
    assert.ok((await onlineBeforeUnlock.json()).length > 0, 'Real old online session must still exist immediately before native execution');
    assert.ok((await offlineBeforeUnlock.json()).length > 0, 'Real old offline session must still exist immediately before native execution');
    passed(`${profile.kind}-separate-live-online-and-offline-sessions-proven-before-native-execution`);
    const csrf = await page.locator('input[name="csrf"]').inputValue();
    if (transportFaults && profile.population === 'HUMAN') nativeTool('arm_record_loss', profile.kind);
    stage(`${profile.kind}-native-accepted-possession-submit`);
    if (transportFaults && profile.population === 'STAFF') await concurrentExecution(profile, context, page, csrf);
    else { await page.locator('#otp').fill(await nextCode(profile)); await submitNativeForm(page, profile, '#ffid-recovery-continue', '', '/complete'); }
    await page.locator('#ffid-native-recovery').waitFor({ state: 'detached' });
    assert.equal((await user(profile)).enabled, true, 'Native password+TOTP recovery did not unlock');
    const after = snapshot(profile.kind); assert.equal(after.native.executions, 1); assert.equal(after.native.maximumChecksPerReservation, 1);
    assert.equal(after.core[0].attempts, 3); assert.equal(after.core[0].state, 'CONSUMED'); assert.equal(after.core[0].outcome, 'SUCCEEDED');
    if (transportFaults && profile.population === 'HUMAN') await reconcileLostRecord(profile, page, after);
    assert.equal(await page.locator('input[type="password"]').count(), 0);
    await assertTranslation(page, 'es', 'ffidRecoveryCompleteTitle');
    await captureSafeJourney(page, `${profile.kind}-complete`);
    passed(`${profile.kind}-real-native-two-factor-unlock-and-owning-execution-journal`);
    const replay = await context.request.post(`${profile.issuer}/firefly-recovery`, { headers: { Origin: origin }, form: { csrf, otp: '000000' } });
    assert.equal(replay.status(), 400); assert.equal(snapshot(profile.kind).native.executions, 1);
    passed(`${profile.kind}-browser-replay-does-not-create-another-execution`);
    const refresh = await request(`${profile.issuer}/protocol/openid-connect/token`, { method: 'POST',
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'native-browser', refresh_token: tokens.refresh_token }) });
    const offlineRefresh = await request(`${profile.issuer}/protocol/openid-connect/token`, { method: 'POST',
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'native-browser', refresh_token: offlineTokens.refresh_token }) });
    assert.equal(offlineRefresh.status, 400);
    assert.equal(refresh.status, 400); const sessions = await admin(profile, `users/${profile.person.id}/sessions`);
    assert.equal((await sessions.json()).length, 0);
    const retiredOffline = await admin(profile, offlinePath); assert.equal(retiredOffline.status, 200); assert.equal((await retiredOffline.json()).length, 0);
    passed(`${profile.kind}-old-refresh-online-and-real-offline-sessions-retired`);
    const fresh = await browser.newContext(); await authenticate(profile, fresh);
    sessionEvidence[profile.kind].afterAuthenticationPageClose = await cookieMetadata(fresh, profile);
    sessionEvidence[profile.kind].authorityBeforeAccount = await sessionAuthority(profile);
    assert.ok(sessionEvidence[profile.kind].authorityBeforeAccount.onlineSessionCount > 0, 'Fresh normal sign-in must retain a genuine online SSO session before Account or PIN access');
    passed(`${profile.kind}-fresh-password-and-pre-enrolled-mfa-required-after-unlock`);
    stage(`${profile.kind}-native-account-navigation`);
    const account = await fresh.newPage(); lastPage = account; accountAssetStatuses = {}; accountErrorKinds = []; accountNavigations = [];
    account.on('pageerror', error => {
      const kind = ['TypeError', 'ReferenceError', 'SyntaxError', 'Error'].includes(error.name) ? error.name : 'Error';
      if (accountErrorKinds.length < 5) accountErrorKinds.push(kind);
    });
    account.on('response', async response => {
      try {
        const url = new URL(response.url());
        if (response.request().isNavigationRequest() && response.request().frame() === account.mainFrame()) {
          accountNavigations.push({ method: response.request().method() === 'POST' ? 'POST' : 'GET',
            status: response.status(), pageClass: navigationClass(response.url(), profile) });
        }
        for (const name of ['copyright.js', 'presentation-policy.js', 'native-account-links.js', 'firefly-console.css']) {
          if (url.pathname.endsWith('/' + name)) accountAssetStatuses[name] = response.status();
        }
        const accountPath = `/realms/${profile.realm}/account`;
        if (response.status() === 200 && response.headers()['content-type']?.startsWith('application/json')
            && url.origin === origin && (url.pathname === accountPath || url.pathname.startsWith(accountPath + '/'))) {
          const headers = await response.request().allHeaders();
          if (headers.authorization?.startsWith('Bearer ')) accountAssertions.set(profile.kind, headers.authorization);
        }
      } catch { /* Only successful actual Account API responses can supply this private fixture assertion. */ }
    });
    lastHttpStatus = (await account.goto(`${profile.issuer}/account/`)).status();
    await account.locator('main').waitFor();
    stage(`${profile.kind}-authenticated-account-console-mount`);
    await account.locator('.pf-v5-c-page').waitFor({ state: 'visible' });
    const accountDeadline = Date.now() + 10000;
    while (!accountAssertions.has(profile.kind) && Date.now() < accountDeadline) await delay(25);
    assert.ok(accountAssertions.has(profile.kind), 'The actual mounted Account Console must receive an accepted JSON API bearer before interacting with its native link');
    lastAccountInventory = await accountInventory(account);
    sessionEvidence[profile.kind].afterAccountNavigation = await cookieMetadata(fresh, profile);
    accountEvidence[profile.kind] = lastAccountInventory;
    const pinLink = account.locator(`a[href="${profile.issuer}/firefly-recovery/support-pin"]`);
    if (profile.population === 'HUMAN') {
      stage('customers-native-account-pin-entry-wait');
      let entryAvailable = true;
      try { await pinLink.waitFor({ state: 'visible' }); }
      catch {
        entryAvailable = false;
        lastAccountInventory = await accountInventory(account); accountEvidence[profile.kind] = lastAccountInventory;
        sessionEvidence[profile.kind].afterAccountEntryWait = await cookieMetadata(fresh, profile);
        sessionEvidence[profile.kind].authorityAfterAccount = await sessionAuthority(profile);
        failed('customers-native-account-pin-entry', 'strict-native-account-pin-link-unavailable');
      }
      if (entryAvailable) await pinLink.click();
      else {
        stage('customers-independent-direct-native-pin-status');
        lastHttpStatus = (await account.goto(`${profile.issuer}/firefly-recovery/support-pin`)).status();
        assert.equal(lastHttpStatus, 200, 'Independent native PIN status still requires the genuine authenticated cookie');
      }
      assert.equal(await account.locator('.ffid-credential-status').count(), 1, 'Actual authenticated native PIN status must be rendered');
      await assertTranslation(account, (await account.locator('html').getAttribute('lang')).startsWith('es') ? 'es' : 'en', 'ffidPinTitle');
      assert.equal(await account.locator('input[type="password"]').count(), 0, 'PIN status entry must not request a secret');
      assert.equal(await account.locator('time[data-ffid-local-date]').count(), 0, 'Initially absent PIN must have no fabricated date');
      if (entryAvailable) passed('customers-native-account-exposes-support-pin-status');
      await supportPin(profile, fresh);
    } else {
      assert.equal(await pinLink.count(), 0, 'Workforce account must not offer the customer support PIN');
      const refusedPin = await fresh.request.get(`${profile.issuer}/firefly-recovery/support-pin`);
      assert.equal(refusedPin.status(), 403); passed('workforce-customer-pin-surface-refused');
    }
    await account.close();
    await fresh.close(); await context.close(); await previousSession.close(); await offlineSession.close();
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
  await writeFile(`${output}/summary.json`, JSON.stringify({ status: failedGates.length ? 'FAILED' : 'PASSED', passed: results,
    failures: failedGates, accountInventory: accountEvidence, sessionEvidence, pinProtection: lastPinProtection,
    ...(failedGates.length ? { pinGuards: pinDiagnostics() } : {}),
    pending: [...(transportFaults ? [] : ['true simultaneous native execution requests', 'post-commit network response-loss injection', 'natural server ceremony expiry and swapped private attestation references']),
      'admitted actor JWT and consumed authorization receipt expiry in native runtime',
      'support PIN BPO/case/delegation owner acceptance', 'production/regulatory approval'],
    scope: 'Owned synthetic HTTPS native Keycloak/Core PostgreSQL/actual generated-SDK Domain acceptance only.' }, null, 2));
  if (failedGates.length) process.exitCode = 1;
} catch (error) {
  reportFailure(error, phase);
  const allowedNames = new Set(['AssertionError', 'Error', 'TypeError', 'TimeoutError']);
  const allowedNetworkCodes = new Set(['ECONNRESET', 'ECONNREFUSED', 'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT',
    'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID']);
  const frames = String(error?.stack || '').split('\n').flatMap(line => {
    const match = line.match(/tooling\/native-runtime\.mjs:(\d+):(\d+)/);
    return match ? [`native-runtime.mjs:${match[1]}:${match[2]}`] : [];
  }).slice(0, 6);
  let inventory = {};
  let counters = {};
  if (activePopulation) {
    try {
      const state = snapshot(activePopulation);
      const numeric = (object, keys) => Object.fromEntries(keys.filter(key => Number.isSafeInteger(object[key]) && object[key] >= 0)
        .map(key => [key, object[key]]));
      counters = { native: numeric(state.native, ['bootstrap', 'knowledge', 'possession', 'attestations', 'executions',
        'recordAttempts', 'maximumChecksPerReservation', 'unlockAudits', 'recordAudits']), operationCount: state.core.length,
      core: state.core.slice(0, 4).map(operation => ({ ...numeric(operation, ['attempts', 'challenges', 'verifiedKnowledge',
        'verifiedPossession', 'pendingReservations', 'successAudits']),
        state: ['OPEN', 'CONSUMED', 'EXHAUSTED'].includes(operation.state) ? operation.state : 'other',
        outcome: ['PENDING', 'UNKNOWN', 'SUCCEEDED', 'FAILED'].includes(operation.outcome) ? operation.outcome : 'none' })) };
    } catch { counters = {}; }
  }
  if (lastPage && !lastPage.isClosed()) {
    try {
      if (new URL(lastPage.url()).pathname.includes('/account/')) {
        lastAccountInventory = await accountInventory(lastPage);
        if (activePopulation) accountEvidence[activePopulation] = lastAccountInventory;
      }
      for (const selector of ['#username', '#password', '#otp', '#totpSecret', '#kc-totp-secret-key', '.ffid-recovery-entry', '#ffid-native-recovery', '#ffid-support-pin']) {
        inventory[selector] = await lastPage.locator(selector).count();
      }
      const path = new URL(lastPage.url()).pathname;
      inventory.canonicalPath = path.endsWith('/protocol/openid-connect/auth') ? 'oidc-authorize'
        : path.includes('/login-actions/') ? 'native-login-action' : path.endsWith('/firefly-recovery') ? 'native-recovery'
        : path.includes('/support-pin') ? 'native-pin' : path.includes('/account/') ? 'account' : path.endsWith('/firefly-recovery/complete') ? 'native-completion'
        : path === '/oidc/callback' ? 'owned-callback' : 'other';
    } catch { inventory = {}; }
  }
  await writeFile(`${output}/summary.json`, JSON.stringify({ status: 'FAILED', passed: results, failures: failedGates, lastCompleted: phase,
    currentStage, errorKind: allowedNames.has(error?.name) ? error.name : 'Error', sourceFrames: frames,
    networkCauseCode: allowedNetworkCodes.has(error?.cause?.code) ? error.cause.code : 'unclassified',
    lastHttpStatus, lastNativeSubmission, inventory, lastAccountInventory, accountInventory: accountEvidence, sessionEvidence,
    pinGuards: pinDiagnostics(), lastPinProtection, counters,
    scope: 'Partial native integration; uncompleted stages are not qualified.' }, null, 2));
  process.exitCode = 1;
} finally {
  pending.clear(); privateProofs.clear(); accountAssertions.clear(); if (browser) await browser.close(); if (server) await new Promise(ok => server.close(ok));
}
