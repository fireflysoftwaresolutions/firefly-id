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
const factors = new Map();
const privateProofs = new Map();
const transportFaults = process.env.FIREFLY_NATIVE_TRANSPORT_FAULTS === 'true';
const fontEvidence = [];
let phase = 'owned-native-runtime-ready';
let currentStage = 'initialization';
let lastPage;
let lastHttpStatus;
let lastNativeSubmission;
const stage = value => { currentStage = value; };
let browser;
let server;
const passed = label => { phase = label; results.push(label); console.log(`PASS ${label}`); };
const delay = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));
const nativeTool = (action, population) => execFileSync('python3', ['tooling/native_integration_fixture.py', action,
  ...(population ? ['--population', population] : [])], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const snapshot = population => JSON.parse(nativeTool('snapshot', population));
const faultStatus = population => JSON.parse(nativeTool('fault_status', population));
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
async function nextCode(profile) {
  const factor = factors.get(profile.kind); assert.ok(factor, 'Previously enrolled native TOTP required');
  let counter = Math.floor(Date.now() / 30000);
  if (counter <= factor.lastCounter) { await delay((factor.lastCounter + 1) * 30000 - Date.now() + 300); counter = Math.floor(Date.now() / 30000); }
  factor.lastCounter = counter; return totpCode(factor.secret, counter * 30);
}
async function submitNativeForm(page, profile, selector, path = '') {
  const submitted = page.waitForRequest(request => request.method() === 'POST'
    && request.url() === `${profile.issuer}/firefly-recovery${path}`);
  await page.locator(selector).click();
  const headers = await (await submitted).allHeaders();
  assert.equal(headers.origin, origin, 'Actual native browser form must send the exact trusted Origin');
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
  const submitted = page.waitForResponse(response => response.request().method() === 'POST'
    && response.url() === `${profile.issuer}/firefly-recovery`);
  await page.locator('#ffid-recovery-continue').click();
  const response = await submitted; lastHttpStatus = response.status();
  const headers = await response.request().allHeaders();
  const form = new URLSearchParams(response.request().postData() || '');
  lastNativeSubmission = { status: response.status(),
    originClass: headers.origin === origin ? 'same' : headers.origin === 'null' ? 'null' : headers.origin ? 'other' : 'absent',
    nativeCookiePresent: /(?:^|;\s*)FF_NATIVE_RECOVERY=/.test(headers.cookie || ''), csrfPresent: Boolean(form.get('csrf')) };
  try { lastNativeSubmission.ceremony = JSON.parse(nativeTool('ceremony_state', profile.kind)); }
  catch { lastNativeSubmission.ceremony = { stage: 'unavailable' }; }
  assert.equal(lastNativeSubmission.originClass, 'same', 'Actual native password form must send the exact trusted Origin');
  assert.equal(response.status(), 200, 'Actual browser native password POST must retain the generic factor stage');
  await page.locator('#otp').waitFor();
  await assertNativeFont(page, `${profile.kind}-masked-native-factor-form`);
  if (known) {
    await captureEmptyNativeForm(page, `${profile.kind}-recovery-totp-es`);
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
async function assertTranslation(page, language, key) {
  assert.ok((await page.locator('html').getAttribute('lang')).startsWith(language));
  assert.equal((await page.locator('#kc-page-title').innerText()).trim(), await sourceMessage(language, key));
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
  await page.reload(); await page.locator('#ffid-recovery-audit-retry').waitFor();
  assert.equal(await page.locator('input[type="password"], #otp, #username').count(), 0, 'Audit-only resume must not ask for factors');
  const fields = await page.locator('#ffid-recovery-audit-retry input').evaluateAll(inputs => inputs.map(input => input.name));
  assert.deepEqual(fields, ['csrf'], 'Audit reconciliation must send only fresh CSRF');
  const retained = snapshot(profile.kind);
  assert.equal(retained.native.executionId, committed.native.executionId);
  assert.equal(retained.core[0].attempts, committed.core[0].attempts);
  stage(`${profile.kind}-committed-record-csrf-only-reconciliation`);
  await submitNativeForm(page, profile, '#ffid-recovery-audit-retry button[type="submit"]');
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
    headers: { Origin: origin }, form: { csrf: token, otp: code }, timeout: 20000,
  }).then(response => ({ response }), error => ({ error }));
  stage(`${profile.kind}-first-genuine-online-verification`);
  const first = submit(csrf);
  const deadline = Date.now() + 2200;
  while (faultStatus(profile.kind).verifyRaceArrivals === 0 && Date.now() < deadline) await delay(25);
  assert.equal(faultStatus(profile.kind).verifyRaceArrivals, 1, 'First request must reach accepted real online verification before racing');
  // Cookie GET is the actual interrupted-delivery resume path: it rotates CSRF and reuses committed proof.
  stage(`${profile.kind}-concurrent-cookie-resume-fresh-csrf`);
  await page.reload(); await page.locator('#otp').waitFor();
  const freshCsrf = await page.locator('input[name="csrf"]').inputValue();
  assert.notEqual(freshCsrf, csrf);
  stage(`${profile.kind}-second-genuine-online-verification`);
  const both = await Promise.all([first, submit(freshCsrf)]);
  for (const result of both) {
    if (result.error) throw result.error; assert.equal(result.response.status(), 200);
    const complete = await page.evaluate(({ html, title }) => {
      const document = new DOMParser().parseFromString(html, 'text/html');
      return document.querySelector('#kc-page-title')?.textContent.trim() === title
        && !document.querySelector('#ffid-native-recovery, .ffid-native-journey [role="alert"]');
    }, { html: await result.response.text(), title: await sourceMessage('es', 'ffidRecoveryCompleteTitle') });
    assert.equal(complete, true, 'Each genuine concurrent response must report COMPLETE without a recovery failure alert');
  }
  const barrier = faultStatus(profile.kind);
  assert.equal(barrier.verifyRaceArrivals, 2); assert.equal(barrier.verifyRaceSpent, true);
  await page.reload();
  assert.equal(await page.locator('#otp, #password').count(), 0, 'Both actual native requests must settle on the same completed journal');
  const settled = snapshot(profile.kind);
  assert.equal(settled.native.executions, 1); assert.equal(settled.native.executionId, settled.core[0].executionId);
  assert.equal(settled.native.unlockAudits, 1); assert.equal(settled.native.recordAudits, 1);
  assert.equal(settled.native.maximumChecksPerReservation, 1); assert.equal(settled.native.knowledge, 1); assert.equal(settled.native.possession, 2);
  assert.equal(settled.core.length, 1); assert.equal(settled.core[0].attempts, 3); assert.equal(settled.core[0].challenges, 2);
  assert.equal(settled.core[0].state, 'CONSUMED'); assert.equal(settled.core[0].outcome, 'SUCCEEDED'); assert.equal(settled.core[0].successAudits, 1);
  passed(`${profile.kind}-two-real-online-verifications-one-native-execution-and-core-success-audit`);
}

async function supportPin(profile, context) {
  let created = false;
  for (const [suffix, pin, expected] of [['set', '70934628', true], ['set', '84173059', true], ['revoke', null, false]]) {
    const page = await context.newPage(); await page.goto(`${profile.issuer}/firefly-recovery/support-pin/${suffix}?kc_locale=en`);
    await assertTranslation(page, 'en', suffix === 'revoke' ? 'ffidPinRevokeTitle' : 'ffidPinTitle');
    await captureEmptyNativeForm(page, `customers-pin-${suffix}-en-${results.length}`);
    await page.locator('#password').fill(profile.person.password); await page.locator('#otp').fill(await nextCode(profile));
    if (pin) { await page.locator('#pin').fill(pin); await page.locator('#pinConfirm').fill(pin); }
    await submitNativeForm(page, profile, '#ffid-pin-save', '/support-pin');
    await page.locator('#ffid-support-pin').waitFor({ state: 'detached' });
    assert.equal(snapshot(profile.kind).native.pinActive, expected, 'Actual native PIN lifecycle state differs');
    assert.equal(await page.locator('input[type="password"]').count(), 0, 'Credential field must not enter status capture');
    await assertTranslation(page, 'en', 'ffidPinTitle');
    await captureSafeJourney(page, `customers-pin-${suffix}-${results.length}`);
    await page.goto(`${profile.issuer}/firefly-recovery/support-pin?kc_locale=es`);
    await assertTranslation(page, 'es', 'ffidPinTitle');
    if (created) await page.waitForFunction(() => {
        const time = document.querySelector('time[data-ffid-local-date]');
        return time && time.textContent === new Intl.DateTimeFormat(document.documentElement.lang,
          { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(time.dateTime));
      });
    else assert.equal(await page.locator('time[data-ffid-local-date]').count(), 0, 'Initial PIN creation must not fabricate a replacement date');
    if (pin) created = true;
    assert.equal(snapshot(profile.kind).native.pinActive, expected, 'Localized status GET must not change PIN lifecycle state');
    await captureSafeJourney(page, `customers-pin-${suffix}-es-${results.length}`);
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
    assert.ok(tokens.scope?.split(' ').includes('offline_access'), 'Actual offline access must have been granted before retirement');
    const browserClients = await (await admin(profile, 'clients?clientId=native-browser')).json(); assert.equal(browserClients.length, 1);
    const offlinePath = `users/${profile.person.id}/offline-sessions/${browserClients[0].id}`;
    const previousOffline = await admin(profile, offlinePath); assert.equal(previousOffline.status, 200);
    assert.ok((await previousOffline.json()).length > 0, 'Real offline session must exist before the native lock');
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
    const csrf = await page.locator('input[name="csrf"]').inputValue();
    if (transportFaults && profile.population === 'HUMAN') nativeTool('arm_record_loss', profile.kind);
    stage(`${profile.kind}-native-accepted-possession-submit`);
    if (transportFaults && profile.population === 'STAFF') await concurrentExecution(profile, context, page, csrf);
    else { await page.locator('#otp').fill(await nextCode(profile)); await submitNativeForm(page, profile, '#ffid-recovery-continue'); }
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
    assert.equal(refresh.status, 400); const sessions = await admin(profile, `users/${profile.person.id}/sessions`);
    assert.equal((await sessions.json()).length, 0);
    const retiredOffline = await admin(profile, offlinePath); assert.equal(retiredOffline.status, 200); assert.equal((await retiredOffline.json()).length, 0);
    passed(`${profile.kind}-old-refresh-online-and-real-offline-sessions-retired`);
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
    pending: [...(transportFaults ? [] : ['true simultaneous native execution requests', 'post-commit network response-loss injection', 'natural server ceremony expiry and swapped private attestation references']),
      'admitted actor JWT and consumed authorization receipt expiry in native runtime',
      'support PIN BPO/case/delegation owner acceptance', 'production/regulatory approval'],
    scope: 'Owned synthetic HTTPS native Keycloak/Core PostgreSQL/actual generated-SDK Domain acceptance only.' }, null, 2));
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
    networkCauseCode: allowedNetworkCodes.has(error?.cause?.code) ? error.cause.code : 'unclassified',
    lastHttpStatus, lastNativeSubmission, inventory, scope: 'Partial native integration; uncompleted stages are not qualified.' }, null, 2));
  process.exitCode = 1;
} finally {
  pending.clear(); privateProofs.clear(); if (browser) await browser.close(); if (server) await new Promise(ok => server.close(ok));
}
