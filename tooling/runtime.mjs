import assert from 'node:assert/strict';
import { createHash, randomBytes, createPublicKey, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { reportFailure } from './safe-errors.mjs';
import { isAuthorizationRefusal } from './protocol-assertions.mjs';
import { selectNewRecoveryMessage } from './recovery-mail.mjs';
import { observeConsole } from './console-diagnostics.mjs';

const stateDir = resolve(process.env.FIREFLY_ID_STATE || '.state/sandbox');
const evidence = resolve('.work/runtime');
await mkdir(evidence, { recursive: true });
const credentials = JSON.parse(await readFile(`${stateDir}/credentials.json`, 'utf8'));
const base = 'http://id.firefly.test:8180';
const issuer = `${base}/realms/sandbox-customers`;
const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
assert.equal(metadata.issuer, issuer);
const redirect = 'http://localhost:3000/oidc/callback';
const clientId = 'sandbox-web';
const results = [];
let phase = 'initialization';
const passed = name => { results.push(name); console.log(`PASS ${name}`); };
const form = values => new URLSearchParams(values);
const post = (url, values) => fetch(url, { method: 'POST', body: form(values) });
let pending;
const server = createServer((request, response) => {
  const url = new URL(request.url, redirect);
  response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
  response.end('Firefly Identity synthetic test callback. You can close this page.');
  if (url.pathname === '/oidc/callback' && pending) pending(url);
});
await new Promise((ok, fail) => server.listen(3000, '127.0.0.1', ok).once('error', fail));
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const captureAccountDiagnostics = observeConsole(page);
let captureConsoleFailure;
page.setDefaultTimeout(15000);

async function assertConsoleContrast(target, surface, dark) {
  await target.waitForFunction(expected => document.documentElement.classList.contains('pf-v5-theme-dark') === expected, dark);
  const samples = await target.evaluate(() => {
    const rgb = value => {
      const parts = value.match(/[\d.]+/g)?.map(Number) || [0, 0, 0, 0];
      return [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1];
    };
    const background = element => {
      const chain = [];
      for (let parent = element; parent; parent = parent.parentElement) chain.unshift(parent);
      let color = [255, 255, 255];
      for (const parent of chain) {
        const layer = rgb(getComputedStyle(parent).backgroundColor);
        color = color.map((value, index) => layer[index] * layer[3] + value * (1 - layer[3]));
      }
      return color;
    };
    const main = document.querySelector('.pf-v5-c-page__main');
    return ['h1', 'h2', 'p', 'label', 'input:not([type="hidden"]):not(:disabled):not([readonly])'].flatMap(selector => {
      const element = [...(main?.querySelectorAll(selector) || [])].find(candidate => candidate.getClientRects().length);
      if (!element) return [];
      return [{ kind: selector.startsWith('input') ? 'editable-input' : selector,
        foreground: rgb(getComputedStyle(element).color).slice(0, 3), background: background(element) }];
    });
  });
  const luminance = channels => channels.map(value => {
    const channel = value / 255;
    return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4;
  }).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
  const results = samples.map(sample => {
    const values = [luminance(sample.foreground), luminance(sample.background)].sort((a, b) => b - a);
    return { ...sample, contrast: (values[0] + .05) / (values[1] + .05) };
  });
  await writeFile(`${evidence}/${surface}-contrast.json`, JSON.stringify({ dark, samples: results }, null, 2));
  assert.ok(results.length >= 2, 'Console contrast samples are unavailable');
  assert.ok(results.every(sample => sample.contrast >= 4.5), 'Rendered console text contrast is below the selected 4.5:1 threshold');
}

async function assertWelcomeLayout(target) {
  const layout = await target.evaluate(() => {
    const description = document.querySelector('.keycloak__dashboard_welcome_tab');
    const section = description?.closest('.pf-v5-c-page__main-section');
    const bounds = element => {
      const { left, right, width } = element.getBoundingClientRect();
      return { left, right, width };
    };
    return { viewport: innerWidth, description: description ? bounds(description) : null,
      section: section ? bounds(section) : null,
      links: [...(section?.querySelectorAll('.pf-v5-c-action-list a') || [])].map(bounds) };
  });
  assert.ok(layout.description && layout.section, 'Native administrative welcome content is unavailable');
  assert.ok(layout.description.width >= Math.min(480, layout.section.width - 48), 'Welcome description is compressed into a narrow grid column');
  assert.equal(layout.links.length, 3, 'Native administrative resource links are missing');
  assert.ok(layout.links.every(link => link.left >= 0 && link.right <= layout.viewport), 'Administrative resource links are clipped outside the viewport');
}

function authorization({ challenge, state, nonce, ...extra }) {
  const url = new URL(metadata.authorization_endpoint);
  url.search = form({ client_id: clientId, response_type: 'code', redirect_uri: redirect,
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256', ...extra }).toString();
  return url.href;
}

async function login({ capture = false, checkReplay = false } = {}) {
  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(24).toString('base64url');
  const nonce = randomBytes(24).toString('base64url');
  let timer;
  const callback = new Promise((ok, fail) => {
    timer = setTimeout(() => fail(new Error('OIDC callback deadline exceeded')), 30000);
    pending = url => { clearTimeout(timer); pending = null; ok(url); };
  });
  try {
    phase = 'login authorization page';
    await page.goto(authorization({ challenge, state, nonce }));
    if (await page.locator('#username').isVisible()) {
      if (capture) {
        phase = 'login desktop presentation';
        await page.setViewportSize({ width: 1440, height: 1000 });
        await page.emulateMedia({ colorScheme: 'light' });
        await page.evaluate(() => document.fonts.ready);
        assert.ok(await page.evaluate(() => document.fonts.check('16px Manrope')));
        const brand = await page.evaluate(() => {
          const title = getComputedStyle(document.querySelector('#kc-page-title'));
          const label = getComputedStyle(document.querySelector('label[for="username"]'));
          const action = getComputedStyle(document.querySelector('#kc-login'));
          return { titleSize: title.fontSize, titleWeight: title.fontWeight, labelSize: label.fontSize,
            labelWeight: label.fontWeight, actionColor: action.backgroundColor };
        });
        assert.deepEqual(brand, { titleSize: '27px', titleWeight: '450', labelSize: '13px',
          labelWeight: '650', actionColor: 'rgb(255, 179, 74)' }, 'Effective native controls diverge from the canonical brand tokens');
        assert.ok(await page.evaluate(() => {
          const width = document.querySelector('main').getBoundingClientRect().width;
          return width >= 440 && width <= 500;
        }), 'Desktop form measure is outside the reviewed composition');
        await page.screenshot({ path: `${evidence}/login-desktop-light.png`, fullPage: true });
        await page.emulateMedia({ colorScheme: 'dark' });
        await page.waitForFunction(() => document.documentElement.classList.contains('pf-v5-theme-dark'));
        await page.screenshot({ path: `${evidence}/login-desktop-dark.png`, fullPage: true });
        await page.setViewportSize({ width: 390, height: 844 });
        await page.emulateMedia({ colorScheme: 'light' });
        await page.waitForFunction(() => !document.documentElement.classList.contains('pf-v5-theme-dark'));
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page.screenshot({ path: `${evidence}/login-mobile-light.png`, fullPage: true });
        await page.emulateMedia({ colorScheme: 'dark' });
        await page.waitForFunction(() => document.documentElement.classList.contains('pf-v5-theme-dark'));
        await page.screenshot({ path: `${evidence}/login-mobile-dark.png`, fullPage: true });
        phase = 'login mobile bounds';
        await writeFile(`${evidence}/layout.json`, JSON.stringify(await page.evaluate(() => ({
          viewport: innerWidth, document: document.documentElement.scrollWidth,
          mainWidth: document.querySelector('main').getBoundingClientRect().width,
          fontLoaded: document.fonts.check('16px Manrope'),
        })), null, 2));
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      }
      phase = 'login credential submission';
      await page.locator('#username').fill(credentials.customers.username);
      await page.locator('#password').fill(credentials.customers.password);
      await page.locator('#kc-login').click();
    }
    const callbackUrl = await callback;
    phase = 'login callback state and code';
    assert.equal(callbackUrl.searchParams.get('state'), state);
    assert.ok(callbackUrl.searchParams.get('code'));
    const code = callbackUrl.searchParams.get('code');
    const exchange = await post(metadata.token_endpoint, { grant_type: 'authorization_code',
      client_id: clientId, redirect_uri: redirect, code, code_verifier: verifier });
    phase = `code exchange HTTP ${exchange.status}`;
    assert.equal(exchange.status, 200, 'Code exchange failed');
    const tokens = await exchange.json();
    phase = 'ID token signature, issuer, audience and nonce';
    const idPayload = await validateJwt(tokens.id_token, clientId);
    assert.equal(idPayload.nonce, nonce);
    if (checkReplay) {
      const replay = await post(metadata.token_endpoint, { grant_type: 'authorization_code',
        client_id: clientId, redirect_uri: redirect, code, code_verifier: verifier });
      phase = `code replay HTTP ${replay.status}`;
      assert.equal(replay.status, 400);
    }
    return tokens;
  } finally { clearTimeout(timer); pending = null; }
}

async function validateJwt(token, audience) {
  const [header, payload, signature] = token.split('.');
  const decodedHeader = JSON.parse(Buffer.from(header, 'base64url'));
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  console.log(`JWT validation shape: ${JSON.stringify({
    purpose: audience === clientId ? 'identity' : 'api', algorithmAllowed: decodedHeader.alg === 'RS256',
    audienceMatches: [claims.aud].flat().includes(audience), issuerMatches: claims.iss === issuer,
    expiryFresh: claims.exp > Date.now() / 1000, subjectPresent: Boolean(claims.sub),
  })}`);
  phase = 'JWT declared algorithm';
  assert.equal(decodedHeader.alg, 'RS256');
  const { keys } = await (await fetch(metadata.jwks_uri)).json();
  const jwk = keys.find(key => key.kid === decodedHeader.kid && key.use === 'sig');
  phase = 'JWT signing key resolution';
  assert.ok(jwk);
  phase = 'JWT cryptographic signature';
  assert.ok(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`),
    createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(signature, 'base64url')));
  phase = 'JWT exact issuer';
  assert.equal(claims.iss, issuer);
  phase = 'JWT receiver audience';
  assert.ok([claims.aud].flat().includes(audience));
  phase = 'JWT expiry';
  assert.ok(claims.exp > Date.now() / 1000);
  phase = 'JWT nonempty subject';
  assert.ok(claims.sub);
  return claims;
}

try {
  for (const [name, extra] of [
    ['external redirect rejected', { redirect_uri: 'https://attacker.invalid/callback' }],
    ['missing PKCE rejected', { code_challenge: '', code_challenge_method: '' }],
    ['implicit flow rejected', { response_type: 'token' }],
  ]) {
    const url = authorization({ challenge: 'a'.repeat(43), state: 'synthetic', nonce: 'synthetic', ...extra });
    const response = await fetch(url, { redirect: 'manual' });
    const location = response.headers.get('location');
    assert.ok(isAuthorizationRefusal(response.status, location, redirect));
    assert.ok(!response.headers.get('location')?.includes('attacker.invalid'));
    passed(name);
  }
  const passwordGrant = await post(metadata.token_endpoint, { grant_type: 'password', client_id: clientId,
    username: credentials.customers.username, password: credentials.customers.password });
  assert.equal(passwordGrant.status, 400);
  passed('password grant disabled');

  let tokens = await login({ capture: true });
  phase = 'customer access token signature and profile';
  const claims = await validateJwt(tokens.access_token, 'sandbox-api');
  console.log(`Provider claim shape: ${JSON.stringify({
    tenantMatches: claims.tenant_id === 'synthetic-tenant',
    populationMatches: claims.principal_kind === 'HUMAN', clientMatches: claims.client_id === clientId,
    hasStaffLink: claims.staff_actor_id !== undefined, partyLinkPresent: typeof claims.party_id === 'string',
    exp: typeof claims.exp, nbf: typeof claims.nbf,
    audienceType: Array.isArray(claims.aud) ? 'array' : typeof claims.aud,
    audienceCount: [claims.aud].flat().length,
    audienceHasResource: [claims.aud].flat().includes('sandbox-api'),
    audienceHasAccount: [claims.aud].flat().includes('account'),
  })}`);
  phase = 'signed tenant namespace';
  assert.equal(claims.tenant_id, 'synthetic-tenant');
  phase = 'signed human population';
  assert.equal(claims.principal_kind, 'HUMAN');
  phase = 'signed client identity';
  assert.equal(claims.client_id, clientId);
  phase = 'absence of workforce identity';
  assert.equal(claims.staff_actor_id, undefined);
  phase = 'synthetic party identity format';
  assert.match(claims.party_id, /^[a-f0-9-]{36}$/);
  passed('real code PKCE, state, nonce, JWKS and signed claims');
  const otherRealm = await fetch(`${base}/realms/sandbox-workforce/protocol/openid-connect/userinfo`,
    { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(otherRealm.status, 401);
  passed('cross-realm token refused');

  phase = 'refresh rotation';
  const refresh = await post(metadata.token_endpoint, { grant_type: 'refresh_token',
    client_id: clientId, refresh_token: tokens.refresh_token });
  assert.equal(refresh.status, 200);
  const rotated = await refresh.json();
  assert.ok(rotated.refresh_token !== tokens.refresh_token, 'Refresh token did not rotate');
  phase = 'refresh reuse rejection';
  const reuse = await post(metadata.token_endpoint, { grant_type: 'refresh_token',
    client_id: clientId, refresh_token: tokens.refresh_token });
  assert.equal(reuse.status, 400);
  passed('refresh rotation and reuse rejection');

  tokens = await login();
  phase = 'account console';
  captureConsoleFailure = () => captureAccountDiagnostics(evidence, 'account');
  await page.goto(`${issuer}/account/`);
  await page.getByRole('heading', { name: 'Personal info' }).waitFor();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.emulateMedia({ colorScheme: 'light' });
  await page.evaluate(() => document.fonts.ready);
  assert.ok(await page.evaluate(() => document.fonts.check('16px Manrope')));
  await assertConsoleContrast(page, 'account-light', false);
  await page.screenshot({ path: `${evidence}/account-desktop-light.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  await assertConsoleContrast(page, 'account-desktop-dark', true);
  await page.screenshot({ path: `${evidence}/account-desktop-dark.png`, fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: 'light' });
  await assertConsoleContrast(page, 'account-mobile-light', false);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.screenshot({ path: `${evidence}/account-mobile-light.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  await assertConsoleContrast(page, 'account-dark', true);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Account layout overflows the mobile viewport');
  await page.screenshot({ path: `${evidence}/account-mobile-dark.png`, fullPage: true });
  passed('real account console and self-hosted Manrope');
  await captureAccountDiagnostics(evidence, 'account', { failure: false });
  captureConsoleFailure = undefined;
  phase = 'RP initiated logout';
  const logout = new URL(metadata.end_session_endpoint);
  logout.search = form({ id_token_hint: tokens.id_token,
    post_logout_redirect_uri: 'http://localhost:3000/signed-out', state: 'synthetic-logout' });
  await page.goto(logout.href);
  if (await page.locator('#kc-logout').isVisible()) await page.locator('#kc-logout').click();
  await page.waitForURL('http://localhost:3000/signed-out*');
  const afterLogout = await post(metadata.token_endpoint, { grant_type: 'refresh_token',
    client_id: clientId, refresh_token: tokens.refresh_token });
  assert.equal(afterLogout.status, 400);
  passed('RP initiated logout invalidates refresh session');

  phase = 'password recovery';
  const recoveryAuth = authorization({ challenge: 'a'.repeat(43), state: 'recovery', nonce: 'recovery' });
  await page.goto(recoveryAuth);
  const priorMailbox = await (await fetch('http://localhost:8025/api/v1/messages')).json();
  const priorMessageIds = new Set((priorMailbox.messages || []).map(message => message.ID));
  await page.getByRole('link', { name: 'Forgot Password?' }).click();
  await page.getByLabel('Username or email').fill(credentials.customers.username);
  await page.getByRole('button', { name: 'Submit' }).click();
  let message;
  for (let attempt = 0; attempt < 20; attempt++) {
    const mailbox = await (await fetch('http://localhost:8025/api/v1/messages')).json();
    message = selectNewRecoveryMessage(mailbox.messages || [], priorMessageIds, 'customers@example.invalid');
    if (message) break;
    await new Promise(ok => setTimeout(ok, 500));
  }
  assert.ok(message, 'Synthetic recovery email was not delivered to Mailpit');
  const mail = await (await fetch(`http://localhost:8025/api/v1/message/${message.ID}`)).json();
  assert.ok(mail.HTML.includes('firefly'));
  const recoveryLink = mail.HTML.match(/href="([^"\s]*\/login-actions\/action-token[^"\s]*)"/);
  assert.ok(recoveryLink, 'Missing server-generated recovery link');
  await page.goto(recoveryLink[1].replaceAll('&amp;', '&'));
  const newPassword = `Aa1${randomBytes(30).toString('base64url')}`;
  await writeFile(`${stateDir}/pending-recovery-password.txt`, newPassword, { mode: 0o600 });
  await page.locator('#password-new').fill(newPassword);
  await page.locator('#password-confirm').fill(newPassword);
  await page.getByRole('button', { name: 'Submit' }).click();
  await context.clearCookies();
  credentials.customers.password = newPassword;
  await login();
  await writeFile(`${stateDir}/credentials.json`, JSON.stringify(credentials, null, 2) + '\n', { mode: 0o600 });
  passed('synthetic recovery email, password reset and fresh credential login');

  phase = 'master administration console';
  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  const captureAdminDiagnostics = observeConsole(adminPage);
  captureConsoleFailure = () => captureAdminDiagnostics(evidence, 'admin');
  await adminPage.goto(`${base}/admin/master/console/`);
  await adminPage.locator('#username').fill('sandbox-bootstrap');
  await adminPage.locator('#password').fill((await readFile(`${stateDir}/secrets/admin-password`, 'utf8')).trim());
  await adminPage.locator('#kc-login').click();
  await adminPage.locator('.pf-v5-c-masthead').waitFor({ timeout: 30000 });
  await adminPage.setViewportSize({ width: 1440, height: 1000 });
  await adminPage.emulateMedia({ colorScheme: 'light' });
  await adminPage.evaluate(() => document.fonts.ready);
  assert.ok(await adminPage.evaluate(() => document.fonts.check('16px Manrope')));
  await assertConsoleContrast(adminPage, 'admin-light', false);
  await assertWelcomeLayout(adminPage);
  await adminPage.screenshot({ path: `${evidence}/admin-desktop-light.png`, fullPage: true });
  await adminPage.emulateMedia({ colorScheme: 'dark' });
  await assertConsoleContrast(adminPage, 'admin-desktop-dark', true);
  await adminPage.screenshot({ path: `${evidence}/admin-desktop-dark.png`, fullPage: true });
  await adminPage.setViewportSize({ width: 390, height: 844 });
  const sidebar = adminPage.locator('.pf-v5-c-page__sidebar.pf-m-expanded');
  if (await sidebar.count()) await adminPage.locator('.pf-v5-c-masthead__toggle button').click();
  await adminPage.emulateMedia({ colorScheme: 'light' });
  await assertConsoleContrast(adminPage, 'admin-mobile-light', false);
  await assertWelcomeLayout(adminPage);
  assert.ok(await adminPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await adminPage.screenshot({ path: `${evidence}/admin-mobile-light.png`, fullPage: true });
  await adminPage.emulateMedia({ colorScheme: 'dark' });
  await assertConsoleContrast(adminPage, 'admin-dark', true);
  await assertWelcomeLayout(adminPage);
  assert.ok(await adminPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Administration layout overflows the mobile viewport');
  await adminPage.screenshot({ path: `${evidence}/admin-mobile-dark.png`, fullPage: true });
  await adminContext.close();
  passed('real master administration console and self-hosted Manrope');
  captureConsoleFailure = undefined;
  await login({ checkReplay: true });
  passed('authorization code replay refused in its own session');
  await context.clearCookies();
  const freshReceiverTokens = await login();
  await writeFile(`${stateDir}/runtime-token.txt`, freshReceiverTokens.access_token, { mode: 0o600 });
  await writeFile(`${evidence}/summary.json`, JSON.stringify({ results,
    tokenShape: { exp: typeof claims.exp, nbf: typeof claims.nbf,
      client_id: typeof claims.client_id, tenant_id: typeof claims.tenant_id },
    scope: 'Hosted ephemeral sandbox; no business entitlement or production acceptance.' }, null, 2));
} catch (error) {
  // Navigation errors can include credential-bearing action/logout URLs.
  reportFailure(error, results.at(-1) || 'none');
  console.error(`Failed stage: ${phase}`);
  if (captureConsoleFailure) {
    try { await captureConsoleFailure(); } catch { console.error('Console diagnostics unavailable.'); }
  }
  process.exitCode = 1;
} finally {
  try {
    await browser.close();
    await new Promise(ok => server.close(ok));
  } catch (error) {
    reportFailure(error, 'runtime cleanup');
    process.exitCode = 1;
  }
}
