import assert from 'node:assert/strict';
import { createHash, randomBytes, createPublicKey, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { reportFailure } from './safe-errors.mjs';
import { isAuthorizationRefusal } from './protocol-assertions.mjs';
import { selectNewRecoveryMessage } from './recovery-mail.mjs';

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
page.setDefaultTimeout(15000);

function authorization({ challenge, state, nonce, ...extra }) {
  const url = new URL(metadata.authorization_endpoint);
  url.search = form({ client_id: clientId, response_type: 'code', redirect_uri: redirect,
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256', ...extra }).toString();
  return url.href;
}

async function login({ capture = false } = {}) {
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
    await page.goto(authorization({ challenge, state, nonce }));
    if (await page.locator('#username').isVisible()) {
      if (capture) {
        await page.setViewportSize({ width: 1440, height: 1000 });
        await page.emulateMedia({ colorScheme: 'light' });
        await page.evaluate(() => document.fonts.ready);
        assert.ok(await page.evaluate(() => document.fonts.check('16px Manrope')));
        await page.screenshot({ path: `${evidence}/login-desktop-light.png`, fullPage: true });
        await page.setViewportSize({ width: 390, height: 844 });
        await page.emulateMedia({ colorScheme: 'dark' });
        await page.screenshot({ path: `${evidence}/login-mobile-dark.png`, fullPage: true });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      }
      await page.locator('#username').fill(credentials.customers.username);
      await page.locator('#password').fill(credentials.customers.password);
      await page.locator('#kc-login').click();
    }
    const callbackUrl = await callback;
    assert.equal(callbackUrl.searchParams.get('state'), state);
    assert.ok(callbackUrl.searchParams.get('code'));
    const code = callbackUrl.searchParams.get('code');
    const exchange = await post(metadata.token_endpoint, { grant_type: 'authorization_code',
      client_id: clientId, redirect_uri: redirect, code, code_verifier: verifier });
    assert.equal(exchange.status, 200, 'Code exchange failed');
    const tokens = await exchange.json();
    const idPayload = await validateJwt(tokens.id_token, clientId);
    assert.equal(idPayload.nonce, nonce);
    const replay = await post(metadata.token_endpoint, { grant_type: 'authorization_code',
      client_id: clientId, redirect_uri: redirect, code, code_verifier: verifier });
    assert.equal(replay.status, 400);
    return tokens;
  } finally { clearTimeout(timer); pending = null; }
}

async function validateJwt(token, audience) {
  const [header, payload, signature] = token.split('.');
  const decodedHeader = JSON.parse(Buffer.from(header, 'base64url'));
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  assert.equal(decodedHeader.alg, 'RS256');
  const { keys } = await (await fetch(metadata.jwks_uri)).json();
  const jwk = keys.find(key => key.kid === decodedHeader.kid && key.use === 'sig');
  assert.ok(jwk);
  assert.ok(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`),
    createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(signature, 'base64url')));
  assert.equal(claims.iss, issuer);
  assert.ok([claims.aud].flat().includes(audience));
  assert.ok(claims.exp > Date.now() / 1000);
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
  const claims = await validateJwt(tokens.access_token, 'sandbox-api');
  assert.equal(claims.tenant_id, 'synthetic-tenant');
  assert.equal(claims.principal_kind, 'HUMAN');
  assert.equal(claims.client_id, clientId);
  assert.equal(claims.staff_actor_id, undefined);
  assert.match(claims.party_id, /^[a-f0-9-]{36}$/);
  await writeFile(`${stateDir}/runtime-token.txt`, tokens.access_token, { mode: 0o600 });
  passed('real code PKCE, state, nonce, JWKS, signed claims, code replay');
  const otherRealm = await fetch(`${base}/realms/sandbox-workforce/protocol/openid-connect/userinfo`,
    { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(otherRealm.status, 401);
  passed('cross-realm token refused');

  const refresh = await post(metadata.token_endpoint, { grant_type: 'refresh_token',
    client_id: clientId, refresh_token: tokens.refresh_token });
  assert.equal(refresh.status, 200);
  const rotated = await refresh.json();
  assert.ok(rotated.refresh_token !== tokens.refresh_token, 'Refresh token did not rotate');
  const reuse = await post(metadata.token_endpoint, { grant_type: 'refresh_token',
    client_id: clientId, refresh_token: tokens.refresh_token });
  assert.equal(reuse.status, 400);
  passed('refresh rotation and reuse rejection');

  tokens = await login();
  await page.goto(`${issuer}/account/`);
  await page.getByRole('heading', { name: 'Personal info' }).waitFor();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.emulateMedia({ colorScheme: 'light' });
  await page.evaluate(() => document.fonts.ready);
  assert.ok(await page.evaluate(() => document.fonts.check('16px Manrope')));
  await page.screenshot({ path: `${evidence}/account-desktop-light.png`, fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.screenshot({ path: `${evidence}/account-mobile-dark.png`, fullPage: true });
  passed('real account console and self-hosted Manrope');
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

  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  await adminPage.goto(`${base}/admin/master/console/`);
  await adminPage.locator('#username').fill('sandbox-bootstrap');
  await adminPage.locator('#password').fill((await readFile(`${stateDir}/secrets/admin-password`, 'utf8')).trim());
  await adminPage.locator('#kc-login').click();
  await adminPage.locator('.pf-v5-c-masthead').waitFor({ timeout: 30000 });
  await adminPage.setViewportSize({ width: 1440, height: 1000 });
  await adminPage.emulateMedia({ colorScheme: 'light' });
  await adminPage.evaluate(() => document.fonts.ready);
  assert.ok(await adminPage.evaluate(() => document.fonts.check('16px Manrope')));
  await adminPage.screenshot({ path: `${evidence}/admin-desktop-light.png`, fullPage: true });
  await adminPage.setViewportSize({ width: 390, height: 844 });
  await adminPage.emulateMedia({ colorScheme: 'dark' });
  await adminPage.screenshot({ path: `${evidence}/admin-mobile-dark.png`, fullPage: true });
  await adminContext.close();
  passed('real master administration console and self-hosted Manrope');
  await writeFile(`${evidence}/summary.json`, JSON.stringify({ results,
    tokenShape: { exp: typeof claims.exp, nbf: typeof claims.nbf,
      client_id: typeof claims.client_id, tenant_id: typeof claims.tenant_id },
    scope: 'Hosted ephemeral sandbox; no business entitlement or production acceptance.' }, null, 2));
} catch (error) {
  // Navigation errors can include credential-bearing action/logout URLs.
  reportFailure(error, results.at(-1) || 'none');
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
