import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { reportFailure } from './safe-errors.mjs';

const base = 'http://id.firefly.test:8180';
const issuer = `${base}/realms/sandbox-customers`;
const redirect = 'http://localhost:3000/oidc/callback';
const credentials = JSON.parse(await readFile(resolve(process.env.FIREFLY_ID_STATE || '.state/sandbox', 'credentials.json'), 'utf8'));
const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
assert.equal(metadata.issuer, issuer);
const directory = resolve('.work/localization-runtime');
await mkdir(directory, { recursive: true });
const callbacks = new Map();
const results = [];
let phase = 'localized browser setup';
const server = createServer((request, response) => {
  const url = new URL(request.url, redirect);
  response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
  response.end('Synthetic localization callback. No credentials are displayed.');
  if (url.pathname === '/oidc/callback') callbacks.set(url.searchParams.get('state'), url);
});
await new Promise((ok, fail) => server.listen(3000, '127.0.0.1', ok).once('error', fail));
const browser = await chromium.launch();

function authorization(locale, extra = {}) {
  const verifier = randomBytes(48).toString('base64url');
  const state = randomBytes(24).toString('base64url');
  const url = new URL(metadata.authorization_endpoint);
  url.search = new URLSearchParams({ client_id: 'sandbox-web', response_type: 'code', redirect_uri: redirect,
    scope: 'openid profile email', ui_locales: locale, state, nonce: randomBytes(24).toString('base64url'),
    code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), ...extra });
  return { url, verifier, state };
}

async function assertLocale(page, locale) {
  assert.equal(await page.locator('html').getAttribute('lang'), locale);
  await page.evaluate(() => document.fonts.ready);
  assert.ok(await page.evaluate(() => document.fonts.check('16px Manrope')));
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
}

try {
  for (const locale of ['en', 'es']) {
    const context = await browser.newContext({ locale: locale === 'es' ? 'es-ES' : 'en-US',
      viewport: { width: 1440, height: 1000 }, colorScheme: 'light' });
    const page = await context.newPage();
    page.setDefaultTimeout(20000);
    try {
      phase = `localized ${locale} sign-in presentation`;
      const auth = authorization(locale);
      await page.goto(auth.url.href);
      await page.locator('#username').waitFor();
      await assertLocale(page, locale);
      assert.equal(await page.locator('#login-select-toggle option').count(), 2);
      await page.locator('#ffid-access-policy').waitFor({ state: 'visible' });
      await page.screenshot({ path: `${directory}/${locale}-login-desktop-light.png`, fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      await page.emulateMedia({ colorScheme: 'dark' });
      await assertLocale(page, locale);
      await page.screenshot({ path: `${directory}/${locale}-login-mobile-dark.png`, fullPage: true });

      phase = `localized ${locale} generic sign-in refusal`;
      await page.locator('#username').fill(credentials.customers.username);
      await page.locator('#password').fill('Deliberately incorrect synthetic localization password');
      await page.locator('#kc-login').click();
      await page.locator('#ffid-signin-error').waitFor({ state: 'visible' });
      const refusal = (await page.locator('#ffid-signin-error').innerText()).trim();
      assert.ok(refusal.startsWith(locale === 'es' ? 'No se ha podido iniciar sesión.' : 'Sign-in could not be completed.'));
      assert.equal(await page.locator('input[type="password"]').count(), 1);
      assert.equal(await page.locator('[data-password-toggle]').count(), 0);
      await assertLocale(page, locale);

      phase = `localized ${locale} successful code and PKCE`;
      await page.locator('#username').fill(credentials.customers.username);
      await page.locator('#password').fill(credentials.customers.password);
      await page.locator('#kc-login').click();
      await page.waitForURL(value => value.origin === new URL(redirect).origin && value.pathname === '/oidc/callback');
      const callback = callbacks.get(auth.state);
      assert.ok(callback?.searchParams.get('code') && !callback.searchParams.has('error'));
      const exchange = await fetch(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
        grant_type: 'authorization_code', client_id: 'sandbox-web', redirect_uri: redirect,
        code: callback.searchParams.get('code'), code_verifier: auth.verifier }) });
      assert.equal(exchange.status, 200);
      const tokens = await exchange.json();

      phase = `localized ${locale} logout confirmation`;
      const logout = new URL(metadata.end_session_endpoint);
      logout.search = new URLSearchParams({ client_id: 'sandbox-web', post_logout_redirect_uri: 'http://localhost:3000/signed-out',
        ui_locales: locale, state: randomBytes(24).toString('base64url') });
      await page.goto(logout.href);
      await page.locator('#kc-logout').waitFor({ state: 'visible' });
      await assertLocale(page, locale);
      await page.screenshot({ path: `${directory}/${locale}-logout-mobile-dark.png`, fullPage: true });
      await page.locator('#kc-logout').click();
      await page.waitForURL('http://localhost:3000/signed-out*');
      const afterLogout = await fetch(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
        grant_type: 'refresh_token', client_id: 'sandbox-web', refresh_token: tokens.refresh_token }) });
      assert.equal(afterLogout.status, 400);

      phase = `localized ${locale} recovery and generic acknowledgement`;
      await page.goto(authorization(locale).url.href);
      await page.locator('a[href*="/login-actions/reset-credentials"]').click();
      await page.locator('#kc-reset-password-form').waitFor();
      await assertLocale(page, locale);
      await page.screenshot({ path: `${directory}/${locale}-recovery-mobile-dark.png`, fullPage: true });
      await page.locator('#username').fill(`unknown-localization-${randomBytes(12).toString('hex')}`);
      await page.locator('#kc-form-buttons').click();
      await page.locator('.kc-feedback-text').waitFor({ state: 'visible' });
      await assertLocale(page, locale);
      assert.ok((await page.locator('.kc-feedback-text').innerText()).startsWith(locale === 'es'
        ? 'Si hay una cuenta que cumpla los requisitos' : 'If an eligible account matches'));

      phase = `localized ${locale} protocol error presentation`;
      await page.goto(authorization(locale, { client_id: 'unknown-localization-fixture' }).url.href);
      await page.locator('#kc-error-message').waitFor();
      await assertLocale(page, locale);
      await page.screenshot({ path: `${directory}/${locale}-error-mobile-dark.png`, fullPage: true });
      results.push(`${locale}: login, generic refusal, code/PKCE, logout/refresh refusal, recovery and protocol error`);
      console.log(`PASS localized ${locale} identity journeys`);
    } finally { await context.close(); }
  }
  await writeFile(`${directory}/summary.json`, JSON.stringify({ results,
    scope: 'Real isolated provider presentation and locale propagation; no regulatory or production acceptance.' }, null, 2));
} catch (error) {
  reportFailure(error, phase);
  process.exitCode = 1;
} finally {
  callbacks.clear();
  await browser.close();
  await new Promise(ok => server.close(ok));
}
