import assert from 'node:assert/strict';
import { createHash, createHmac, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { reportFailure } from './safe-errors.mjs';
import { selectNewRecoveryMessage } from './recovery-mail.mjs';

const BASE = 'http://id.firefly.test:8180';
const REDIRECT = 'http://localhost:3000/oidc/callback';
const CLIENT = 'sandbox-web';
const delay = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));

export function totpCode(encodedSecret, epochSeconds = Date.now() / 1000, digits = 6) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = encodedSecret.replace(/[\s=]/g, '').toUpperCase();
  assert.ok(/^[A-Z2-7]+$/.test(normalized), 'Invalid retained TOTP state');
  assert.ok([6, 8].includes(digits) && epochSeconds >= 0, 'Invalid TOTP parameters');
  let bits = '';
  for (const character of normalized) bits += alphabet.indexOf(character).toString(2).padStart(5, '0');
  const key = Buffer.from((bits.match(/.{8}/g) || []).map(byte => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(epochSeconds / 30)));
  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits)).toString().padStart(digits, '0');
}

async function protectedJson(filename, value) {
  const temporary = `${filename}.next-${randomBytes(8).toString('hex')}`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  await rename(temporary, filename);
}

async function request(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(15000) });
}

async function jsonRequest(url, options = {}) {
  const response = await request(url, options);
  assert.ok(response.ok, 'Expected successful JSON endpoint response');
  return response.json();
}

async function validateJwt(compact, metadata, audience) {
  const parts = compact.split('.');
  assert.equal(parts.length, 3, 'Expected signed compact JWT');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(header.alg, 'RS256');
  const { keys } = await jsonRequest(metadata.jwks_uri);
  const jwk = keys.find(key => key.kid === header.kid && key.use === 'sig');
  assert.ok(jwk, 'No matching issuer signature key');
  assert.ok(verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`),
    createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url')), 'JWT signature refused');
  assert.equal(claims.iss, metadata.issuer);
  assert.ok([claims.aud].flat().includes(audience), 'Required audience absent');
  assert.ok(typeof claims.exp === 'number' && claims.exp > Date.now() / 1000, 'Token expired');
  assert.ok(typeof claims.sub === 'string' && claims.sub.length > 0, 'Subject absent');
  if (claims.nbf !== undefined) assert.ok(claims.nbf <= Date.now() / 1000 + 60, 'Not-before refused');
  return claims;
}

async function main() {
  const results = [];
  const passed = name => { results.push(name); console.log(`PASS ${name}`); };
  let browser;
  let server;
  let phase = 'extended setup';
  const pending = new Map();
  try {
    const selected = (process.env.FIREFLY_ID_EXTENDED_FLOWS || 'verify,profile,mfa').split(',');
    assert.ok(selected.length > 0 && selected.every(name => ['verify', 'profile', 'mfa'].includes(name)), 'Unknown extended flow');
    const stateDir = resolve(process.env.FIREFLY_ID_STATE || '.state/sandbox');
    assert.equal((await stat(stateDir)).mode & 0o077, 0, 'Sandbox state must remain owner-only');
    assert.equal((await stat(`${stateDir}/credentials.json`)).mode & 0o077, 0, 'Credentials must remain owner-only');
    const credentials = JSON.parse(await readFile(`${stateDir}/credentials.json`, 'utf8'));
    const metadataCache = new Map();
    async function metadataFor(population) {
      if (!metadataCache.has(population)) {
        const issuer = `${BASE}/realms/sandbox-${population}`;
        const metadata = await jsonRequest(`${issuer}/.well-known/openid-configuration`);
        assert.equal(metadata.issuer, issuer);
        metadataCache.set(population, metadata);
      }
      return metadataCache.get(population);
    }
    server = createServer((incoming, outgoing) => {
      const url = new URL(incoming.url, REDIRECT);
      outgoing.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
      outgoing.end('Synthetic identity callback. No credentials are displayed.');
      if (url.pathname === '/oidc/callback') pending.get(url.searchParams.get('state'))?.(url);
    });
    await new Promise((ok, fail) => server.listen(3000, '127.0.0.1', ok).once('error', fail));
    const { chromium } = await import('playwright');
    browser = await chromium.launch();

    let adminPage;
    let adminAuthorization;
    async function adminRead(url) {
      if (!adminPage) {
        const context = await browser.newContext();
        adminPage = await context.newPage();
        adminPage.setDefaultTimeout(20000);
        const authenticated = adminPage.waitForResponse(async response => response.status() === 200
          && new URL(response.url()).pathname.startsWith('/admin/realms')
          && (await response.request().allHeaders()).authorization?.startsWith('Bearer '), { timeout: 40000 });
        authenticated.catch(() => {});
        await adminPage.goto(`${BASE}/admin/master/console/`);
        await adminPage.locator('#username').fill('sandbox-bootstrap');
        await adminPage.locator('#password').fill((await readFile(`${stateDir}/secrets/admin-password`, 'utf8')).trim());
        await adminPage.locator('#kc-login').click();
        adminAuthorization = (await (await authenticated).request().allHeaders()).authorization;
      }
      assert.ok(adminAuthorization?.startsWith('Bearer '), 'Actual browser administrative bearer required');
      const claims = JSON.parse(Buffer.from(adminAuthorization.slice(7).split('.')[1], 'base64url'));
      assert.ok(typeof claims.exp === 'number', 'Administrative token expiry missing');
      if (claims.exp < Date.now() / 1000 + 30) {
        const renewed = adminPage.waitForResponse(async response => response.status() === 200
          && new URL(response.url()).pathname.startsWith('/admin/realms')
          && (await response.request().allHeaders()).authorization?.startsWith('Bearer '));
        renewed.catch(() => {});
        await adminPage.reload();
        adminAuthorization = (await (await renewed).request().allHeaders()).authorization;
      }
      const response = await request(url, { headers: { Authorization: adminAuthorization, Accept: 'application/json' } });
      assert.equal(response.status, 200, 'Authenticated administrative snapshot refused');
      return response.json();
    }

    async function startLogin(population, account, existingContext) {
      const metadata = await metadataFor(population);
      const context = existingContext || await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(20000);
      const verifier = randomBytes(48).toString('base64url');
      const state = randomBytes(24).toString('base64url');
      const nonce = randomBytes(24).toString('base64url');
      let timer;
      let callbackReceived = false;
      const callback = new Promise((ok, fail) => {
        timer = setTimeout(() => fail(new Error('Extended callback deadline exceeded')), 120000);
        pending.set(state, url => { callbackReceived = true; clearTimeout(timer); pending.delete(state); ok(url); });
      });
      // Required-action UI work precedes awaiting the callback; keep failures handled meanwhile.
      callback.catch(() => {});
      const url = new URL(metadata.authorization_endpoint);
      url.search = new URLSearchParams({ client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid profile email', state, nonce, code_challenge_method: 'S256',
        code_challenge: createHash('sha256').update(verifier).digest('base64url') });
      const cancel = () => { clearTimeout(timer); pending.delete(state); };
      try {
        await page.goto(url.href);
        if (await page.locator('#username').isVisible()) {
          await page.locator('#username').fill(account.username);
          await page.locator('#password').fill(account.password);
          await page.locator('#kc-login').click();
        }
      } catch (error) { cancel(); throw error; }
      return { context, page, metadata, cancel,
        get callbackReceived() { return callbackReceived; },
        async finish() {
          try {
            const result = await callback;
            assert.equal(result.searchParams.get('state'), state);
            assert.ok(!result.searchParams.has('error'), 'Authorization was refused');
            assert.ok(result.searchParams.get('code'), 'No authorization code');
            if (result.searchParams.has('iss')) assert.equal(result.searchParams.get('iss'), metadata.issuer);
            const response = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
              grant_type: 'authorization_code', client_id: CLIENT, redirect_uri: REDIRECT,
              code: result.searchParams.get('code'), code_verifier: verifier }) });
            assert.equal(response.status, 200, 'Real PKCE code exchange refused');
            const tokens = await response.json();
            const identity = await validateJwt(tokens.id_token, metadata, CLIENT);
            assert.equal(identity.nonce, nonce);
            const claims = await validateJwt(tokens.access_token, metadata, 'sandbox-api');
            assert.equal(claims.sub, identity.sub, 'Identity and access token subjects differ');
            return { tokens, identity, claims };
          } finally { cancel(); }
        },
      };
    }

    async function protectedProfile(population, account, flow, baseline) {
      const protectedNames = ['tenant_id', 'party_id', 'staff_actor_id', 'principal_kind', 'client_id'];
      const sentinelName = `ffid_unmanaged_${randomBytes(10).toString('hex')}`;
      const forbiddenNames = [...protectedNames, sentinelName];
      phase = `${population} authenticated Account REST read and hidden attribute boundary`;
      const accountPath = `/realms/sandbox-${population}/account/`;
      const profileReady = flow.page.waitForResponse(async response => {
        const req = response.request();
        if (new URL(response.url()).pathname !== accountPath || req.method() !== 'GET' || response.status() !== 200) return false;
        const headers = await req.allHeaders();
        return headers.authorization?.startsWith('Bearer ') && (headers['content-type'] || '').includes('application/json');
      });
      profileReady.catch(() => {});
      await flow.page.goto(`${flow.metadata.issuer}/account/`);
      const profileResponse = await profileReady;
      const accountToken = (await profileResponse.request().allHeaders()).authorization;
      assert.ok(accountToken?.startsWith('Bearer '), 'Actual account API bearer required');
      function assertHidden(profile) {
        for (const name of forbiddenNames) {
          assert.ok(!Object.hasOwn(profile.attributes || {}, name) && !Object.hasOwn(profile, name), 'Account response exposed a protected or unmanaged attribute');
          assert.ok(!(profile.userProfileMetadata?.attributes || []).some(attribute => attribute.name === name), 'Account metadata exposed a protected or unmanaged attribute');
        }
      }
      const profile = await profileResponse.json();
      assertHidden(profile);
      const body = { username: profile.username, email: profile.email,
        firstName: profile.firstName, lastName: profile.lastName, attributes: profile.attributes || {} };
      const accountApi = `${flow.metadata.issuer}/account/`;
      const accountHeaders = { Authorization: accountToken, 'Content-Type': 'application/json', Accept: 'application/json' };
      const update = value => request(accountApi, { method: 'POST', headers: accountHeaders, body: JSON.stringify(value) });
      assert.match(baseline.claims.sub, /^[a-f0-9-]{36}$/, 'Synthetic user identifier missing');
      const userApi = `${BASE}/admin/realms/sandbox-${population}/users/${baseline.claims.sub}`;
      async function snapshot() {
        const user = await adminRead(userApi);
        assert.equal(user.id, baseline.claims.sub, 'Administrative snapshot identifies another user');
        assert.equal(user.username, account.username, 'Administrative snapshot identifies another account');
        return { attributes: user.attributes || {}, unmanaged: await adminRead(`${userApi}/unmanagedAttributes`) };
      }
      phase = `${population} private managed and unmanaged administrative baseline`;
      const stored = await snapshot();
      assert.deepEqual(stored.attributes.tenant_id, [baseline.claims.tenant_id], 'Stored tenant source differs from signed identity');
      const linkage = population === 'workforce' ? 'staff_actor_id' : 'party_id';
      const otherLinkage = population === 'workforce' ? 'party_id' : 'staff_actor_id';
      assert.equal(baseline.claims.principal_kind, population === 'workforce' ? 'STAFF' : 'HUMAN', 'Unexpected signed population');
      assert.equal(baseline.claims.client_id, CLIENT, 'Unexpected signed client');
      assert.equal(baseline.claims[otherLinkage], undefined, 'Signed identity contains cross-population linkage');
      assert.deepEqual(stored.attributes[linkage], [baseline.claims[linkage]], 'Stored population source differs from signed identity');
      for (const name of [otherLinkage, 'principal_kind', 'client_id', sentinelName]) {
        assert.ok(!Object.hasOwn(stored.attributes, name) && !Object.hasOwn(stored.unmanaged, name), 'Unexpected cross-population or shadow attribute at baseline');
      }
      async function unchanged() {
        assert.deepEqual(await snapshot(), stored, 'Account write changed stored managed or unmanaged attributes');
        const visible = await request(accountApi, { headers: accountHeaders });
        assert.equal(visible.status, 200, 'Authenticated Account REST read refused');
        assertHidden(await visible.json());
        const fresh = await startLogin(population, account, flow.context);
        try {
          const result = await fresh.finish();
          assert.equal(result.claims.sub, baseline.claims.sub, 'Fresh signed identity identifies another user');
          for (const name of forbiddenNames) {
            assert.deepEqual(result.claims[name], baseline.claims[name], 'Protected signed identity claim changed');
          }
        } finally { fresh.cancel(); await fresh.page.close(); }
      }
      phase = `${population} permitted baseline Account REST update and independent readback`;
      assert.equal((await update(body)).status, 204, 'Baseline profile write must be permitted before forgery tests');
      await unchanged();
      const attempts = { tenant_id: 'forged-tenant', party_id: randomUUID(), staff_actor_id: randomUUID(),
        principal_kind: population === 'workforce' ? 'HUMAN' : 'STAFF', client_id: 'forged-client', [sentinelName]: randomUUID() };
      for (const [name, value] of Object.entries(attempts)) {
        const label = name === sentinelName ? 'unmanaged sentinel' : name;
        for (const operation of ['write', 'remove']) {
          phase = `${population} ${label} Account REST ${operation} refusal`;
          const attempted = await update({ ...body, attributes: { ...body.attributes, [name]: operation === 'write' ? [value] : [] } });
          assert.ok([204, 400].includes(attempted.status), 'Unexpected protected-profile update response');
          phase = `${population} ${label} ${operation} private storage and fresh signed identity readback`;
          await unchanged();
        }
      }
      passed(`${population} permitted Account REST updates cannot change protected sources, cross-population or unmanaged attributes; administrative storage and fresh signed claims remain unchanged`);
    }

    if (selected.includes('verify')) {
      phase = 'verification fixture email and required action';
      assert.ok(credentials.verify_email, 'Fresh extended verification fixture required');
      const mailbox = await jsonRequest('http://localhost:8025/api/v1/messages');
      const prior = new Set((mailbox.messages || []).map(message => message.ID));
      const flow = await startLogin('customers', credentials.verify_email);
      try {
        await flow.page.getByRole('heading', { name: 'Check your email' }).waitFor();
        let message;
        for (let attempt = 0; attempt < 30; attempt++) {
          const current = await jsonRequest('http://localhost:8025/api/v1/messages');
          message = selectNewRecoveryMessage(current.messages || [], prior, 'verify-email@example.invalid');
          if (message) break;
          await delay(500);
        }
        assert.ok(message, 'No new synthetic verification email');
        const mail = await jsonRequest(`http://localhost:8025/api/v1/message/${message.ID}`);
        const matched = mail.HTML.match(/href="([^"\s]*\/login-actions\/action-token[^"\s]*)"/);
        assert.ok(matched, 'Verification action link missing');
        const action = new URL(matched[1].replaceAll('&amp;', '&'));
        assert.equal(action.origin, BASE);
        assert.ok(action.pathname.startsWith('/realms/sandbox-customers/login-actions/action-token'));
        const popupReady = flow.page.waitForEvent('popup');
        popupReady.catch(() => {});
        await flow.page.evaluate(href => {
          const link = document.createElement('a');
          link.href = href; link.target = '_blank'; link.textContent = 'Open synthetic verification message';
          document.body.append(link); link.click(); link.remove();
        }, action.href);
        const popup = await popupReady;
        await popup.waitForLoadState('domcontentloaded');
        // A fresh authentication session can show an explicit confirmation before consuming the link.
        const confirm = popup.locator('#kc-info-message a[href*="/login-actions/action-token"]');
        if (await confirm.isVisible()) await confirm.click();
        const result = await flow.finish();
        assert.equal(result.identity.email_verified, true, 'Email verification did not complete');
        passed('new synthetic verification email, real popup action and signed verified identity');
        phase = 'consumed verification action status and recognized refusal';
        const replayContext = await browser.newContext();
        let replayCallback = false;
        try {
          const replay = await replayContext.newPage();
          replay.on('request', req => {
            const url = new URL(req.url());
            if (url.origin === new URL(REDIRECT).origin && url.pathname === new URL(REDIRECT).pathname) replayCallback = true;
          });
          const response = await replay.goto(action.href);
          assert.ok(response && response.status() >= 200 && response.status() < 500, 'Reused verification action produced a provider failure');
          await replay.locator('#kc-info-message, #kc-error-message').waitFor();
          const replayText = await replay.locator('#kc-info-message, #kc-error-message').innerText();
          assert.ok(/already verified|verified already|no longer valid|expired|invalid|already used/i.test(replayText), 'Reused verification action was not refused or identified as consumed');
          assert.ok(!replayCallback && !replay.url().startsWith(REDIRECT), 'Reused action issued a login callback');
        } finally { await replayContext.close(); }
        passed('consumed verification action cannot issue a new login code');
      } finally { flow.cancel(); await flow.context.close(); }
    }

    if (selected.includes('profile')) {
      phase = 'customer profile fixture browser authentication';
      const flow = await startLogin('customers', credentials.customers);
      try {
        const baseline = await flow.finish();
        await protectedProfile('customers', credentials.customers, flow, baseline);
      } finally { flow.cancel(); await flow.context.close(); }
    }

    if (selected.includes('mfa')) {
      phase = 'workforce retained factor and enrollment authentication';
      const filename = `${stateDir}/secrets/workforce-totp.json`;
      assert.ok(((await stat(filename)).mode & 0o077) === 0, 'TOTP state must remain owner-only');
      let factor = JSON.parse(await readFile(filename, 'utf8'));
      let enrolledNow = false;
      async function nextCode() {
        while (Math.floor(Date.now() / 30000) <= Math.max(factor.lastAcceptedCounter ?? -1, factor.lastAttemptedCounter ?? -1)) await delay(500);
        const counter = Math.floor(Date.now() / 30000);
        return { value: totpCode(factor.secret), counter };
      }
      const initial = await startLogin('workforce', credentials.workforce);
      try {
        if (await initial.page.locator('#totpSecret').count()) {
          assert.ok(factor.status !== 'enrolled', 'Server factor unexpectedly reset; preserve retained evidence');
          await initial.page.locator('#mode-manual').click();
          const secret = (await initial.page.locator('#kc-totp-secret-key').innerText()).replace(/\s/g, '');
          factor = { status: 'pending-enrollment', secret, lastAcceptedCounter: -1 };
          await protectedJson(filename, factor);
          const code = await nextCode();
          factor.lastAttemptedCounter = code.counter;
          await protectedJson(filename, factor);
          await initial.page.locator('#totp').fill(code.value);
          await initial.page.locator('#userLabel').fill('Synthetic hosted TOTP');
          await initial.page.locator('#saveTOTPBtn').click();
          factor.lastAcceptedCounter = code.counter;
          enrolledNow = true;
        } else {
          assert.ok(factor.secret, 'Existing server factor has no preserved local test secret');
          await initial.page.locator('#otp').waitFor();
          const code = await nextCode();
          factor.lastAttemptedCounter = code.counter;
          await protectedJson(filename, factor);
          await initial.page.locator('#otp').fill(code.value);
          await initial.page.locator('#kc-login').click();
          factor.lastAcceptedCounter = code.counter;
        }
        const authenticated = await initial.finish();
        assert.equal(authenticated.claims.principal_kind, 'STAFF');
        assert.equal(authenticated.claims.tenant_id, 'synthetic-tenant');
        assert.match(authenticated.claims.staff_actor_id, /^[a-f0-9-]{36}$/);
        assert.equal(authenticated.claims.party_id, undefined);
        factor.status = 'enrolled';
        await protectedJson(filename, factor);
        passed(enrolledNow ? 'workforce real TOTP enrollment and signed STAFF identity' : 'workforce retained TOTP factor and signed STAFF identity');
      } finally { initial.cancel(); await initial.context.close(); }
      phase = 'workforce fresh browser challenge authentication';
      const challenge = await startLogin('workforce', credentials.workforce);
      try {
        phase = 'workforce fresh OTP challenge field';
        await challenge.page.locator('#otp').waitFor();
        const now = Date.now() / 1000;
        const validWindow = new Set([-30, 0, 30].map(offset => totpCode(factor.secret, now + offset)));
        let wrong = 0;
        while (validWindow.has(wrong.toString().padStart(6, '0'))) wrong++;
        phase = 'workforce wrong OTP submission';
        await challenge.page.locator('#otp').fill(wrong.toString().padStart(6, '0'));
        await challenge.page.locator('#kc-login').click();
        phase = 'workforce visible native OTP refusal without callback';
        await challenge.page.locator('#input-error-otp').waitFor({ state: 'visible' });
        assert.ok((await challenge.page.locator('#input-error-otp').innerText()).trim(), 'Native OTP error is empty');
        assert.equal(await challenge.page.locator('#otp').getAttribute('aria-invalid'), 'true', 'Wrong OTP was not marked invalid');
        assert.ok(!challenge.callbackReceived && !challenge.page.url().startsWith(REDIRECT), 'Invalid OTP reached callback');
        phase = 'workforce fresh valid factor generation';
        const code = await nextCode();
        factor.lastAttemptedCounter = code.counter;
        await protectedJson(filename, factor);
        phase = 'workforce valid OTP submission';
        await challenge.page.locator('#otp').fill(code.value);
        await challenge.page.locator('#kc-login').click();
        phase = 'workforce valid OTP signed code exchange';
        const result = await challenge.finish();
        assert.equal(result.claims.principal_kind, 'STAFF');
        assert.equal(result.claims.tenant_id, 'synthetic-tenant');
        assert.equal(result.claims.client_id, CLIENT);
        assert.match(result.claims.staff_actor_id, /^[a-f0-9-]{36}$/);
        assert.equal(result.claims.party_id, undefined);
        factor.lastAcceptedCounter = code.counter;
        await protectedJson(filename, factor);
        passed('fresh workforce MFA challenge refuses bad OTP and accepts valid factor before signed code exchange');
        await protectedProfile('workforce', credentials.workforce, challenge, result);
      } finally { challenge.cancel(); await challenge.context.close(); }
    }
    const evidence = resolve('.work/extended-runtime');
    await mkdir(evidence, { recursive: true });
    await writeFile(`${evidence}/summary.json`, JSON.stringify({ flows: selected, results,
      pending: ['verification token expiration', 'passkey enrollment and challenge', 'lost-factor and step-up recovery'],
      scope: 'Synthetic provider flows only; no production or business authorization acceptance.' }, null, 2));
  } catch (error) {
    reportFailure(error, phase);
    process.exitCode = 1;
  } finally {
    pending.clear();
    try {
      if (browser) await browser.close();
      if (server?.listening) await new Promise(ok => server.close(ok));
    } catch (error) { reportFailure(error, 'extended cleanup'); process.exitCode = 1; }
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await main();
