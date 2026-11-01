import assert from 'node:assert/strict';
import { createHash, createHmac, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { reportFailure } from './safe-errors.mjs';
import { selectNewRecoveryMessage } from './recovery-mail.mjs';
import { readAdminValidation } from './policy-runtime.mjs';
import { observeConsole } from './console-diagnostics.mjs';

const BASE = 'http://id.firefly.test:8180';
const REDIRECT = 'http://localhost:3000/oidc/callback';
const CLIENT = 'sandbox-web';
const delay = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));

export function extendedRouteClass(address) {
  if (address === 'about:blank') return 'ABOUT_BLANK';
  let url;
  try { url = new URL(address); } catch { return 'INVALID_URL'; }
  if (url.origin !== BASE) return 'OTHER_ORIGIN';
  if (url.pathname === '/admin/master/console/' || url.pathname === '/admin/master/console') return 'ADMIN_CONSOLE';
  if (url.pathname === '/realms/master/protocol/openid-connect/auth') return 'MASTER_AUTHORIZATION';
  if (url.pathname.startsWith('/realms/master/login-actions/')) return 'MASTER_LOGIN_ACTION';
  return 'OTHER_IDENTITY_ROUTE';
}

export function extendedFailureDiagnostics(error) {
  const result = { sourceFrames: String(error?.stack || '').split('\n').flatMap(line => {
    const frame = line.match(/tooling\/extended-runtime\.mjs:(\d{1,6}):(\d{1,5})/);
    return frame ? [`extended-runtime.mjs:${frame[1]}:${frame[2]}`] : [];
  }).slice(0, 4) };
  const allowed = new Set(['localhost', 'http://localhost:8180', 'required', 'preferred', 'discouraged', 'not specified', 'HS512', 'RS256']);
  for (const name of ['actual', 'expected']) {
    const value = error?.[name];
    const type = typeof value;
    result[`${name}Type`] = ['undefined', 'boolean', 'number', 'string', 'object'].includes(type) ? type : 'other';
    if (type === 'boolean' || (Number.isInteger(value) && value >= 0 && value <= 1000) || allowed.has(value)) result[name] = value;
  }
  return result;
}

export function verificationExpiryDelay(claims, now = Date.now()) {
  assert.ok(Number.isInteger(claims.iat) && Number.isInteger(claims.exp)
    && claims.exp > claims.iat && claims.exp - claims.iat <= 60, 'Unbounded verification expiry fixture');
  const wait = Math.max(0, claims.exp * 1000 + 2000 - now);
  assert.ok(Number.isFinite(wait) && wait <= 62000, 'Verification expiry exceeds the fixture deadline');
  return wait;
}

export function parseVerificationAction(compact, issuer, subject, now = Date.now()) {
  assert.match(issuer, /^http:\/\/localhost:8180\/realms\/sandbox-authenticators-[a-f0-9]{12}$/);
  assert.ok(typeof compact === 'string' && compact.length <= 16384 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(compact),
    'Bounded compact verification action required');
  const parts = compact.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(header.alg, 'HS512', 'Unexpected pinned internal action algorithm');
  assert.equal(header.typ, 'JWT');
  assert.equal(Buffer.from(parts[2], 'base64url').length, 64);
  assert.equal(claims.iss, issuer);
  assert.deepEqual([claims.aud].flat(), [issuer]);
  assert.equal(claims.sub, subject);
  assert.equal(claims.typ, 'verify-email');
  verificationExpiryDelay(claims, now);
  assert.ok(claims.exp * 1000 > now && claims.iat * 1000 <= now + 2000, 'Action is not currently within its parsed lifetime');
  // Internal HMAC keys stay on the server. These parsed claims guide the fixture; the confirmation page validates the original token.
  return claims;
}

export function authenticatorFixtureRealm(source, name, password) {
  assert.equal(source.realm, 'sandbox-customers', 'Only the generated synthetic customer source is permitted');
  assert.match(name, /^sandbox-authenticators-[a-f0-9]{12}$/);
  assert.ok(typeof password === 'string' && password.length >= 14, 'Fresh synthetic password required');
  const realm = structuredClone(source);
  delete realm.id;
  realm.realm = name;
  realm.displayName = 'Isolated authenticator fixture';
  realm.attributes = { frontendUrl: 'http://localhost:8180' };
  realm.clients = realm.clients.filter(client => client.clientId === CLIENT && client.publicClient === true);
  assert.equal(realm.clients.length, 1, 'Exact synthetic public client required');
  const flow = (alias, authenticators) => ({ alias, providerId: 'basic-flow', topLevel: true, builtIn: false,
    authenticationExecutions: authenticators.map((authenticator, index) => ({ authenticator,
      authenticatorFlow: false, requirement: 'REQUIRED', priority: 10 + index * 10 })) });
  realm.authenticationFlows = [flow('fixture-enrollment', ['auth-username-password-form']),
    flow('fixture-passkey', ['auth-username-form', 'webauthn-authenticator-passwordless'])];
  realm.browserFlow = 'fixture-enrollment';
  realm.requiredActions = [{ alias: 'webauthn-register-passwordless', providerId: 'webauthn-register-passwordless',
    name: 'WebAuthn passwordless registration', enabled: true, defaultAction: false, priority: 60 }];
  Object.assign(realm, { webAuthnPolicyPasswordlessRpEntityName: 'Isolated Firefly test RP',
    webAuthnPolicyPasswordlessRpId: 'localhost', webAuthnPolicyPasswordlessSignatureAlgorithms: ['ES256'],
    webAuthnPolicyPasswordlessAttestationConveyancePreference: 'none',
    webAuthnPolicyPasswordlessAuthenticatorAttachment: 'platform',
    webAuthnPolicyPasswordlessRequireResidentKey: 'Yes', webAuthnPolicyPasswordlessResidentKey: 'required',
    webAuthnPolicyPasswordlessUserVerificationRequirement: 'required',
    webAuthnPolicyPasswordlessCreateTimeout: 30, webAuthnPolicyPasswordlessExtraOrigins: [] });
  realm.users = [false, true].map(verified => ({ username: verified ? 'synthetic-passkey' : 'synthetic-expiry',
    email: `${verified ? 'passkey' : 'expiry'}-${name.slice(-12)}@example.invalid`,
    firstName: 'Synthetic', lastName: 'Authenticator', enabled: true, emailVerified: verified,
    attributes: { tenant_id: ['synthetic-tenant'], party_id: [randomUUID()] },
    requiredActions: [verified ? 'webauthn-register-passwordless' : 'VERIFY_EMAIL'],
    credentials: [{ type: 'password', value: password, temporary: false }],
    clientRoles: { account: ['manage-account', 'view-profile'] } }));
  return realm;
}

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

export async function validateJwt(compact, metadata, audience) {
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
  let ownedRealm;
  let adminValidation;
  let adminPage;
  let captureAdminDiagnostics;
  let adminInitialNavigation;
  const adminNavigation = [];
  const pending = new Map();
  try {
    const selected = (process.env.FIREFLY_ID_EXTENDED_FLOWS || 'verify,profile,mfa').split(',');
    assert.ok(selected.length > 0 && selected.every(name => ['verify', 'profile', 'mfa', 'verify-expiry', 'passkey'].includes(name)), 'Unknown extended flow');
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

    let adminAuthorization;
    async function adminRead(url) {
      if (!adminPage) {
        const callerPhase = phase;
        const context = await browser.newContext();
        adminPage = await context.newPage();
        adminPage.setDefaultTimeout(20000);
        captureAdminDiagnostics = observeConsole(adminPage);
        adminPage.on('response', response => {
          try {
            const req = response.request();
            if (req.isNavigationRequest() && req.frame() === adminPage.mainFrame() && adminNavigation.length < 8) {
              adminNavigation.push({ route: extendedRouteClass(response.url()), status: response.status() });
            }
          } catch { /* Detached navigation has no shareable location. */ }
        });
        const authenticated = adminPage.waitForResponse(async response => response.status() === 200
          && new URL(response.url()).pathname.startsWith('/admin/realms')
          && (await response.request().allHeaders()).authorization?.startsWith('Bearer '), { timeout: 40000 });
        authenticated.catch(() => {});
        phase = 'administrative console navigation';
        const navigation = await adminPage.goto(`${BASE}/admin/master/console/`);
        adminInitialNavigation = { status: navigation?.status() ?? null, route: extendedRouteClass(adminPage.url()) };
        assert.equal(adminInitialNavigation.status, 200, 'Initial administrative console HTTP response refused');
        phase = 'administrative username form';
        await adminPage.locator('#username').fill('sandbox-bootstrap');
        phase = 'administrative password form';
        await adminPage.locator('#password').fill((await readFile(`${stateDir}/secrets/admin-password`, 'utf8')).trim());
        phase = 'administrative authenticated response';
        await adminPage.locator('#kc-login').click();
        adminAuthorization = (await (await authenticated).request().allHeaders()).authorization;
        phase = callerPhase;
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

    async function fixtureWrite(name, suffix, body, create = false) {
      assert.match(name, /^sandbox-authenticators-[a-f0-9]{12}$/);
      assert.ok(create ? body.realm === name : ownedRealm === name, 'Only this run\'s isolated realm may change');
      await adminRead(`${BASE}/admin/realms/master`);
      const response = await request(`${BASE}/admin/realms${create ? '' : `/${name}${suffix}`}`, {
        method: create ? 'POST' : 'PUT', headers: { Authorization: adminAuthorization, 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (response.status !== (create ? 201 : 204)) adminValidation = await readAdminValidation(response);
      assert.equal(response.status, create ? 201 : 204, 'Owned authenticator fixture operation refused');
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
          if (await page.locator('#password').isVisible()) await page.locator('#password').fill(account.password);
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

    if (selected.some(name => ['verify-expiry', 'passkey'].includes(name))) {
      phase = 'owned hosted authenticator fixture admission';
      assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Authenticator fixtures run only in hosted CI');
      assert.equal(process.env.FIREFLY_ID_AUTHENTICATOR_FIXTURE, 'owned-hosted');
      const owner = JSON.parse(await readFile(`${stateDir}/ownership.json`, 'utf8'));
      assert.equal(owner.mode, 'sandbox');
      assert.equal(owner.created_by, 'firefly-id/scripts/generate.py');
      assert.match(owner.project, /^firefly-id-sandbox-[a-f0-9]{10}$/);
      const name = `sandbox-authenticators-${randomBytes(6).toString('hex')}`;
      const fixture = authenticatorFixtureRealm(JSON.parse(await readFile(`${stateDir}/realms/sandbox-customers-realm.json`, 'utf8')),
        name, `Aa1${randomBytes(36).toString('base64url')}`);
      phase = 'isolated realm import HTTP response';
      await fixtureWrite(name, '', fixture, true);
      ownedRealm = name;
      const realmApi = `${BASE}/admin/realms/${name}`;
      phase = 'isolated realm administrative readback HTTP response';
      const installed = await adminRead(realmApi);
      phase = 'isolated realm frontend origin readback';
      assert.equal(installed.attributes?.frontendUrl, 'http://localhost:8180');
      phase = 'isolated realm RP identifier readback';
      assert.equal(installed.webAuthnPolicyPasswordlessRpId, 'localhost');
      phase = 'isolated realm resident-key policy readback';
      assert.equal(installed.webAuthnPolicyPasswordlessResidentKey, 'required');
      phase = 'isolated realm user-verification policy readback';
      assert.equal(installed.webAuthnPolicyPasswordlessUserVerificationRequirement, 'required');
      const population = name.slice('sandbox-'.length);
      const issuer = `http://localhost:8180/realms/${name}`;
      phase = 'isolated realm discovery HTTP response';
      const metadata = await jsonRequest(`${issuer}/.well-known/openid-configuration`);
      phase = 'isolated realm discovery issuer readback';
      assert.equal(metadata.issuer, issuer);
      metadataCache.set(population, metadata);
      phase = 'isolated realm synthetic user readback';
      const users = await adminRead(`${realmApi}/users?max=10`);
      async function userFor(username) {
        const matches = users.filter(user => user.username === username);
        assert.equal(matches.length, 1, 'Exact owned synthetic account required');
        return matches[0];
      }
      async function verificationMail(user, lifespan) {
        const mailbox = await jsonRequest('http://localhost:8025/api/v1/messages');
        const prior = new Set((mailbox.messages || []).map(message => message.ID));
        await fixtureWrite(name, `/users/${user.id}/send-verify-email?lifespan=${lifespan}&client_id=${CLIENT}&redirect_uri=${encodeURIComponent(REDIRECT)}`);
        let message;
        for (let attempt = 0; attempt < 30; attempt++) {
          const current = await jsonRequest('http://localhost:8025/api/v1/messages');
          message = selectNewRecoveryMessage(current.messages || [], prior, user.email);
          if (message) break;
          await delay(250);
        }
        assert.ok(message, 'No fresh verification message for the owned recipient');
        const mail = await jsonRequest(`http://localhost:8025/api/v1/message/${message.ID}`);
        const matched = mail.HTML.match(/href="([^"\s]*\/login-actions\/action-token[^"\s]*)"/);
        assert.ok(matched, 'Signed verification action absent');
        const action = new URL(matched[1].replaceAll('&amp;', '&'));
        assert.equal(action.origin, 'http://localhost:8180');
        assert.equal(action.pathname, `/realms/${name}/login-actions/action-token`);
        return action;
      }

      if (selected.includes('verify-expiry')) {
        const user = await userFor('synthetic-expiry');
        const snapshot = async () => {
          const current = await adminRead(`${realmApi}/users/${user.id}`);
          return { emailVerified: current.emailVerified, requiredActions: current.requiredActions };
        };
        const original = await snapshot();
        assert.equal(original.emailVerified, false);
        assert.ok(original.requiredActions.includes('VERIFY_EMAIL'));
        phase = 'genuine verification email parsed internal profile and absolute expiry';
        const action = await verificationMail(user, 15);
        const compact = action.searchParams.get('key');
        const parsed = parseVerificationAction(compact, issuer, user.id);
        assert.ok(parsed.exp - parsed.iat >= 14 && parsed.exp - parsed.iat <= 15,
          'Server did not apply the requested bounded action lifetime');
        phase = 'server validates original action before expiry without completing verification';
        const beforeExpiry = await browser.newContext();
        let beforeCallback = false;
        try {
          const page = await beforeExpiry.newPage();
          page.on('request', req => { if (req.url().startsWith(REDIRECT)) beforeCallback = true; });
          assert.equal((await page.goto(action.href))?.status(), 200, 'Server refused the original action before expiry');
          await page.locator('#kc-info-message a[href*="/login-actions/action-token"]').waitFor();
          assert.ok(Date.now() / 1000 < parsed.exp, 'Pre-expiry validation did not finish before the original deadline');
          assert.ok(!beforeCallback && !page.url().startsWith(REDIRECT), 'Confirmation page completed authentication');
          assert.deepEqual(await snapshot(), original, 'Viewing confirmation completed verification or changed required actions');
        } finally { await beforeExpiry.close(); }
        passed('server validates the original signed verification action before expiry without verifying email or issuing a code');
        await delay(verificationExpiryDelay(parsed));
        assert.ok(Date.now() / 1000 > parsed.exp, 'Signed action is not yet expired');
        assert.equal(action.searchParams.get('key'), compact, 'Expiry probe changed the signed action');
        phase = 'expired unchanged verification link refusal and unchanged private state';
        const context = await browser.newContext();
        let callback = false;
        try {
          const page = await context.newPage();
          page.on('request', req => { if (req.url().startsWith(REDIRECT)) callback = true; });
          const response = await page.goto(action.href);
          assert.ok(response && response.status() >= 200 && response.status() < 500);
          const message = page.locator('#kc-info-message, #kc-error-message');
          await message.waitFor();
          assert.match(await message.innerText(), /expired|no longer valid/i, 'Expired signed link has no recognized expiry refusal');
          assert.ok(!callback && !page.url().startsWith(REDIRECT), 'Expired action issued a code');
          assert.deepEqual(await snapshot(), original, 'Expired action changed verification state or required actions');
        } finally { await context.close(); }
        passed('genuine signed verification action expires naturally without verification, required-action removal or login code');
        phase = 'fresh verification action succeeds after expired predecessor';
        const fresh = await verificationMail(user, 120);
        const positive = await browser.newContext();
        try {
          const page = await positive.newPage();
          await page.goto(fresh.href);
          const confirm = page.locator('#kc-info-message a[href*="/login-actions/action-token"]');
          if (await confirm.isVisible()) await confirm.click();
          await page.locator('#kc-info-message, #kc-error-message').waitFor();
          const verified = await snapshot();
          assert.equal(verified.emailVerified, true);
          assert.ok(!verified.requiredActions.includes('VERIFY_EMAIL'));
        } finally { await positive.close(); }
        passed('fresh server-issued verification action remains usable after an expired action');
      }

      if (selected.includes('passkey')) {
        const user = await userFor('synthetic-passkey');
        const account = { username: user.username, password: fixture.users.find(entry => entry.username === user.username).credentials[0].value };
        async function virtualAuthenticator(page, credential) {
          const session = await page.context().newCDPSession(page);
          await session.send('WebAuthn.enable', { enableUI: false });
          const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', { options: {
            protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
            hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
          } });
          if (credential) await session.send('WebAuthn.addCredential', { authenticatorId, credential });
          return { session, authenticatorId };
        }
        phase = 'actual platform passkey enrollment and signed PKCE exchange';
        const enrollment = await startLogin(population, account);
        let credential;
        try {
          await enrollment.page.locator('#registerWebAuthn').waitFor();
          assert.equal(await enrollment.page.evaluate(() => window.isSecureContext), true);
          const authenticator = await virtualAuthenticator(enrollment.page);
          enrollment.page.on('dialog', dialog => dialog.accept('Owned hosted passkey'));
          await enrollment.page.locator('#registerWebAuthn').click();
          const result = await enrollment.finish();
          assert.equal(result.claims.sub, user.id);
          const stored = await adminRead(`${realmApi}/users/${user.id}/credentials`);
          assert.equal(stored.filter(item => item.type === 'webauthn-passwordless').length, 1);
          const listed = await authenticator.session.send('WebAuthn.getCredentials', { authenticatorId: authenticator.authenticatorId });
          assert.equal(listed.credentials.length, 1);
          [credential] = listed.credentials;
          assert.equal(credential.rpId, 'localhost');
          assert.equal(credential.isResidentCredential, true);
          assert.ok(credential.privateKey && credential.userHandle, 'Browser did not create a resident key');
        } finally { enrollment.cancel(); await enrollment.context.close(); }
        passed('configured loopback RP, required user verification and resident platform passkey enroll through the real form and signed code exchange');
        phase = 'owned passwordless flow binding';
        await fixtureWrite(name, '', { browserFlow: 'fixture-passkey' });
        assert.equal((await adminRead(realmApi)).browserFlow, 'fixture-passkey');
        for (const bogus of [true, false]) {
          phase = bogus ? 'actual invalid WebAuthn signature refuses callback' : 'fresh passkey assertion and signed PKCE exchange';
          const existingSessions = bogus ? (await adminRead(`${realmApi}/users/${user.id}/sessions`)).map(session => session.id).sort() : [];
          const flow = await startLogin(population, { username: account.username });
          try {
            await flow.page.locator('#authenticateWebAuthnButton').waitFor();
            assert.equal(await flow.page.locator('#password').count(), 0, 'Password fallback appeared in the required passkey flow');
            const authenticator = await virtualAuthenticator(flow.page, credential);
            if (bogus) await authenticator.session.send('WebAuthn.setResponseOverrideBits', {
              authenticatorId: authenticator.authenticatorId, isBogusSignature: true });
            await flow.page.locator('#authenticateWebAuthnButton').click();
            if (bogus) {
              const feedback = flow.page.locator('#kc-error-message, .kc-feedback-text').first();
              await feedback.waitFor();
              assert.ok((await feedback.innerText()).trim(), 'WebAuthn refusal has no visible message');
              assert.ok(!flow.callbackReceived && !flow.page.url().startsWith(REDIRECT), 'Invalid WebAuthn signature issued a code');
              assert.deepEqual((await adminRead(`${realmApi}/users/${user.id}/sessions`)).map(session => session.id).sort(), existingSessions,
                'Invalid signature created an authenticated session');
              passed('real WebAuthn assertion with an invalid signature is refused without a login code');
            } else {
              const result = await flow.finish();
              assert.equal(result.claims.sub, user.id);
              const after = await authenticator.session.send('WebAuthn.getCredentials', { authenticatorId: authenticator.authenticatorId });
              assert.ok(after.credentials[0].signCount > credential.signCount, 'Fresh assertion did not advance authenticator signature count');
              passed('fresh browser passkey assertion without password or SSO completes signed PKCE exchange');
            }
          } finally { flow.cancel(); await flow.context.close(); }
        }
      }
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
    await writeFile(`${evidence}/summary.json`, JSON.stringify({ status: 'passed', flows: selected, results,
      pending: [...(selected.includes('verify-expiry') ? [] : ['verification token expiration']),
        ...(selected.includes('passkey') ? [] : ['passkey enrollment and challenge']),
        'physical or synced passkey authenticators and production RP trust', 'real-provider proofing',
        'workforce, administrator, passkey and external-store lost-factor recovery',
        'BPO verification and institution-specific policy', 'recovery codes and phishing-resistant step-up'],
      scope: 'Synthetic provider flows only; no production or business authorization acceptance.' }, null, 2));
  } catch (error) {
    reportFailure(error, phase);
    const evidence = resolve('.work/extended-runtime');
    await mkdir(evidence, { recursive: true });
    let administration;
    if (adminPage) {
      administration = { initialNavigation: adminInitialNavigation, navigation: adminNavigation,
        currentRoute: extendedRouteClass(adminPage.url()) };
      try {
        administration.markers = await adminPage.evaluate(() => ({
          usernamePresent: Boolean(document.querySelector('#username')),
          passwordPresent: Boolean(document.querySelector('#password')),
          loginSubmitPresent: Boolean(document.querySelector('#kc-login')),
          errorMessagePresent: Boolean(document.querySelector('#kc-error-message')),
          feedbackPresent: Boolean(document.querySelector('.kc-feedback-text')),
        }));
        await captureAdminDiagnostics(evidence, 'admin', { failure: false });
      } catch { administration.snapshotUnavailable = true; }
    }
    await writeFile(`${evidence}/summary.json`, JSON.stringify({ status: 'failed', phase, results,
      ...extendedFailureDiagnostics(error), ...(adminValidation ? { adminValidation } : {}),
      ...(administration ? { administration } : {}),
      scope: 'Fixed stage labels only; no raw mail, credentials, tokens, authenticator keys or browser traces.' }, null, 2));
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
