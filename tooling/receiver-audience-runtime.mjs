import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { reportFailure } from './safe-errors.mjs';

const base = 'http://id.firefly.test:8180';
const issuer = `${base}/realms/sandbox-customers`;
const resource = 'sandbox-api';
const directory = resolve('.work/receiver-audiences');
const request = (url, options = {}) => fetch(url, { ...options, signal: AbortSignal.timeout(15000) });

async function main() {
  let phase = 'receiver audience setup';
  let browser;
  const servers = [];
  const results = [];
  let sourceHead;
  let status = 'failed';
  try {
    sourceHead = process.env.GITHUB_SHA;
    assert.match(sourceHead || '', /^[a-f0-9]{40}$/, 'Exact hosted source revision required');
    await mkdir(directory, { recursive: true });
    const stateDir = resolve(process.env.FIREFLY_ID_STATE || '.state/sandbox');
    assert.equal((await stat(stateDir)).mode & 0o077, 0, 'Sandbox state must remain owner-only');
    const ownership = JSON.parse(await readFile(`${stateDir}/ownership.json`, 'utf8'));
    assert.equal(ownership.mode, 'sandbox');
    assert.equal(ownership.created_by, 'firefly-id/scripts/generate.py');
    assert.match(ownership.project, /^firefly-id-sandbox-[a-f0-9]{10}$/);
    const credentialFile = `${stateDir}/credentials.json`;
    assert.equal((await stat(credentialFile)).mode & 0o077, 0, 'Credentials must remain owner-only');
    const credentials = JSON.parse(await readFile(credentialFile, 'utf8'));
    assert.ok(credentials.customers.username && credentials.customers.password
      && credentials.customers.backend_client_secret, 'Protected interactive credentials required');
    const metadataResponse = await request(`${issuer}/.well-known/openid-configuration`);
    assert.equal(metadataResponse.status, 200);
    const metadata = await metadataResponse.json();
    assert.equal(metadata.issuer, issuer);
    for (const [name, suffix] of [['authorization_endpoint', 'auth'], ['token_endpoint', 'token'], ['jwks_uri', 'certs']]) {
      assert.equal(metadata[name], `${issuer}/protocol/openid-connect/${suffix}`, 'Unexpected provider endpoint');
    }
    const keyResponse = await request(metadata.jwks_uri);
    assert.equal(keyResponse.status, 200);
    const { keys } = await keyResponse.json();
    assert.ok(Array.isArray(keys));

    function verifiedClaims(token, expectedAudience) {
      assert.equal(typeof token, 'string', 'Signed JWT required');
      const parts = token.split('.');
      assert.equal(parts.length, 3, 'Compact signed JWT required');
      const [header, payload, signature] = parts;
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url'));
      assert.equal(decodedHeader.alg, 'RS256', 'Unexpected signing algorithm');
      assert.ok(typeof decodedHeader.kid === 'string' && decodedHeader.kid.length > 0);
      const key = keys.find(candidate => candidate.kid === decodedHeader.kid
        && candidate.use === 'sig' && candidate.kty === 'RSA'
        && (candidate.alg === undefined || candidate.alg === 'RS256'));
      assert.ok(key, 'Provider signing key missing');
      assert.ok(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`),
        createPublicKey({ key, format: 'jwk' }), Buffer.from(signature, 'base64url')), 'JWT signature refused');
      const claims = JSON.parse(Buffer.from(payload, 'base64url'));
      assert.equal(claims.iss, issuer, 'Unexpected token issuer');
      assert.ok(typeof claims.exp === 'number' && claims.exp > Date.now() / 1000, 'JWT expired or expiry missing');
      if (claims.nbf !== undefined) assert.ok(typeof claims.nbf === 'number' && claims.nbf <= Date.now() / 1000, 'JWT not yet valid');
      assert.ok(typeof claims.sub === 'string' && claims.sub.length > 0, 'JWT subject missing');
      const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      assert.ok(audiences.length > 0 && audiences.every(value => typeof value === 'string' && value.length > 0), 'JWT audience malformed');
      assert.ok(audiences.includes(expectedAudience), 'Expected receiver audience missing');
      return claims;
    }

    const { chromium } = await import('playwright');
    browser = await chromium.launch();
    for (const client of [{ name: 'sandbox-web', port: 3000 }, { name: 'sandbox-backend', port: 8081 }]) {
      phase = `${client.name} callback setup`;
      const redirect = `http://localhost:${client.port}/oidc/callback`;
      const state = randomBytes(24).toString('base64url');
      const nonce = randomBytes(24).toString('base64url');
      const verifier = randomBytes(48).toString('base64url');
      let callback;
      const server = createServer((incoming, outgoing) => {
        const url = new URL(incoming.url, redirect);
        const accepted = incoming.method === 'GET' && url.pathname === '/oidc/callback'
          && url.searchParams.get('state') === state;
        outgoing.writeHead(accepted ? 200 : 400, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
        outgoing.end('Synthetic audience callback. No credentials are displayed.');
        if (accepted && !callback) callback = url;
      });
      servers.push(server);
      await new Promise((ok, fail) => server.listen(client.port, '127.0.0.1', ok).once('error', fail));
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        page.setDefaultTimeout(20000);
        const authorization = new URL(metadata.authorization_endpoint);
        authorization.search = new URLSearchParams({ client_id: client.name, response_type: 'code',
          redirect_uri: redirect, scope: 'openid profile email', state, nonce,
          code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url') });
        phase = `${client.name} browser credential authentication`;
        await page.goto(authorization.href);
        await page.locator('#username').fill(credentials.customers.username);
        await page.locator('#password').fill(credentials.customers.password);
        await page.locator('#kc-login').click();
        await page.waitForURL(value => value.origin === new URL(redirect).origin && value.pathname === '/oidc/callback');
        assert.ok(callback?.searchParams.get('code') && !callback.searchParams.has('error'), 'Browser authentication refused');
        assert.equal(callback.searchParams.get('state'), state);
        phase = `${client.name} authorization code and PKCE exchange`;
        const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: client.name,
          redirect_uri: redirect, code: callback.searchParams.get('code'), code_verifier: verifier });
        if (client.name === 'sandbox-backend') body.set('client_secret', credentials.customers.backend_client_secret);
        const exchange = await request(metadata.token_endpoint, { method: 'POST', body });
        assert.equal(exchange.status, 200, 'Interactive code exchange refused');
        const tokens = await exchange.json();
        phase = `${client.name} signed identity and access token validation`;
        const identity = verifiedClaims(tokens.id_token, client.name);
        assert.equal(identity.nonce, nonce, 'Unexpected identity nonce');
        const access = verifiedClaims(tokens.access_token, resource);
        assert.equal(access.azp, client.name, 'Unexpected authorized client');
        assert.equal(access.sub, identity.sub, 'Identity and access subject differ');
        const audiences = Array.isArray(access.aud) ? access.aud : [access.aud];
        const shape = { client: client.name, audienceType: Array.isArray(access.aud) ? 'array' : 'string',
          audienceCount: audiences.length, resourcePresent: audiences.includes(resource), accountPresent: audiences.includes('account') };
        results.push(shape);
        console.log(`Receiver audience shape: ${JSON.stringify(shape)}`);
      } finally { await context.close(); }
    }
    status = 'passed';
  } catch (error) {
    reportFailure(error, phase);
    process.exitCode = 1;
  } finally {
    try { if (browser) await browser.close(); } catch (error) { reportFailure(error, 'receiver audience browser cleanup'); process.exitCode = 1; status = 'failed'; }
    for (const server of servers) {
      try {
        if (server.listening) await new Promise((ok, fail) => {
          server.close(error => error ? fail(error) : ok());
          server.closeAllConnections();
        });
      } catch (error) { reportFailure(error, 'receiver audience callback cleanup'); process.exitCode = 1; status = 'failed'; }
    }
    if (/^[a-f0-9]{40}$/.test(sourceHead || '')) {
      await mkdir(directory, { recursive: true });
      await writeFile(`${directory}/summary.json`, JSON.stringify({ schemaVersion: 1, sourceHead, status, results }, null, 2) + '\n');
    }
  }
}

main().catch(error => { reportFailure(error, 'receiver audience evidence persistence'); process.exitCode = 1; });
