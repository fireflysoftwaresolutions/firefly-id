import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { reportFailure } from './safe-errors.mjs';

const state = resolve('.state/sandbox');
const evidence = resolve('.work/configuration-lookup');
let phase = 'optional service client ownership';
try {
  const owner = JSON.parse(await readFile(`${state}/ownership.json`, 'utf8'));
  const compose = await readFile(`${state}/compose.json`);
  assert.equal(owner.mode, 'sandbox');
  assert.equal(owner.created_by, 'firefly-id/scripts/generate.py');
  assert.match(owner.project, /^firefly-id-sandbox-[a-f0-9]{10}$/);
  assert.equal(owner.compose_sha256, createHash('sha256').update(compose).digest('hex'));
  const configured = JSON.parse(await readFile(`${state}/configuration-lookup-client.json`, 'utf8'));
  assert.match(configured.issuer, /^http:\/\/id\.firefly\.test:8180\/realms\/sandbox-(customers|workforce|institutions)$/);
  assert.equal(configured.secret_file, 'secrets/configuration-lookup-client-secret');
  const secret = (await readFile(`${state}/${configured.secret_file}`, 'utf8')).trim();
  const discovery = await (await fetch(`${configured.issuer}/.well-known/openid-configuration`, { redirect: 'error' })).json();
  assert.equal(discovery.issuer, configured.issuer);
  assert.equal(discovery.token_endpoint, configured.token_endpoint);
  assert.equal(discovery.jwks_uri, configured.jwks_uri);
  const grant = (endpoint, values, credential = secret) => fetch(endpoint, { method: 'POST', redirect: 'error',
    headers: { Authorization: `Basic ${Buffer.from(`${configured.client_id}:${credential}`).toString('base64')}` },
    body: new URLSearchParams(values), signal: AbortSignal.timeout(10000) });
  phase = 'actual client credentials issuance';
  const response = await grant(discovery.token_endpoint, { grant_type: 'client_credentials' });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.token_type.toLowerCase(), 'bearer');
  assert.equal(Object.hasOwn(result, 'refresh_token'), false);
  const parts = result.access_token.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  assert.equal(header.alg, 'RS256');
  const jwks = await (await fetch(discovery.jwks_uri, { redirect: 'error' })).json();
  const keys = jwks.keys.filter(key => key.kid === header.kid && key.kty === 'RSA' && key.use === 'sig');
  assert.equal(keys.length, 1);
  assert.ok(verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`),
    createPublicKey({ key: keys[0], format: 'jwk' }), Buffer.from(parts[2], 'base64url')));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(claims.iss, configured.issuer);
  assert.ok(typeof claims.sub === 'string' && claims.sub.length > 0 && claims.sub.length <= 255);
  assert.equal(claims.tenant_id, configured.tenant_id);
  assert.equal(claims.client_id, configured.client_id);
  assert.equal(claims.principal_kind, 'MACHINE');
  assert.ok(!Object.hasOwn(claims, 'party_id') && !Object.hasOwn(claims, 'staff_actor_id'));
  const audiences = [claims.aud].flat();
  assert.ok(audiences.every(value => typeof value === 'string') && audiences.includes(configured.audience));
  assert.ok(typeof claims.exp === 'number' && claims.exp > Date.now() / 1000);
  if (Object.hasOwn(claims, 'nbf')) assert.ok(typeof claims.nbf === 'number' && claims.nbf <= Date.now() / 1000);
  phase = 'service grant restrictions';
  const wrongCredential = await grant(discovery.token_endpoint, { grant_type: 'client_credentials' }, `${secret}-invalid`);
  assert.ok([400, 401].includes(wrongCredential.status));
  assert.equal(Object.hasOwn(await wrongCredential.json(), 'access_token'), false);
  const interactive = await grant(discovery.token_endpoint, { grant_type: 'password', username: 'not-a-human', password: 'invalid' });
  assert.ok([400, 401].includes(interactive.status));
  assert.equal(Object.hasOwn(await interactive.json(), 'access_token'), false);
  const otherRealm = configured.issuer.endsWith('sandbox-workforce') ? 'sandbox-customers' : 'sandbox-workforce';
  const crossRealm = await grant(`http://id.firefly.test:8180/realms/${otherRealm}/protocol/openid-connect/token`, { grant_type: 'client_credentials' });
  assert.ok([400, 401].includes(crossRealm.status));
  assert.equal(Object.hasOwn(await crossRealm.json(), 'access_token'), false);
  await mkdir(evidence, { recursive: true });
  await writeFile(`${state}/configuration-lookup-token.txt`, result.access_token, { mode: 0o600 });
  await writeFile(`${evidence}/metadata.json`, JSON.stringify({
    status: 'native-issuance-verified', issuer: claims.iss, subject: claims.sub, tenant_id: claims.tenant_id,
    client_id: claims.client_id, principal_kind: claims.principal_kind, audiences,
    discovery_endpoint: `${configured.issuer}/.well-known/openid-configuration`,
    token_endpoint: discovery.token_endpoint, jwks_uri: discovery.jwks_uri,
    scopes: typeof claims.scope === 'string' ? claims.scope.split(/\s+/).filter(Boolean) : [],
    credential_reference: 'secrets/configuration-lookup-client-secret',
    checks: ['live-key-signature', 'issuer-audience-tenant', 'actual-opaque-service-subject',
      'no-human-links', 'wrong-secret-refused', 'password-grant-refused', 'cross-realm-refused'],
    scope: 'Fresh synthetic client issuance only; no Configuration lookup or business authorization is granted.'
  }, null, 2));
  console.log('PASS optional service issuance and grant isolation; no credential or token output');
} catch (error) {
  reportFailure(error, phase);
  process.exitCode = 1;
}
