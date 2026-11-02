import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { assertionProperties, privilegedWriteDiagnostic } from './privileged-runtime.mjs';
import { validateJwt } from './extended-runtime.mjs';
import { prepareMasterActions, qualifyMasterActions } from './master-action-links.mjs';
import { isMasterCallback, masterCallbackObserver, masterRouteClass } from './master-callback.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ORIGIN = 'https://id.firefly.test:8443';
const ISSUER = ORIGIN + '/realms/master';
const CALLBACK = ORIGIN + '/admin/master/console/fixture-return';
const CLIENT = 'security-admin-console';
const BROWSER = 'firefly-privileged-browser-v1';
const DENY = 'firefly-privileged-deny-v1';
const WEBAUTHN_POLICY_KEYS = Object.freeze(['webAuthnPolicy', 'webAuthnPolicyPasswordless'].flatMap(prefix => [
  'RpEntityName', 'SignatureAlgorithms', 'RpId', 'AttestationConveyancePreference', 'AuthenticatorAttachment',
  'RequireResidentKey', 'ResidentKey', 'UserVerificationRequirement', 'CreateTimeout', 'AvoidSameAuthenticatorRegister',
  'AcceptableAaguids', 'ExtraOrigins'].map(field => prefix + field))
  .concat(['webAuthnPolicyPasswordlessPasskeysEnabled', 'webAuthnPolicyPasswordlessMediation']));
const NULLABLE_WEBAUTHN_POLICY_KEYS = new Set(['webAuthnPolicyPasswordlessMediation']);
export const CONTROL_KEYS = Object.freeze(['attributes', 'registrationAllowed', 'resetPasswordAllowed', 'rememberMe', 'registrationEmailAsUsername',
  'editUsernameAllowed', 'verifyEmail', 'browserFlow', 'directGrantFlow', 'registrationFlow', 'resetCredentialsFlow',
  'dockerAuthenticationFlow', 'firstBrokerLoginFlow', 'authenticationFlows', 'requiredActions', ...WEBAUTHN_POLICY_KEYS,
  'eventsEnabled', 'adminEventsEnabled', 'adminEventsDetailsEnabled']);

export function ownedRuntime(root, env, owner) {
  assert.ok(env.GITHUB_ACTIONS === 'true' && env.RUNNER_OS === 'Linux' && env.RUNNER_ENVIRONMENT === 'github-hosted');
  const run = env.GITHUB_RUN_ID + '-' + env.GITHUB_RUN_ATTEMPT;
  assert.match(run, /^\d+-\d+$/);
  const directory = root + '/.state/master-' + run;
  assert.deepEqual([owner.run, owner.root, owner.kind, owner.project, owner.phase],
    [run, directory, 'master-transition', 'ff-master-' + run, 'enrollment']);
  return directory;
}

export function retainedOperations(candidate) {
  assert.ok(CONTROL_KEYS.every(key => Object.hasOwn(candidate, key) || NULLABLE_WEBAUTHN_POLICY_KEYS.has(key)),
    'Complete generated security controls required');
  // The update API replaces each complete WebAuthn block only when its RP entity name is nonempty.
  for (const key of ['webAuthnPolicyRpEntityName', 'webAuthnPolicyPasswordlessRpEntityName']) {
    assert.ok(typeof candidate[key] === 'string' && candidate[key].trim().length > 0, 'Candidate RP entity name required');
  }
  const flows = candidate.authenticationFlows.filter(item => [BROWSER, DENY].includes(item.alias));
  assert.equal(flows.length, 2);
  assert.ok(flows.every(item => item.providerId === 'basic-flow' && item.topLevel === true && item.builtIn === false));
  // Native passwordless mediation defaults to null and NON_NULL export omits it; omission preserves that builder default.
  const realm = Object.fromEntries(CONTROL_KEYS.filter(key => !['authenticationFlows', 'requiredActions'].includes(key) && Object.hasOwn(candidate, key))
    .map(key => [key, candidate[key]]));
  assert.equal(realm.browserFlow, BROWSER);
  return { realm, flows, actions: candidate.requiredActions };
}

export function retainedControlDiagnostic(candidate) {
  const missingFields = CONTROL_KEYS.filter(key => !Object.hasOwn(candidate, key));
  return { missingFields, missingRequiredFields: missingFields.filter(key => !NULLABLE_WEBAUTHN_POLICY_KEYS.has(key)),
    invalidRpNames: ['webAuthnPolicyRpEntityName', 'webAuthnPolicyPasswordlessRpEntityName']
      .filter(key => typeof candidate[key] !== 'string' || candidate[key].trim().length === 0),
    passwordlessMediation: !Object.hasOwn(candidate, 'webAuthnPolicyPasswordlessMediation') ? 'ABSENT'
      : candidate.webAuthnPolicyPasswordlessMediation === null ? 'NULL' : 'PRESENT' };
}

const RETRYABLE_SOCKET_CODES = new Set(['UND_ERR_SOCKET', 'ECONNRESET', 'EPIPE']);
const TRANSPORT_CODES = new Set([...RETRYABLE_SOCKET_CODES, 'ECONNREFUSED', 'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN',
  'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID']);
const transportCode = error => TRANSPORT_CODES.has(error?.cause?.code) ? error.cause.code : 'OTHER';

export async function retiredAccessRequest(request, bearer, onAttempt = () => {}) {
  const options = { method: 'GET', headers: { Authorization: 'Bearer ' + bearer }, signal: AbortSignal.timeout(30000) };
  for (let attempt = 1; attempt <= 2; attempt++) {
    options.signal.throwIfAborted();
    let response;
    try {
      response = await request(ORIGIN + '/admin/realms/master', options);
    } catch (error) {
      const code = transportCode(error);
      onAttempt({ attempt, outcome: 'TRANSPORT_FAILURE', transportCode: code });
      if (attempt === 2 || error?.name !== 'TypeError' || !RETRYABLE_SOCKET_CODES.has(code)) throw error;
      // Let closed pooled sockets be observed after the synchronous owned-server restart.
      await new Promise(resolve => setImmediate(resolve));
      continue;
    }
    onAttempt({ attempt, outcome: 'HTTP_RESPONSE', status: response.status });
    return response;
  }
}

export function safeRuntimeFailure(error) {
  const names = new Set(['TimeoutError', 'AssertionError', 'TypeError', 'RangeError', 'SyntaxError', 'Error']);
  const frames = String(error?.stack || '').split('\n').flatMap(line => {
    const matched = line.match(/tooling\/(master-transition-runtime|master-action-links)\.mjs:(\d{1,6}):(\d{1,5})/);
    return matched ? [matched[1] + '.mjs:' + matched[2] + ':' + matched[3]] : [];
  }).slice(0, 6);
  return { errorKind: names.has(error?.name) ? error.name : 'OTHER', sourceFrames: frames,
    ...(error?.cause ? { transportCode: transportCode(error) } : {}) };
}

export function classifyAuthenticationMessage(value) {
  const known = [
    ['Passkey registration result is invalid.', 'WEBAUTHN_REGISTRATION_VERIFICATION'],
    ['Failed to register your Passkey.', 'WEBAUTHN_REGISTRATION'],
    ['Passkey origin mismatch.', 'WEBAUTHN_ORIGIN'], ['Passkey RP ID mismatch.', 'WEBAUTHN_RPID'],
    ['Passkey challenge mismatch or expired.', 'WEBAUTHN_CHALLENGE'], ['Passkey signature verification failed.', 'WEBAUTHN_SIGNATURE'],
    ['User verification is required.', 'WEBAUTHN_UV'], ['User presence is required.', 'WEBAUTHN_PRESENCE'],
    ['The Passkey operation was not allowed or timed out.', 'WEBAUTHN_NOT_ALLOWED'],
    ['A security error occurred during the Passkey operation.', 'WEBAUTHN_BROWSER_SECURITY'],
    ['Your organization requires a different type of security key', 'WEBAUTHN_ATTACHMENT'],
    ['This security key model is not allowed', 'WEBAUTHN_AAGUID'], ['Your organization requires verified security keys.', 'WEBAUTHN_ATTESTATION'],
    ['This Passkey is already registered.', 'WEBAUTHN_DUPLICATE'], ['Device already exists with the same name.', 'WEBAUTHN_DUPLICATE_LABEL'],
    ['Invalid redirect uri', 'INVALID_REDIRECT'], ['Invalid requester', 'INVALID_REQUESTER'], ['Invalid Request', 'INVALID_REQUEST'],
    ['Restart login cookie not found.', 'COOKIE_NOT_FOUND'], ['Login timeout.', 'EXPIRED_CODE'],
    ['An error occurred, please login again through your application.', 'INVALID_CODE'],
    ['Account is disabled, contact your administrator.', 'ACCOUNT_DISABLED'],
    ['An internal server error has occurred', 'INTERNAL_SERVER_ERROR'], ['Unexpected server error', 'INTERNAL_SERVER_ERROR'],
  ];
  return known.find(([prefix]) => typeof value === 'string' && value.includes(prefix))?.[1] || 'UNCLASSIFIED';
}

export function registrationSubmissionDiagnostic(post, origin, status) {
  const data = new URLSearchParams(post || '');
  const value = data.get('error') || '';
  const errors = ['NotAllowedError', 'SecurityError', 'InvalidStateError', 'NotSupportedError', 'AbortError', 'ConstraintError'];
  return { status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
    origin: origin === ORIGIN ? 'OWNED' : origin === 'null' ? 'NULL' : origin ? 'OTHER' : 'ABSENT',
    browserError: value ? errors.find(name => value.startsWith(name)) || 'OTHER' : null,
    attestationPresent: !!data.get('attestationObject'), clientDataPresent: !!data.get('clientDataJSON'),
    credentialIdPresent: !!data.get('publicKeyCredentialId') };
}

export async function submitMasterRegistration(page) {
  // Native registration installs its once-only handler in a deferred module after the button becomes visible.
  await page.waitForLoadState('domcontentloaded', { timeout: 25000 });
  await page.locator('#registerWebAuthn').click({ timeout: 25000 });
}

export function componentDiagnostic(component) {
  const kinds = new Map([['org.keycloak.keys.KeyProvider', 'KEYS'],
    ['org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', 'CLIENT_REGISTRATION'],
    ['org.keycloak.userprofile.UserProfileProvider', 'USER_PROFILE'], ['org.keycloak.storage.UserStorageProvider', 'USER_STORAGE']]);
  const providers = new Set(['declarative-user-profile', 'rsa-generated', 'hmac-generated', 'aes-generated', 'ecdsa-generated',
    'trusted-hosts', 'consent-required', 'scope', 'max-clients', 'allowed-protocol-mappers', 'allowed-client-templates',
    'registration-web-origins', 'ldap', 'kerberos']);
  const keys = Object.keys(component.config || {});
  return { kind: kinds.get(component.providerType) || 'OTHER', provider: providers.has(component.providerId) ? component.providerId : 'OTHER',
    configuration: keys.length === 0 ? 'EMPTY' : keys.length === 1 && keys[0] === 'kc.user.profile.config' ? 'USER_PROFILE_JSON' : 'OTHER',
    nested: !!component.subComponents && Object.keys(component.subComponents).length > 0 };
}

export function preparedClientAttributes(client) {
  assert.ok(['account', 'account-console', 'admin-cli', 'broker', CLIENT].includes(client.clientId));
  const attributes = { ...client.attributes, 'client.use.lightweight.access.token.enabled': 'false' };
  if (client.clientId === CLIENT) attributes['pkce.code.challenge.method'] = 'S256';
  return attributes;
}

export async function retireOfflineScope(admin) {
  const scopes = await admin('client-scopes');
  const offline = scopes.filter(scope => scope.name === 'offline_access');
  assert.equal(offline.length, 1); assert.ok(scopes.length > 1);
  assert.match(offline[0].id, /^[A-Za-z0-9-]+$/);
  const path = 'client-scopes/' + offline[0].id;
  const definition = await admin(path);
  assert.equal(definition.id, offline[0].id); assert.equal(definition.name, 'offline_access');
  assert.equal(definition.protocol, 'openid-connect');
  const mappings = await admin(path + '/scope-mappings');
  assert.equal(Object.keys(mappings.clientMappings || {}).length, 0, 'Unreviewed offline client-role mappings');
  const roles = mappings.realmMappings || [];
  assert.ok(Array.isArray(roles) && roles.every(role => role.clientRole === false && typeof role.id === 'string'));
  // Deletion clears all assignments; preserving the scope prevents import from recreating its role with a new ID.
  await admin(path, 'DELETE');
  await admin('client-scopes', 'POST', definition);
  assert.deepEqual(await admin(path), definition, 'Offline scope definition changed');
  if (roles.length) await admin(path + '/scope-mappings/realm', 'POST', roles);
  // Cached client-scope ID lists can resolve the recreated ID until the realm cache is cleared.
  await admin('clear-realm-cache', 'POST');
  assert.deepEqual(await admin(path), definition, 'Offline scope definition changed after cache refresh');
  const ordered = values => [...values].sort((left, right) => left.id.localeCompare(right.id));
  assert.deepEqual(ordered(await admin(path + '/scope-mappings/realm')), ordered(roles), 'Offline scope role identities changed');
  const restoredMappings = await admin(path + '/scope-mappings');
  assert.equal(Object.keys(restoredMappings.clientMappings || {}).length, 0, 'Offline scope gained client-role mappings');
  assert.deepEqual(ordered(restoredMappings.realmMappings || []), ordered(roles), 'Offline scope mapping inventory changed');
  const retained = (await admin('client-scopes')).filter(scope => scope.name === 'offline_access');
  assert.equal(retained.length, 1); assert.equal(retained[0].id, definition.id);
  for (const defaults of ['default-default-client-scopes', 'default-optional-client-scopes']) {
    assert.ok(!(await admin(defaults)).some(scope => scope.id === definition.id || scope.name === 'offline_access'),
      'Offline scope remains a realm default');
  }
}

export function clientAttributeDiagnostic(clientId, requested, actual) {
  const known = new Set(['realm_client', 'pkce.code.challenge.method', 'client.use.lightweight.access.token.enabled',
    'post.logout.redirect.uris', 'backchannel.logout.session.required', 'backchannel.logout.revoke.offline.tokens',
    'oauth2.device.authorization.grant.enabled', 'oidc.ciba.grant.enabled', 'standard.token.exchange.enabled',
    'oauth2.token.exchange.grant.enabled', 'use.refresh.tokens', 'client.secret.creation.time',
    'client.secret.rotation.enabled', 'client.secret.expiration.time', 'client.secret.rotated',
    'client.secret.rotated.creation.time', 'client.secret.rotated.expiration.time', 'client.secret.remaining.expiration.time',
    'client.secret.authentication.allowed.method']);
  const expected = Object.fromEntries(Object.entries(requested).filter(([, value]) => value !== null));
  const effective = actual && typeof actual === 'object' && !Array.isArray(actual) ? actual : {};
  const classify = (key, value, present) => !present ? 'ABSENT' : value === 'true' ? 'TRUE' : value === 'false' ? 'FALSE'
    : key === 'pkce.code.challenge.method' && value === 'S256' ? 'S256'
      : key === 'post.logout.redirect.uris' && value === '+' ? 'PLUS' : 'OTHER';
  const unknownExpected = Object.keys(expected).filter(key => !known.has(key));
  const unknownActual = Object.keys(effective).filter(key => !known.has(key));
  return { clientId: ['account', 'account-console', 'admin-cli', 'broker', CLIENT, 'master-realm'].includes(clientId) ? clientId : 'OTHER',
    actualObject: actual !== null && typeof actual === 'object' && !Array.isArray(actual),
    attributes: [...known].filter(key => Object.hasOwn(requested, key) || Object.hasOwn(effective, key)).sort().map(key => {
      const expectedPresent = Object.hasOwn(expected, key); const actualPresent = Object.hasOwn(effective, key);
      return { key, expectedPresent, actualPresent, matches: expectedPresent === actualPresent && expected[key] === effective[key],
        expectedClass: classify(key, expected[key], expectedPresent), actualClass: classify(key, effective[key], actualPresent) };
    }), unknownExpectedCount: Math.min(unknownExpected.length, 10000), unknownActualCount: Math.min(unknownActual.length, 10000),
    unknownValuesMatch: unknownExpected.length === unknownActual.length
      && unknownExpected.every(key => Object.hasOwn(effective, key) && expected[key] === effective[key]) };
}

export function verifyPreparedClientReadback(initial, effective, requested, window) {
  const expected = Object.fromEntries(Object.entries(requested).filter(([, value]) => value !== null));
  const creation = 'client.secret.creation.time';
  const generated = !Object.hasOwn(expected, creation) && Object.hasOwn(effective.attributes || {}, creation);
  if (generated) {
    // RepresentationToModel.determineNewSecret initializes a nonpublic client's missing secret during PUT.
    assert.equal(initial.clientId, 'broker'); assert.equal(effective.clientId, 'broker');
    assert.equal(initial.publicClient, false); assert.equal(initial.bearerOnly, true); assert.ok(initial.secret == null);
    assert.ok(!Object.hasOwn(initial.attributes || {}, creation));
    assert.equal(effective.publicClient, false); assert.equal(effective.bearerOnly, true); assert.equal(effective.protocol, 'openid-connect');
    for (const flag of ['enabled', 'standardFlowEnabled', 'implicitFlowEnabled', 'directAccessGrantsEnabled', 'serviceAccountsEnabled']) {
      assert.equal(effective[flag], false);
    }
    assert.ok(effective.authorizationServicesEnabled === undefined || effective.authorizationServicesEnabled === false);
    assert.ok(Number.isInteger(window.minimum) && Number.isInteger(window.maximum)
      && window.minimum > 0 && window.maximum >= window.minimum && window.maximum - window.minimum <= 31);
    const timestamp = effective.attributes[creation];
    assert.equal(typeof timestamp, 'string'); assert.match(timestamp, /^[1-9][0-9]{0,9}$/);
    assert.ok(Number(timestamp) >= window.minimum && Number(timestamp) <= window.maximum && Number(timestamp) <= 2147483647);
    expected[creation] = timestamp;
  }
  assert.deepEqual(effective.attributes, expected, 'Prepared client attribute readback differs');
  return generated;
}

async function qualify() {
  const directory = ROOT + '/.state/master-' + process.env.GITHUB_RUN_ID + '-' + process.env.GITHUB_RUN_ATTEMPT;
  assert.equal(realpathSync(directory), directory);
  const owner = JSON.parse(readFileSync(directory + '/ownership.json'));
  ownedRuntime(ROOT, process.env, owner);
  const evidence = ROOT + '/.work/master-transition'; mkdirSync(evidence, { recursive: true });
  const report = { status: 'RUNNING', source: process.env.GITHUB_SHA, results: [],
    boundaries: { import: 'Exact candidate into a new empty owned database; never an overwrite of retained master.',
      transition: 'Generated settings applied to the original owned master without realm replacement.',
      pendingActionLinks: 'PENDING: genuine server-issued links and preaccepted action forms require observed runtime evidence.',
      consoleRendering: 'NOT_QUALIFIED: callback request observation and real PKCE exchange do not validate console UI rendering.',
      leastPrivilege: 'NOT_QUALIFIED: both synthetic accounts hold master admin only to exercise migration and emergency factor enforcement.',
      physicalKeyCustody: 'NOT_QUALIFIED: Chromium virtual authenticator; no physical custody or institutional activation.' } };
  let stage = 'ownership';
  let browser;
  const save = () => writeFileSync(evidence + '/summary.json', JSON.stringify({ ...report, stage }, null, 2) + '\n');
  const pass = name => { report.results.push(name); save(); };
  const lifecycle = (action, input) => {
    const result = spawnSync('python3', [ROOT + '/tooling/master_transition_fixture.py', action], {
      cwd: ROOT, input: input === undefined ? undefined : JSON.stringify(input), encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 240000 });
    assert.equal(result.status, 0, 'Owned lifecycle operation refused');
    return result.stdout.trim() ? JSON.parse(result.stdout) : undefined;
  };
  lifecycle('check');
  const credentials = JSON.parse(readFileSync(directory + '/credentials.json'));
  let token;
  const request = async (url, options) => {
    const parsed = new URL(url);
    assert.equal(parsed.origin, ORIGIN); assert.ok(!parsed.username && !parsed.password);
    return fetch(url, { signal: AbortSignal.timeout(30000), ...options, redirect: 'manual' });
  };
  const admin = async (suffix = '', method = 'GET', body, bearer = token) => {
    assert.ok(!suffix.startsWith('/') && !suffix.includes('..') && !suffix.includes('\\'));
    const response = await request(ORIGIN + '/admin/realms/master' + (suffix ? '/' + suffix : ''), {
      method, headers: { Authorization: 'Bearer ' + bearer, 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (![200, 201, 204].includes(response.status)) {
      const failure = new Error('Owned administrative operation refused');
      failure.diagnostic = await privilegedWriteDiagnostic(response, { body, clientId: body?.clientId,
        operation: suffix.startsWith('clients/') ? 'CLIENT_UPDATE' : suffix.startsWith('authentication/required-actions/')
          ? 'REQUIRED_ACTION_UPDATE' : 'REALM_UPDATE' });
      throw failure;
    }
    return response.status === 200 ? response.json() : undefined;
  };
  let metadata;
  const contexts = new Set();
  const navigation = [];
  const virtual = async (page, credential, scenario) => {
    const session = await page.context().newCDPSession(page);
    await session.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: false,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    if (credential) await session.send('WebAuthn.addCredential', { authenticatorId, credential });
    if (scenario === 'missing-uv') await session.send('WebAuthn.setResponseOverrideBits', { authenticatorId, isBadUV: true });
    return { session, authenticatorId };
  };
  const startLogin = async (username, password, context, expectPassword = true) => {
    if (!context) { context = await browser.newContext(); contexts.add(context); }
    const page = await context.newPage(); page.setDefaultTimeout(25000);
    const state = randomBytes(24).toString('base64url'); const nonce = randomBytes(24).toString('base64url');
    const verifier = randomBytes(48).toString('base64url');
    let received; let complete;
    const returned = new Promise(ok => { complete = ok; });
    page.on('response', response => {
      if (!response.request().isNavigationRequest() || navigation.length >= 24) return;
      const location = response.headers().location;
      navigation.push({ status: response.status(), route: masterRouteClass(response.url()),
        ...(location ? { redirect: masterRouteClass(new URL(location, response.url())) } : {}) });
    });
    // Request observation includes redirect destinations that Playwright routing does not intercept.
    const observeCallback = masterCallbackObserver(state, value => { received = value; complete(value); });
    page.on('request', request => observeCallback(request.url()));
    await page.route(isMasterCallback, async route => {
      await route.fulfill({ contentType: 'text/plain', body: 'Owned synthetic callback.' });
    });
    const url = new URL(metadata.authorization_endpoint);
    url.search = new URLSearchParams({ client_id: CLIENT, redirect_uri: CALLBACK, response_type: 'code', scope: 'openid',
      state, nonce, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url') });
    const loginStage = stage;
    stage = loginStage + '-authorization-navigation'; save();
    await page.goto(url.href);
    if (expectPassword) {
      stage = loginStage + '-password-form'; save();
      await page.locator('#password').waitFor(); assert.ok(!received, 'Cookie bypassed required password');
      if (await page.locator('#username').isVisible()) await page.locator('#username').fill(username);
      await page.locator('#password').fill(password); stage = loginStage + '-password-submit'; save();
      await page.locator('#kc-login').click();
    }
    return { page, context, get received() { return received; }, async finish() {
      stage = loginStage + '-callback-wait'; save();
      const value = await Promise.race([returned, new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error('Owned callback deadline')), 40000); timer.unref(); })]);
      assert.ok(!value.searchParams.has('error') && value.searchParams.getAll('code').length === 1);
      if (value.searchParams.has('iss')) assert.equal(value.searchParams.get('iss'), ISSUER);
      const response = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
        grant_type: 'authorization_code', client_id: CLIENT, redirect_uri: CALLBACK, code: value.searchParams.get('code'), code_verifier: verifier }) });
      stage = loginStage + '-pkce-token-response'; save();
      assert.equal(response.status, 200); const tokens = await response.json();
      stage = loginStage + '-id-token-validation'; save();
      const identity = await validateJwt(tokens.id_token, metadata, CLIENT); assert.equal(identity.nonce, nonce);
      return { tokens, identity };
    } };
  };
  const accounts = {};
  const registrationSubmissions = [];
  const proveAccess = async value => {
    const response = await request(ORIGIN + '/admin/realms/master', { headers: { Authorization: 'Bearer ' + value } });
    assert.equal(response.status, 200, 'Actual master administration permission required');
  };
  const freshRefresh = async tokens => {
    const response = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token',
      client_id: CLIENT, refresh_token: tokens.refresh_token }) });
    assert.equal(response.status, 200, 'Old refresh token must be usable before retirement');
    const refreshed = await response.json(); await proveAccess(refreshed.access_token); return refreshed;
  };
  let retirementWindow;
  const readback = async () => {
    const effective = await admin('partial-export?exportClients=true&exportGroupsAndRoles=true', 'POST');
    lifecycle('readback', { effective, retirementWindow });
  };
  const snapshotUser = async user => ({ account: await admin('users/' + user.id),
    credentials: await admin('users/' + user.id + '/credentials'), sessions: await admin('users/' + user.id + '/sessions') });
  const authenticate = async (kind, scenario = 'valid', context) => {
    const account = accounts[kind];
    const before = token ? await snapshotUser(account) : undefined;
    const login = await startLogin(account.username, credentials[kind], context);
    await login.page.locator('#authenticateWebAuthnButton').waitFor();
    assert.equal(await login.page.locator('#registerWebAuthn, #otp').count(), 0);
    if (scenario === 'password-only') {
      assert.ok(!login.received); assert.deepEqual(await snapshotUser(account), before);
      await login.page.close(); return;
    }
    let presented = account.credential;
    if (scenario === 'wrong-key') {
      const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
      presented = { ...presented, privateKey: key.export({ format: 'der', type: 'pkcs8' }).toString('base64') };
    }
    const authenticator = await virtual(login.page, presented, scenario);
    const posted = login.page.waitForRequest(value => value.method() === 'POST' && new URL(value.url()).pathname.startsWith('/realms/master/login-actions/authenticate')
      && new URLSearchParams(value.postData() || '').has('authenticatorData'));
    await login.page.locator('#authenticateWebAuthnButton').click();
    const properties = assertionProperties((await posted).postData(), account.credential);
    assert.equal(properties.signedByEnrolledKey, scenario !== 'wrong-key');
    assert.equal(properties.userVerified, scenario !== 'missing-uv');
    if (scenario !== 'valid') {
      await login.page.locator('#kc-error-message, .kc-feedback-text').first().waitFor();
      assert.ok(!login.received); assert.equal(await login.page.locator('#registerWebAuthn').count(), 0);
      assert.deepEqual(await snapshotUser(account), before);
      await login.page.close(); return;
    }
    const result = await login.finish(); assert.equal(result.identity.sub, account.id);
    await proveAccess(result.tokens.access_token);
    const listed = await authenticator.session.send('WebAuthn.getCredentials', { authenticatorId: authenticator.authenticatorId });
    assert.ok(listed.credentials[0].signCount > account.credential.signCount);
    account.credential = listed.credentials[0];
    await login.page.close(); return result;
  };
  try {
    stage = 'bootstrap-and-reviewed-prerequisites'; save();
    const { chromium } = await import('playwright');
    browser = await chromium.launch({ headless: true });
    metadata = await (await request(ISSUER + '/.well-known/openid-configuration')).json();
    assert.equal(metadata.issuer, ISSUER);
    const bootstrapResponse = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli', username: 'synthetic-bootstrap', password: credentials.bootstrap }) });
    assert.equal(bootstrapResponse.status, 200);
    let bootstrapTokens = await bootstrapResponse.json(); token = bootstrapTokens.access_token; await proveAccess(token);
    await admin('', 'PUT', { sslRequired: 'all', verifyEmail: true, registrationAllowed: false,
      accessTokenLifespan: 1800, eventsEnabled: true, adminEventsEnabled: true, adminEventsDetailsEnabled: false,
      smtpServer: { host: '127.0.0.1', port: '1025', from: 'identity@example.invalid',
        fromDisplayName: 'Owned synthetic identity', ssl: 'false', starttls: 'false', auth: 'false' },
      eventsExpiration: 86400, eventsListeners: ['jboss-logging'], enabledEventTypes: [],
      loginTheme: 'firefly-id', accountTheme: 'firefly-id', adminTheme: 'firefly-id', emailTheme: 'firefly-id',
      webAuthnPolicyRpId: 'id.firefly.test', webAuthnPolicyRpEntityName: 'Owned synthetic master',
      webAuthnPolicySignatureAlgorithms: ['ES256'], webAuthnPolicyAuthenticatorAttachment: 'cross-platform',
      webAuthnPolicyUserVerificationRequirement: 'required', webAuthnPolicyAttestationConveyancePreference: 'none',
      webAuthnPolicyRequireResidentKey: 'No', webAuthnPolicyExtraOrigins: [],
      webAuthnPolicyCreateTimeout: 20, webAuthnPolicyPasswordlessPasskeysEnabled: false, attributes: {} });
    const usersBefore = await admin('users');
    assert.deepEqual(usersBefore.map(value => value.username), ['synthetic-bootstrap']);
    const bootstrap = usersBefore[0];
    const clients = await admin('clients');
    assert.deepEqual(clients.map(value => value.clientId).sort(),
      ['account', 'account-console', 'admin-cli', 'broker', 'master-realm', CLIENT].sort());
    const consoleClient = clients.find(value => value.clientId === CLIENT);
    await admin('clients/' + consoleClient.id, 'PUT', { ...consoleClient, rootUrl: ORIGIN,
      baseUrl: ORIGIN + '/admin/master/console/', redirectUris: [ORIGIN + '/admin/master/console/*'], webOrigins: [ORIGIN],
      attributes: { 'pkce.code.challenge.method': 'S256', 'client.use.lightweight.access.token.enabled': 'false' } });
    const adminRole = await admin('roles/admin');
    const register = (await admin('authentication/required-actions')).find(value => value.alias === 'webauthn-register');
    assert.ok(register); await admin('authentication/required-actions/webauthn-register', 'PUT', { ...register, enabled: true, defaultAction: false });
    for (const kind of ['ordinary', 'emergency']) {
      stage = 'enroll-' + kind; save();
      const username = 'synthetic-' + kind;
      await admin('users', 'POST', { username, enabled: true, firstName: 'Synthetic', lastName: kind,
        email: kind + '@example.invalid', emailVerified: true, requiredActions: ['webauthn-register'],
        credentials: [{ type: 'password', value: credentials[kind], temporary: false }] });
      const users = await admin('users?username=' + username + '&exact=true'); assert.equal(users.length, 1);
      const user = users[0]; await admin('users/' + user.id + '/role-mappings/realm', 'POST', [adminRole]);
      const login = await startLogin(username, credentials[kind]);
      stage = 'enroll-' + kind + '-registration-form'; save();
      await login.page.locator('#registerWebAuthn').waitFor();
      stage = 'enroll-' + kind + '-virtual-authenticator'; save();
      const authenticator = await virtual(login.page);
      login.page.on('dialog', dialog => dialog.accept('Owned synthetic ' + kind + ' key'));
      stage = 'enroll-' + kind + '-registration-submit'; save();
      login.page.on('response', response => {
        const submitted = response.request();
        if (submitted.method() === 'POST' && new URL(submitted.url()).pathname === '/realms/master/login-actions/required-action'
          && registrationSubmissions.length < 4) {
          registrationSubmissions.push(registrationSubmissionDiagnostic(submitted.postData(), submitted.headers().origin, response.status()));
        }
      });
      stage = 'enroll-' + kind + '-registration-module-readiness'; save();
      await submitMasterRegistration(login.page);
      const result = await login.finish(); assert.equal(result.identity.sub, user.id); await proveAccess(result.tokens.access_token);
      const listed = await authenticator.session.send('WebAuthn.getCredentials', { authenticatorId: authenticator.authenticatorId });
      assert.equal(listed.credentials.length, 1); assert.equal(listed.credentials[0].rpId, 'id.firefly.test');
      const keys = await admin('users/' + user.id + '/credentials');
      assert.equal(keys.filter(value => value.type === 'webauthn').length, 1);
      assert.ok(keys.some(value => value.type === 'password')); assert.ok(!keys.some(value => value.type === 'webauthn-passwordless'));
      assert.deepEqual((await admin('users/' + user.id)).requiredActions, []);
      accounts[kind] = { id: user.id, username, credential: listed.credentials[0], tokens: await freshRefresh(result.tokens),
        context: login.context, keys: keys.map(value => [value.id, value.type]).sort() };
      await login.page.close(); pass(kind + '-real-two-factor-enrollment-and-master-role-before-transition');
    }
    token = accounts.ordinary.tokens.access_token;
    stage = 'explicit-source-prerequisites'; save();
    const renewedBootstrap = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli', username: 'synthetic-bootstrap', password: credentials.bootstrap }) });
    assert.equal(renewedBootstrap.status, 200); bootstrapTokens = await renewedBootstrap.json();
    await proveAccess(bootstrapTokens.access_token);
    pass('bootstrap-authority-positive-immediately-before-client-and-account-retirement');
    await retireOfflineScope(admin);
    for (const client of await admin('clients')) {
      for (const kind of ['default', 'optional']) {
        assert.ok(!(await admin('clients/' + client.id + '/' + kind + '-client-scopes')).some(scope => scope.name === 'offline_access'),
          'Offline scope remains assigned');
      }
      if (client.clientId === 'master-realm') {
        assert.equal(client.bearerOnly, true); assert.equal(client.publicClient, false);
        for (const key of ['directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled']) assert.equal(client[key], false);
        continue;
      }
      const attributes = preparedClientAttributes(client);
      const attributeWindow = { minimum: Math.floor(Date.now() / 1000) };
      await admin('clients/' + client.id, 'PUT', { ...client, enabled: client.clientId === CLIENT,
        standardFlowEnabled: client.clientId === CLIENT, directAccessGrantsEnabled: false, implicitFlowEnabled: false,
        serviceAccountsEnabled: false, authorizationServicesEnabled: false,
        authenticationFlowBindingOverrides: {}, attributes });
      attributeWindow.maximum = Math.ceil(Date.now() / 1000);
      const effectiveClient = await admin('clients/' + client.id);
      report.clientAttributeReadbacks ??= [];
      report.clientAttributeReadbacks.push(clientAttributeDiagnostic(client.clientId, attributes, effectiveClient.attributes)); save();
      report.clientAttributeReadbacks.at(-1).nativeSecretMetadataCreated = verifyPreparedClientReadback(
        client, effectiveClient, attributes, attributeWindow); save();
    }
    // Review the complete inventory before changing any component; native profile metadata is retained.
    const components = await admin('components');
    report.componentInventory = components.slice(0, 32).map(componentDiagnostic); save();
    lifecycle('review_components', components);
    await admin('users/' + bootstrap.id, 'PUT', { ...bootstrap, enabled: false, requiredActions: [] });
    const sourceOrdinary = structuredClone(accounts.ordinary.credential);
    const sourceEmergency = structuredClone(accounts.emergency.credential);
    const retainedTokens = accounts.ordinary.tokens;
    const retainedEmergencyTokens = accounts.emergency.tokens;
    pass('reviewed-prerequisites-explicitly-prepared-on-owned-master');

    stage = 'actual-full-export-and-exact-profile-generation'; save();
    lifecycle('export_candidate');
    const candidate = JSON.parse(readFileSync(directory + '/candidate.json'));
    const exported = JSON.parse(readFileSync(directory + '/exchange/source.json'));
    assert.equal(exported.realm, 'master'); assert.ok(exported.id);
    for (const kind of ['ordinary', 'emergency']) {
      const user = exported.users.find(value => value.id === accounts[kind].id);
      assert.ok(user); assert.ok(user.realmRoles.includes('admin'));
      const password = user.credentials.find(value => value.type === 'password');
      assert.ok(password.secretData && JSON.parse(password.secretData).value, 'Actual salted password hash required');
      assert.ok(user.credentials.some(value => value.type === 'webauthn' && value.credentialData));
    }
    assert.deepEqual(candidate.users, exported.users); assert.deepEqual(candidate.roles, exported.roles);
    pass('actual-master-export-includes-enrolled-keys-password-hashes-and-admin-roles');
    stage = 'exact-candidate-import-new-empty-database'; save();
    lifecycle('import_start'); token = undefined;
    const imported = await authenticate('ordinary'); token = imported.tokens.access_token;
    await readback();
    for (const kind of ['ordinary', 'emergency']) {
      const current = await admin('users/' + accounts[kind].id);
      assert.equal(current.username, accounts[kind].username);
      const keys = await admin('users/' + accounts[kind].id + '/credentials');
      assert.deepEqual(keys.map(value => [value.id, value.type]).sort(), accounts[kind].keys);
      assert.ok((await admin('users/' + accounts[kind].id + '/role-mappings/realm')).some(value => value.name === 'admin'));
    }
    await authenticate('emergency');
    pass('exact-import-effective-policy-retained-ids-keys-roles-and-both-two-factor-admin-logins');

    stage = 'resume-original-retained-master'; save();
    lifecycle('retained_start'); token = retainedTokens.access_token;
    accounts.ordinary.credential = sourceOrdinary; accounts.emergency.credential = sourceEmergency;
    await proveAccess(token); await proveAccess(retainedEmergencyTokens.access_token);
    const ordinaryOld = await freshRefresh(retainedTokens); const emergencyOld = await freshRefresh(retainedEmergencyTokens);
    token = ordinaryOld.access_token;
    pass('retained-old-access-and-refresh-authority-positive-immediately-before-transition');
    const actionLinks = await prepareMasterActions({ browser, contexts, admin, accounts,
      stage: value => { stage = value; save(); }, passed: pass });
    stage = 'apply-generated-settings-without-realm-replacement'; save();
    report.retainedControls = retainedControlDiagnostic(candidate); save();
    const operations = retainedOperations(candidate);
    for (const flow of operations.flows) {
      const { authenticationExecutions, ...representation } = flow;
      await admin('authentication/flows', 'POST', representation);
      for (const execution of authenticationExecutions) {
        await admin('authentication/flows/' + flow.alias + '/executions/execution', 'POST', { provider: execution.authenticator });
        const found = (await admin('authentication/flows/' + flow.alias + '/executions')).find(value => value.providerId === execution.authenticator);
        assert.ok(found?.id);
        await admin('authentication/flows/' + flow.alias + '/executions', 'PUT', { ...found, requirement: execution.requirement, priority: execution.priority });
      }
    }
    for (const action of operations.actions) {
      await admin('authentication/required-actions/' + encodeURIComponent(action.alias), 'PUT', action);
    }
    await admin('', 'PUT', operations.realm); await readback();
    // Force a later second than all retained tokens; equal iat/notBefore is otherwise ambiguous.
    const latestIssuedAt = Math.max(...[ordinaryOld, emergencyOld, bootstrapTokens]
      .map(value => JSON.parse(Buffer.from(value.access_token.split('.')[1], 'base64url')).iat));
    while (Math.floor(Date.now() / 1000) <= latestIssuedAt) await new Promise(ok => setTimeout(ok, 200));
    retirementWindow = { minimum: Math.floor(Date.now() / 1000) };
    await admin('logout-all', 'POST'); retirementWindow.maximum = Math.floor(Date.now() / 1000); token = undefined;
    lifecycle('restart');
    report.retained = lifecycle('verify_state');
    pass('original-database-users-credential-hashes-roles-and-nonempty-audit-rows-preserved-before-new-assertions');
    stage = 'retire-old-authority'; report.retiredAccessTransport = []; save();
    for (const old of [ordinaryOld, emergencyOld, bootstrapTokens]) {
      const attempts = []; report.retiredAccessTransport.push(attempts);
      const access = await retiredAccessRequest(request, old.access_token, value => { attempts.push(value); save(); });
      assert.ok([401, 403].includes(access.status), 'Old access token still authorizes master administration');
      const refreshed = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
        grant_type: 'refresh_token', client_id: old === bootstrapTokens ? 'admin-cli' : CLIENT, refresh_token: old.refresh_token }) });
      assert.ok([400, 401].includes(refreshed.status)); assert.ok(!(await refreshed.json()).access_token);
    }
    pass('old-ordinary-emergency-bootstrap-access-and-refresh-authority-refused');
    stage = 'retained-ordinary-positive'; save();
    const ordinary = await authenticate('ordinary', 'valid', accounts.ordinary.context); token = ordinary.tokens.access_token;
    await readback(); assert.equal((await admin('users/' + bootstrap.id)).enabled, false);
    pass('old-sso-cookie-requires-password-and-genuine-uv-key-before-new-master-authority');
    stage = 'retained-emergency-positive'; save();
    await authenticate('emergency', 'valid', accounts.emergency.context);
    pass('emergency-requires-same-password-plus-genuine-uv-key-and-master-permission');
    await qualifyMasterActions({ actions: actionLinks, lifecycle, stage: value => { stage = value; save(); }, passed: pass,
      record: value => { report.actionLinks = { ...report.actionLinks, ...value }; save(); } });
    report.boundaries.pendingActionLinks = 'UPDATE_PASSWORD only: qualified for this single-process owned restart and observed original expiry; other action classes, HA and destination inventories require their own acceptance.';
    for (const kind of ['ordinary', 'emergency']) {
      for (const scenario of ['password-only', 'wrong-key', 'missing-uv']) {
        stage = kind + '-' + scenario + '-refusal'; save(); await authenticate(kind, scenario);
        pass(kind + '-' + scenario + '-refused-without-enrollment-credential-or-session-change');
      }
    }
    stage = 'bootstrap-and-alternate-grant-refusal'; save();
    const disabled = await startLogin('synthetic-bootstrap', credentials.bootstrap);
    await disabled.page.locator('#input-error, #kc-error-message, .kc-feedback-text').first().waitFor();
    assert.ok(!disabled.received); await disabled.page.close();
    for (const client of [CLIENT, 'admin-cli', 'master-realm']) {
      const response = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
        grant_type: 'password', client_id: client, username: accounts.ordinary.username, password: credentials.ordinary }) });
      assert.ok([400, 401].includes(response.status)); assert.ok(!(await response.json()).access_token);
    }
    const internal = new URL(metadata.authorization_endpoint);
    internal.search = new URLSearchParams({ client_id: 'master-realm', redirect_uri: CALLBACK, response_type: 'code' });
    assert.equal((await request(internal.href)).status, 403);
    pass('disabled-bootstrap-and-direct-grants-refused-internal-role-resource-noninteractive');
    report.status = 'PASSED'; stage = 'complete'; save();
    console.log('Owned master import and retained-transition qualification passed; bounded evidence written.');
  } catch (error) {
    report.status = 'FAILED';
    report.failure = { ...safeRuntimeFailure(error), kind: error?.code === 'ERR_ASSERTION' ? 'ASSERTION' : 'RUNTIME',
      ...(Number.isInteger(error?.actual) ? { actualStatus: error.actual } : {}),
      ...(error?.diagnostic ? { administrativeWrite: error.diagnostic } : {}) };
    report.failure.navigation = navigation;
    report.failure.registrationSubmissions = registrationSubmissions;
    try { report.failure.native = lifecycle('authentication_diagnostic'); } catch { report.failure.native = { available: false }; }
    report.failure.visibleControls = [];
    for (const context of contexts) {
      const page = context.pages().at(-1);
      if (!page) continue;
      const visible = { route: masterRouteClass(page.url()) };
      for (const id of ['username', 'password', 'registerWebAuthn', 'authenticateWebAuthnButton', 'kc-info-message',
        'kc-error-message', 'password-new', 'email', 'firstName', 'lastName', 'kc-update-profile-form']) {
        visible[id] = await page.locator('#' + id).isVisible().catch(() => false);
      }
      visible.errorCategory = classifyAuthenticationMessage(await page.locator('#kc-error-message').innerText().catch(() => ''));
      report.failure.visibleControls.push(visible);
      if (report.failure.visibleControls.length === 4) break;
    }
    save(); throw new Error('Owned master qualification refused');
  } finally {
    for (const context of contexts) await context.close().catch(() => {});
    if (browser) await browser.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  qualify().catch(() => { console.error('Owned master qualification refused; inspect bounded summary only.'); process.exitCode = 1; });
}
