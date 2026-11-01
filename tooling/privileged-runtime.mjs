import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, verify } from 'node:crypto';
import { validateJwt } from './extended-runtime.mjs';

const OWNED_ORIGIN = 'https://id.firefly.test:8443';
const OWNED_CALLBACK = 'https://localhost:8448/oidc/callback';
const CLIENT = 'privileged-fixture-browser';
const GUARD_FLOW = 'fixture-privileged';
const denyFlow = 'fixture-deny';
const profile = 'password-webauthn-uv-v1';
const flow = (alias, authenticators) => ({ alias, providerId: 'basic-flow', topLevel: true, builtIn: false,
  authenticationExecutions: authenticators.map((authenticator, index) => ({ authenticator,
    authenticatorFlow: false, requirement: 'REQUIRED', priority: (index + 1) * 10 })) });

export function privilegedFixtureRealm(name, password, origin, callback) {
  assert.match(name, /^native-privileged-[a-f0-9]{12}$/);
  assert.equal(origin, OWNED_ORIGIN); assert.equal(callback, OWNED_CALLBACK);
  assert.ok(typeof password === 'string' && password.length >= 24, 'Fresh synthetic password required');
  return {
    realm: name, enabled: true, sslRequired: 'all', verifyEmail: true,
    registrationAllowed: false, resetPasswordAllowed: false, rememberMe: false,
    loginTheme: 'firefly-id', accountTheme: 'firefly-id', adminTheme: 'firefly-id', emailTheme: 'firefly-id', attributes: { 'firefly.privileged-administration': profile },
    webAuthnPolicyRpEntityName: 'Owned privileged fixture', webAuthnPolicyRpId: 'id.firefly.test',
    webAuthnPolicySignatureAlgorithms: ['ES256'], webAuthnPolicyAttestationConveyancePreference: 'none',
    webAuthnPolicyAuthenticatorAttachment: 'cross-platform', webAuthnPolicyRequireResidentKey: 'No',
    webAuthnPolicyUserVerificationRequirement: 'required', webAuthnPolicyCreateTimeout: 20,
    webAuthnPolicyExtraOrigins: [], webAuthnPolicyPasswordlessPasskeysEnabled: false,
    authenticationFlows: [flow('fixture-supervised-enrollment', ['auth-username-password-form']),
      flow(GUARD_FLOW, ['auth-username-password-form', 'firefly-privileged-webauthn']),
      flow(denyFlow, ['deny-access-authenticator'])],
    browserFlow: 'fixture-supervised-enrollment', directGrantFlow: denyFlow,
    registrationFlow: denyFlow, resetCredentialsFlow: denyFlow,
    requiredActions: [{ alias: 'webauthn-register', providerId: 'webauthn-register', name: 'Supervised fixture enrollment',
      enabled: true, defaultAction: false, priority: 60 }],
    eventsEnabled: true, adminEventsEnabled: true, adminEventsDetailsEnabled: false,
    clients: [{ clientId: CLIENT, enabled: true, protocol: 'openid-connect', publicClient: true,
      standardFlowEnabled: true, implicitFlowEnabled: false, directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false, authorizationServicesEnabled: false, fullScopeAllowed: true,
      redirectUris: [callback], webOrigins: [new URL(callback).origin],
      attributes: { 'pkce.code.challenge.method': 'S256' }, authenticationFlowBindingOverrides: {},
      defaultClientScopes: ['profile', 'email', 'roles'], optionalClientScopes: [] }],
    users: [true, false].map(enrolled => ({ username: enrolled ? 'named-admin' : 'missing-key-admin',
      firstName: 'Synthetic', lastName: enrolled ? 'Enrolled' : 'Missing',
      email: `${enrolled ? 'enrolled' : 'missing'}@example.invalid`, enabled: true, emailVerified: true,
      requiredActions: enrolled ? ['webauthn-register'] : [],
      credentials: [{ type: 'password', value: password, temporary: false }],
      clientRoles: { 'realm-management': ['view-realm'] } })),
  };
}

export function assertionProperties(post, enrolledCredential) {
  const params = new URLSearchParams(post);
  const authenticatorData = Buffer.from(params.get('authenticatorData') || '', 'base64url');
  const clientData = Buffer.from(params.get('clientDataJSON') || '', 'base64url');
  const signature = Buffer.from(params.get('signature') || '', 'base64url');
  assert.ok(authenticatorData.length >= 37 && clientData.length > 0 && signature.length > 0, 'Actual WebAuthn assertion required');
  const publicKey = createPublicKey(createPrivateKey({ key: Buffer.from(enrolledCredential.privateKey, 'base64'), format: 'der', type: 'pkcs8' }));
  return { userVerified: (authenticatorData[32] & 4) !== 0,
    signedByEnrolledKey: verify('sha256', Buffer.concat([authenticatorData, createHash('sha256').update(clientData).digest()]), publicKey, signature) };
}

/** Hosted synthetic qualification only; all mutations are fenced to a newly created realm owned by this invocation. */
export async function qualifyPrivilegedAdministration({ browser, origin, callback, request, adminToken, pending, passed, stage }) {
  assert.ok(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_OS === 'Linux'
    && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Owned hosted Linux runner required');
  assert.equal(origin, OWNED_ORIGIN); assert.equal(callback, OWNED_CALLBACK);
  assert.ok(pending instanceof Map, 'Owned callback dispatch required');
  const name = `native-privileged-${randomBytes(6).toString('hex')}`;
  const password = randomBytes(32).toString('base64url');
  const realm = privilegedFixtureRealm(name, password, origin, callback);
  const issuer = `${origin}/realms/${name}`;
  const contexts = new Set();
  const cancellations = new Set();
  const results = [];
  const record = label => { results.push(label); passed(label); };
  let created = false;
  async function administer(suffix = '', method = 'GET', body) {
    assert.ok(created && /^native-privileged-[a-f0-9]{12}$/.test(name), 'Fresh owned realm required');
    assert.ok(!suffix.includes('..') && !suffix.startsWith('/') && !suffix.includes('\\'), 'Owned relative admin path required');
    return request(`${origin}/admin/realms/${name}${suffix ? '/' + suffix : ''}`, { method,
      headers: { Authorization: `Bearer ${await adminToken()}`, 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }
  async function read(suffix = '') {
    const response = await administer(suffix); assert.equal(response.status, 200, 'Owned administrative read refused');
    return response.json();
  }
  async function write(suffix, body) {
    assert.equal((await administer(suffix, 'PUT', body)).status, 204, 'Owned fixture update refused');
  }
  async function newContext() {
    const context = await browser.newContext(); contexts.add(context); return context;
  }
  async function virtual(page, credential, options = {}) {
    const session = await page.context().newCDPSession(page);
    await session.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: false,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    } });
    if (credential) await session.send('WebAuthn.addCredential', { authenticatorId, credential });
    if (Object.keys(options).length) await session.send('WebAuthn.setResponseOverrideBits', { authenticatorId, ...options });
    return { session, authenticatorId };
  }
  let metadata;
  async function start(username = 'named-admin', context) {
    context ||= await newContext();
    const page = await context.newPage(); page.setDefaultTimeout(25000);
    const state = randomBytes(24).toString('base64url');
    const nonce = randomBytes(24).toString('base64url');
    const verifier = randomBytes(48).toString('base64url');
    let received;
    let timer;
    const returned = new Promise((ok, fail) => {
      timer = setTimeout(() => fail(new Error('Owned privileged callback deadline exceeded')), 60000);
      pending.set(state, value => { received = value; clearTimeout(timer); pending.delete(state); ok(value); });
    });
    returned.catch(() => {});
    const cancel = () => { clearTimeout(timer); pending.delete(state); cancellations.delete(cancel); };
    cancellations.add(cancel);
    const url = new URL(metadata.authorization_endpoint);
    url.search = new URLSearchParams({ client_id: CLIENT, redirect_uri: callback, response_type: 'code', scope: 'openid',
      state, nonce, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url') });
    await page.goto(url.href);
    // No prompt=login: an existing SSO cookie must still reach the real password execution.
    await page.locator('#password').waitFor();
    assert.ok(!received, 'SSO cookie bypassed the required password');
    if (await page.locator('#username').isVisible()) await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('#kc-login').click();
    return { page, context, cancel, get received() { return received; },
      async finish() {
        const result = await returned;
        assert.equal(result.searchParams.get('state'), state);
        assert.ok(!result.searchParams.has('error') && result.searchParams.has('code'), 'Privileged authorization code missing');
        const response = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
          grant_type: 'authorization_code', client_id: CLIENT, redirect_uri: callback,
          code: result.searchParams.get('code'), code_verifier: verifier }) });
        assert.equal(response.status, 200, 'Real privileged PKCE exchange refused');
        const tokens = await response.json();
        const identity = await validateJwt(tokens.id_token, metadata, CLIENT);
        assert.equal(identity.nonce, nonce);
        cancel();
        return { tokens, identity };
      } };
  }
  async function snapshot(userId) {
    const [account, keys, sessions] = await Promise.all([read(`users/${userId}`), read(`users/${userId}/credentials`), read(`users/${userId}/sessions`)]);
    return { requiredActions: account.requiredActions || [], keyIds: keys.map(key => key.id).sort(), sessions: sessions.map(session => session.id).sort() };
  }
  async function refused(login, userId, before) {
    await login.page.locator('#kc-error-message, .kc-feedback-text').first().waitFor();
    assert.ok(!login.received, 'Refused privileged attempt issued a code');
    assert.equal(await login.page.locator('#registerWebAuthn').count(), 0, 'Refusal triggered enrollment');
    assert.deepEqual(await snapshot(userId), before, 'Refusal changed keys, required actions or authenticated sessions');
    login.cancel(); await login.page.close();
  }
  try {
    stage('privileged-owned-realm-create');
    const authorization = `Bearer ${await adminToken()}`;
    assert.equal((await request(`${origin}/admin/realms/${name}`, { headers: { Authorization: authorization } })).status, 404,
      'Random privileged realm already exists; refusing to adopt it');
    const response = await request(`${origin}/admin/realms`, { method: 'POST',
      headers: { Authorization: authorization, 'Content-Type': 'application/json' }, body: JSON.stringify(realm) });
    assert.equal(response.status, 201, 'Fresh privileged fixture creation refused'); created = true;
    const discovery = await request(`${issuer}/.well-known/openid-configuration`);
    assert.equal(discovery.status, 200); metadata = await discovery.json(); assert.equal(metadata.issuer, issuer);
    const users = await read('users');
    const enrolled = users.find(user => user.username === 'named-admin');
    const missing = users.find(user => user.username === 'missing-key-admin');
    assert.ok(enrolled?.id && missing?.id);

    stage('privileged-supervised-two-factor-enrollment');
    const retainedContext = await newContext();
    const enrollment = await start('named-admin', retainedContext);
    await enrollment.page.locator('#registerWebAuthn').waitFor();
    const registration = await virtual(enrollment.page);
    enrollment.page.on('dialog', dialog => dialog.accept('Owned privileged fixture key'));
    await enrollment.page.locator('#registerWebAuthn').click();
    assert.equal((await enrollment.finish()).identity.sub, enrolled.id);
    const listed = await registration.session.send('WebAuthn.getCredentials', { authenticatorId: registration.authenticatorId });
    assert.equal(listed.credentials.length, 1);
    let credential = listed.credentials[0];
    assert.equal(credential.rpId, 'id.firefly.test');
    const stored = await read(`users/${enrolled.id}/credentials`);
    assert.equal(stored.filter(key => key.type === 'webauthn').length, 1);
    assert.equal(stored.filter(key => key.type === 'webauthn-passwordless').length, 0);
    assert.deepEqual((await read(`users/${enrolled.id}`)).requiredActions || [], []);
    await enrollment.page.close();
    record('privileged-real-two-factor-webauthn-enrollment-completed-before-transition');

    stage('privileged-owned-profile-transition');
    for (const client of await read('clients')) {
      const body = { ...client, directAccessGrantsEnabled: false, implicitFlowEnabled: false, serviceAccountsEnabled: false,
        ...(client.clientId === CLIENT ? {} : { enabled: false, standardFlowEnabled: false }) };
      await write(`clients/${client.id}`, body);
    }
    for (const action of await read('authentication/required-actions')) {
      await write(`authentication/required-actions/${encodeURIComponent(action.alias)}`, { ...action, enabled: false, defaultAction: false });
    }
    await write('', { browserFlow: GUARD_FLOW, directGrantFlow: denyFlow, registrationFlow: denyFlow,
      resetCredentialsFlow: denyFlow, registrationAllowed: false, resetPasswordAllowed: false,
      webAuthnPolicyPasswordlessPasskeysEnabled: false, webAuthnPolicyUserVerificationRequirement: 'required' });
    const effective = await read(); assert.equal(effective.browserFlow, GUARD_FLOW);
    assert.equal(effective.webAuthnPolicyUserVerificationRequirement, 'required');
    assert.ok((await read('authentication/required-actions')).every(action => !action.enabled && !action.defaultAction));
    const steps = (await read(`authentication/flows/${GUARD_FLOW}/executions`)).filter(step => !step.authenticationFlow);
    assert.deepEqual(steps.map(step => [step.providerId, step.requirement]),
      [['auth-username-password-form', 'REQUIRED'], ['firefly-privileged-webauthn', 'REQUIRED']]);
    record('privileged-owned-flow-readback-confirms-required-password-and-native-guard-with-no-setup');

    stage('privileged-missing-key-refusal');
    let before = await snapshot(missing.id);
    await refused(await start('missing-key-admin'), missing.id, before);
    record('privileged-missing-key-refused-without-enrollment-or-session');

    stage('privileged-password-only-and-direct-grant-refusal');
    before = await snapshot(enrolled.id);
    const passwordOnly = await start();
    await passwordOnly.page.locator('#authenticateWebAuthnButton').waitFor();
    assert.ok(!passwordOnly.received); assert.deepEqual(await snapshot(enrolled.id), before);
    assert.equal(await passwordOnly.page.locator('#registerWebAuthn, #otp').count(), 0);
    passwordOnly.cancel(); await passwordOnly.page.close();
    const direct = await request(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({
      grant_type: 'password', client_id: CLIENT, username: 'named-admin', password }) });
    assert.equal(direct.status, 400); assert.ok(!(await direct.json()).access_token);
    record('privileged-password-alone-remains-at-required-key-and-direct-grant-refuses');

    for (const scenario of ['wrong-key', 'bad-signature', 'missing-user-verification', 'valid', 'sso-cookie']) {
      stage(`privileged-${scenario}`);
      before = await snapshot(enrolled.id);
      const login = await start('named-admin', scenario === 'sso-cookie' ? retainedContext : undefined);
      await login.page.locator('#authenticateWebAuthnButton').waitFor();
      let presented = credential;
      if (scenario === 'wrong-key') {
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        presented = { ...credential, privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') };
      }
      const authenticator = await virtual(login.page, presented,
        scenario === 'bad-signature' ? { isBogusSignature: true } : scenario === 'missing-user-verification' ? { isBadUV: true } : {});
      const submitted = login.page.waitForRequest(value => value.method() === 'POST'
        && new URL(value.url()).pathname.startsWith(`/realms/${name}/login-actions/authenticate`)
        && new URLSearchParams(value.postData() || '').has('authenticatorData'));
      await login.page.locator('#authenticateWebAuthnButton').click();
      const properties = assertionProperties((await submitted).postData(), credential);
      assert.equal(properties.userVerified, scenario !== 'missing-user-verification');
      assert.equal(properties.signedByEnrolledKey, !['wrong-key', 'bad-signature'].includes(scenario),
        'UV refusal must use a genuine signature, distinct from the wrong-key/signature refusals');
      if (['valid', 'sso-cookie'].includes(scenario)) {
        const result = await login.finish(); assert.equal(result.identity.sub, enrolled.id);
        const realmRead = await request(`${origin}/admin/realms/${name}`, { headers: { Authorization: `Bearer ${result.tokens.access_token}` } });
        assert.equal(realmRead.status, 200, 'Named administrator must have the actual scoped realm-read permission');
        const masterRead = await request(`${origin}/admin/realms/master`, { headers: { Authorization: `Bearer ${result.tokens.access_token}` } });
        assert.ok([401, 403].includes(masterRead.status), 'Fixture administrator must not gain master permission');
        const after = await authenticator.session.send('WebAuthn.getCredentials', { authenticatorId: authenticator.authenticatorId });
        assert.ok(after.credentials[0].signCount > credential.signCount); credential = after.credentials[0];
        await login.page.close();
      } else await refused(login, enrolled.id, before);
      record(`privileged-${scenario}-${['valid', 'sso-cookie'].includes(scenario) ? 'signed-pkce-and-scoped-admin-permission' : 'refused-without-session-or-enrollment'}`);
    }

    stage('privileged-deleted-key-on-resumed-assertion');
    const resumed = await start();
    await resumed.page.locator('#authenticateWebAuthnButton').waitFor();
    await virtual(resumed.page, credential);
    const key = (await read(`users/${enrolled.id}/credentials`)).find(value => value.type === 'webauthn');
    assert.ok(key?.id); assert.equal((await administer(`users/${enrolled.id}/credentials/${key.id}`, 'DELETE')).status, 204);
    before = await snapshot(enrolled.id);
    await resumed.page.locator('#authenticateWebAuthnButton').click();
    await refused(resumed, enrolled.id, before);
    record('privileged-credential-deleted-after-challenge-refuses-resumed-assertion-without-setup');
    return { status: 'PASSED', results,
      scope: 'Owned synthetic Keycloak password plus two-factor WebAuthn; no physical-key, master cutover, emergency custody or institutional acceptance.' };
  } finally {
    for (const cancel of cancellations) cancel();
    for (const context of contexts) await context.close();
  }
}
