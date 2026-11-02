import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { selectNewRecoveryMessage } from './recovery-mail.mjs';
import { isMasterCallback } from './master-callback.mjs';

const ORIGIN = 'https://id.firefly.test:8443';
const ISSUER = ORIGIN + '/realms/master';
const CALLBACK = ORIGIN + '/admin/master/console/fixture-return';
const MAIL = 'http://127.0.0.1:8025';
const pause = milliseconds => new Promise(ok => setTimeout(ok, milliseconds));

export function actionExpiryWait(claims, now = Date.now()) {
  assert.ok(Array.isArray(claims) && claims.length > 0 && claims.length <= 3);
  for (const item of claims) assert.ok(Number.isInteger(item.iat) && Number.isInteger(item.exp)
    && item.exp > item.iat && item.exp - item.iat <= 120, 'Bounded original action lifetime required');
  const wait = Math.max(0, Math.max(...claims.map(item => item.exp)) * 1000 + 2000 - now);
  assert.ok(wait <= 122000, 'Owned action expiry deadline exceeded');
  return wait;
}

export function parseMasterAction(mail, subject, now = Date.now()) {
  assert.ok(typeof mail?.HTML === 'string' && mail.HTML.length <= 1024 * 1024);
  const matched = mail.HTML.match(/href="([^"\s]*\/login-actions\/action-token[^"\s]*)"/);
  assert.ok(matched, 'Fresh server-issued action missing');
  const url = new URL(matched[1].replaceAll('&amp;', '&'));
  assert.equal(url.origin, ORIGIN); assert.equal(url.pathname, '/realms/master/login-actions/action-token');
  const compact = url.searchParams.get('key');
  assert.ok(typeof compact === 'string' && compact.length <= 16384 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(compact));
  const parts = compact.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(header.alg, 'HS512'); assert.equal(header.typ, 'JWT'); assert.equal(Buffer.from(parts[2], 'base64url').length, 64);
  assert.equal(claims.iss, ISSUER); assert.deepEqual([claims.aud].flat(), [ISSUER]);
  assert.equal(claims.sub, subject); assert.equal(claims.typ, 'execute-actions');
  assert.equal(claims.azp, 'security-admin-console'); assert.equal(claims.reduri, CALLBACK);
  assert.deepEqual(claims.rqac, ['UPDATE_PASSWORD']); actionExpiryWait([claims], now);
  assert.ok(claims.exp * 1000 > now && claims.iat * 1000 <= now + 2000);
  // The server validates the internal HMAC on the real confirmation page; this parser never invents or signs authority.
  return { url, claims };
}

/** Only called inside the run-owned master fixture after its container/loopback ownership checks. */
export async function prepareMasterActions({ browser, contexts, admin, accounts, stage, passed }) {
  const mailbox = async path => {
    assert.ok(path === '/api/v1/messages' || /^\/api\/v1\/message\/[A-Za-z0-9_-]+$/.test(path));
    const response = await fetch(MAIL + path, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200);
    const length = Number(response.headers.get('content-length'));
    assert.ok(!Number.isFinite(length) || length <= 1024 * 1024, 'Bounded owned mailbox response required');
    const content = await response.text(); assert.ok(content.length <= 1024 * 1024);
    return JSON.parse(content);
  };
  const issue = async account => {
    const prior = new Set(((await mailbox('/api/v1/messages')).messages || []).map(value => value.ID));
    await admin('users/' + account.id + '/execute-actions-email?lifespan=120&client_id=security-admin-console&redirect_uri=' + encodeURIComponent(CALLBACK),
      'PUT', ['UPDATE_PASSWORD']);
    let message;
    for (let attempt = 0; attempt < 30; attempt++) {
      message = selectNewRecoveryMessage((await mailbox('/api/v1/messages')).messages || [], prior,
        account.username.replace('synthetic-', '') + '@example.invalid');
      if (message) break;
      await pause(250);
    }
    assert.ok(message, 'Fresh owned execute-actions mail absent');
    return parseMasterAction(await mailbox('/api/v1/message/' + message.ID), account.id);
  };
  const open = async (action, allowRefusal = false) => {
    const context = await browser.newContext(); contexts.add(context);
    const page = await context.newPage(); page.setDefaultTimeout(25000);
    let callback = false;
    page.on('request', request => { if (isMasterCallback(request.url())) callback = true; });
    await page.route(isMasterCallback, async route => {
      callback = true; await route.fulfill({ contentType: 'text/plain', body: 'Owned action callback.' });
    });
    const response = await page.goto(action.url.href); assert.ok(response && response.status() >= 200 && response.status() < 500);
    const confirmation = page.locator('#kc-info-message a[href*="/login-actions/action-token"]');
    await page.locator('#kc-info-message, #kc-error-message').first().waitFor();
    assert.ok(!callback && Date.now() / 1000 < action.claims.exp);
    if (allowRefusal && !await confirmation.isVisible()) {
      assert.match(await page.locator('#kc-info-message, #kc-error-message').first().innerText(), /expired|no longer valid|invalid|not allowed/i);
      assert.equal(await page.locator('#password-new').count(), 0);
      return { page, context, confirmationUrl: undefined, get callback() { return callback; } };
    }
    await confirmation.waitFor();
    const confirmationUrl = new URL(await confirmation.getAttribute('href'), ORIGIN);
    assert.equal(confirmationUrl.origin, ORIGIN); assert.equal(confirmationUrl.pathname, action.url.pathname);
    const resumed = parseMasterAction({ HTML: '<a href="' + confirmationUrl.href + '">Resume</a>' }, action.claims.sub);
    assert.equal(resumed.claims.exp, action.claims.exp, 'Confirmation must retain the original expiry');
    return { page, context, confirmationUrl, get callback() { return callback; } };
  };
  stage('issue-genuine-action-links-before-transition');
  const fresh = await issue(accounts.ordinary);
  const confirmation = await issue(accounts.emergency);
  const accepted = await issue(accounts.ordinary);
  const resumed = await open(confirmation);
  const form = await open(accepted);
  await form.page.locator('#kc-info-message a[href*="/login-actions/action-token"]').click();
  await form.page.locator('#password-new').waitFor();
  assert.ok(!form.callback && Date.now() / 1000 < accepted.claims.exp);
  const formUrl = new URL(await form.page.locator('#kc-passwd-update-form').getAttribute('action'), ORIGIN);
  assert.equal(formUrl.origin, ORIGIN); assert.equal(formUrl.pathname, '/realms/master/login-actions/required-action');
  passed('three-genuine-email-actions-issued-pretransition-one-server-confirmed-and-one-password-form-opened');
  return { fresh, confirmation, accepted, resumed, form, open };
}

export async function qualifyMasterActions({ actions, lifecycle, stage, passed, record }) {
  stage('unexpired-actions-after-transition');
  assert.ok([actions.fresh, actions.confirmation, actions.accepted].every(value => Date.now() / 1000 < value.claims.exp),
    'Transition exceeded original lifetime; unexpired action boundary is unproven');
  lifecycle('action_baseline');
  // An already accepted action must not survive the deliberately restarted original process as a weaker credential path.
  await actions.form.page.locator('#password-new').fill(randomBytes(32).toString('base64url'));
  await actions.form.page.locator('#password-confirm').fill(await actions.form.page.locator('#password-new').inputValue());
  await actions.form.page.locator('#kc-passwd-update-form').locator('input[type="submit"], button[type="submit"]').click();
  await actions.form.page.locator('#kc-error-message, #kc-info-message, #password').first().waitFor();
  assert.ok(!actions.form.callback, 'Old accepted action produced a callback');
  assert.equal(await actions.form.page.locator('#password-new').count(), 0, 'Old accepted action remained writable after restart');
  lifecycle('verify_action_state');
  passed('preaccepted-password-action-form-refuses-after-owned-process-restart-without-credential-or-session-change');

  // Test the unaccepted signed authority without confirming it into a new credential ceremony.
  const reopened = await actions.open(actions.fresh, true);
  assert.ok(!reopened.callback && !actions.resumed.callback);
  lifecycle('verify_action_state');
  record({ unexpiredSignedLink: reopened.confirmationUrl ? 'SERVER_CONFIRMATION_STILL_REACHABLE' : 'REFUSED',
    immediateRevocation: 'NOT_INFERRED_FROM_CONFIGURATION',
    containment: 'All ingress remained owned and loopback-only while awaiting the original signed deadline.',
    acceptedAction: 'Previously rendered password form refused after owned original-process restart.' });
  passed(reopened.confirmationUrl ? 'unexpired-signed-action-still-valid-and-requires-original-expiry-wait'
    : 'unexpired-signed-action-refused-after-transition-without-state-mutation');
  const wait = actionExpiryWait([actions.fresh.claims, actions.confirmation.claims, actions.accepted.claims]);
  stage('closed-owned-ingress-wait-for-original-action-expiry');
  const deadline = Date.now() + wait;
  while (Date.now() < deadline) await pause(Math.min(1000, deadline - Date.now()));
  stage('expired-fresh-and-preconfirmation-action-refusals');
  for (const [page, url, callback] of [[reopened.page, actions.fresh.url, () => reopened.callback],
    [actions.resumed.page, actions.resumed.confirmationUrl, () => actions.resumed.callback]]) {
    const response = await page.goto(url.href);
    assert.ok(response && response.status() >= 200 && response.status() < 500);
    const message = page.locator('#kc-info-message, #kc-error-message'); await message.waitFor();
    assert.match(await message.innerText(), /expired|no longer valid|invalid/i);
    assert.ok(!callback()); assert.equal(await page.locator('#password-new').count(), 0);
    lifecycle('verify_action_state');
  }
  record({ completion: 'EXPIRED_NOT_REVOKED', originalMaximumLifetimeSeconds: 120,
    freshAndPreconfirmationResume: 'Both unchanged signed URLs refused after original expiry with no retained identity/session mutation.' });
  passed('original-server-issued-action-expiry-refuses-fresh-and-preconfirmation-resume-with-retained-state-unchanged');
}
