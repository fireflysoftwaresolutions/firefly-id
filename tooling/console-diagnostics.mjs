import { writeFile } from 'node:fs/promises';

export function consoleResourceGroup(address) {
  let path;
  try { path = new URL(address).pathname; } catch { return 'other'; }
  if (/^\/resources\/[^/]+\/account\/[^/]+$/.test(path)) return 'account-messages';
  if (/^\/resources\/[^/]+\/(account|admin)\/[^/]+\//.test(path)) return 'console-asset';
  if (/^\/resources\/[^/]+\/common\//.test(path)) return 'shared-asset';
  if (/\/protocol\/openid-connect\//.test(path)) return 'identity-protocol';
  if (/^\/realms\/[^/]+\/account\//.test(path)) return 'account-api';
  if (/^\/admin\/realms\//.test(path)) return 'administration-api';
  return 'other';
}

export function consoleErrorGroup(error) {
  const message = typeof error?.message === 'string' ? error.message : '';
  if (/crypto|secure context/i.test(message)) return 'secure-context';
  if (/module|import/i.test(message)) return 'module-loading';
  if (/json|unexpected token/i.test(message)) return 'response-format';
  if (/fetch|network/i.test(message)) return 'network';
  if (/keycloak|initializ/i.test(message)) return 'identity-initialization';
  return 'other';
}

// Only fixed categories and structural booleans leave the synthetic browser.
export function observeConsole(page) {
  const failures = [];
  const errors = [];
  page.on('pageerror', error => {
    if (errors.length < 12) errors.push(consoleErrorGroup(error));
  });
  page.on('console', message => {
    if (message.type() === 'error' && errors.length < 12) errors.push(consoleErrorGroup({ message: message.text() }));
  });
  page.on('response', response => {
    if (response.status() >= 400 && failures.length < 30) {
      failures.push({ group: consoleResourceGroup(response.url()), status: response.status() });
    }
  });
  page.on('requestfailed', request => {
    if (failures.length < 30) failures.push({ group: consoleResourceGroup(request.url()), status: 'network-failure' });
  });
  return async (directory, surface) => {
    if (!['account', 'admin'].includes(surface)) throw new Error('Unknown console surface');
    const structure = await page.evaluate(() => ({
      surface: ['account', 'admin'].includes(document.body?.dataset.pageId) ? document.body.dataset.pageId : 'other',
      loading: Boolean(document.querySelector('.keycloak__loading-container')),
      appChildren: Math.min(document.querySelector('#app')?.childElementCount || 0, 20),
      masthead: Boolean(document.querySelector('.pf-v5-c-masthead')),
      loginForm: Boolean(document.querySelector('#kc-login')),
      personalInfoHeading: [...document.querySelectorAll('h1,h2')].some(element => element.textContent.trim() === 'Personal info'),
      fontLoaded: document.fonts.check('16px Manrope'),
    }));
    await writeFile(`${directory}/${surface}-diagnostics.json`, JSON.stringify({ structure, errors, failures }, null, 2));
    // Never capture credential, action-token, OTP enrollment or arbitrary error pages.
    const location = new URL(page.url());
    if (structure.surface === surface && location.origin === 'http://id.firefly.test:8180'
      && !location.search && !location.hash
      && ['/realms/sandbox-customers/account/', '/admin/master/console/'].includes(location.pathname)) {
      await page.screenshot({ path: `${directory}/${surface}-failure.png`, fullPage: true });
    }
  };
}
