const ORIGIN = 'https://id.firefly.test:8443';
const CALLBACK_PATH = '/admin/master/console/fixture-return';

export function isMasterCallback(value) {
  try {
    const url = value instanceof URL ? value : new URL(value);
    return url.origin === ORIGIN && url.pathname === CALLBACK_PATH && !url.username && !url.password;
  } catch { return false; }
}

export function masterCallbackResult(value, state) {
  if (!isMasterCallback(value) || typeof state !== 'string' || !state) return null;
  const url = new URL(value);
  return url.searchParams.getAll('state').length === 1 && url.searchParams.get('state') === state ? url : null;
}

export function masterCallbackObserver(state, complete) {
  let received = false;
  return value => {
    if (received) return;
    const result = masterCallbackResult(value, state);
    if (!result) return;
    received = true;
    complete(result);
  };
}

export function masterRouteClass(value) {
  let url;
  try { url = value instanceof URL ? value : new URL(value); } catch { return 'INVALID_URL'; }
  if (url.origin !== ORIGIN) return 'OTHER_ORIGIN';
  if (isMasterCallback(url)) return 'OWNED_CALLBACK';
  const paths = new Map([
    ['/realms/master/login-actions/required-action', 'MASTER_REQUIRED_ACTION'],
    ['/realms/master/login-actions/authenticate', 'MASTER_LOGIN_ACTION'],
    ['/realms/master/login-actions/action-token', 'MASTER_ACTION_TOKEN'],
    ['/realms/master/protocol/openid-connect/auth', 'MASTER_AUTHORIZATION'],
    ['/realms/master/protocol/openid-connect/token', 'MASTER_TOKEN'],
    ['/admin/master/console/', 'MASTER_CONSOLE'],
  ]);
  return paths.get(url.pathname) || 'OWNED_OTHER';
}
