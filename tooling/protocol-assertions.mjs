export function isAuthorizationRefusal(status, location, expectedRedirect) {
  if (status >= 500) return false;
  if (!location) return status >= 400 && status < 500;
  const target = new URL(location);
  const expected = new URL(expectedRedirect);
  if (target.origin !== expected.origin || target.pathname !== expected.pathname) return false;
  const fragment = new URLSearchParams(target.hash.slice(1));
  for (const name of ['code', 'access_token', 'id_token']) {
    if (target.searchParams.has(name) || fragment.has(name)) return false;
  }
  return target.searchParams.has('error') || fragment.has('error');
}
