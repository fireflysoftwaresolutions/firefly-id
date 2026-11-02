export function selectNewRecoveryMessage(messages, previousIds, recipient) {
  return messages.find(message => !previousIds.has(message.ID)
    && message.To?.some(to => to.Address === recipient));
}

export function passwordResetOutcome(observed, expected) {
  let url;
  try { url = new URL(observed.url); } catch { return 'UNCONFIRMED'; }
  if (url.username || url.password || url.hash) return 'UNCONFIRMED';
  const callback = new URL(expected.redirect);
  if (url.origin === callback.origin && url.pathname === callback.pathname) {
    return url.searchParams.getAll('state').length === 1 && url.searchParams.get('state') === expected.state
      && url.searchParams.getAll('code').length === 1 && !!url.searchParams.get('code')
      && !url.searchParams.has('error') ? 'ACCEPTED_CALLBACK' : 'UNCONFIRMED';
  }
  const issuer = new URL(expected.issuer);
  if (url.origin !== issuer.origin || !url.pathname.startsWith(issuer.pathname + '/login-actions/')) return 'UNCONFIRMED';
  const messages = (observed.errors || []).map(value => value.trim().replace(/\s+/g, ' ')).filter(Boolean);
  if (messages.length) {
    if (messages.every(value => value === 'Invalid password: password is not allowed.')) return 'REFUSED_DENYLIST';
    if (messages.every(value => /^Invalid password: must not be equal to any of last \d+ passwords\.$/.test(value))) return 'REFUSED_HISTORY';
    if (messages.every(value => /^Invalid password: (minimum|maximum) length \d+\.$/.test(value))) return 'REFUSED_LENGTH';
    if (messages.every(value => ['Invalid password: must not be equal to the username.',
      'Invalid password: must not be equal to the email.', 'Invalid password: Can not contain the username.'].includes(value))) return 'REFUSED_IDENTITY';
    if (messages.every(value => value === "Password confirmation doesn't match.")) return 'REFUSED_CONFIRMATION';
    return 'REFUSED_OTHER';
  }
  return !observed.passwordForm && observed.success?.some(value => value.trim() === 'Your password has been updated.')
    ? 'ACCEPTED_MESSAGE' : 'UNCONFIRMED';
}
