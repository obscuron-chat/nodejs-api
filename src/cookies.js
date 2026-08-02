function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  for (const pair of header.split(';')) {
    const index = pair.indexOf('=');
    if (index === -1) continue;
    const key = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (!key) continue;
    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = undefined;
    }
  }
  return cookies;
}

function refreshCookie(config, token) {
  const secure = config.nodeEnv === 'production' ? 'Secure; ' : 'Secure; ';
  return `${config.refreshCookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; ${secure}SameSite=Strict`;
}

function clearRefreshCookie(config) {
  return `${config.refreshCookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

module.exports = {
  clearRefreshCookie,
  parseCookies,
  refreshCookie
};
