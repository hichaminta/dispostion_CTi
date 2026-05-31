const KEYCLOAK_URL = 'http://localhost:8080';
const REALM = 'cti-realm';
const CLIENT_ID = 'cti-client';
const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;

const TOKEN_KEY   = 'cti_token';
const REFRESH_KEY = 'cti_refresh_token';
const EXPIRY_KEY  = 'cti_token_expiry';
const USER_KEY    = 'cti_user';

export async function login(username, password) {
  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: CLIENT_ID, username, password }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    if (err.error_description === 'Account is not fully set up') {
      throw { requirePasswordChange: true, username, oldPassword: password };
    }
    throw new Error(err.error_description || 'Identifiants incorrects');
  }
  const data = await resp.json();
  _storeTokens(data);
  const userInfo = JSON.parse(atob(data.access_token.split('.')[1]));
  sessionStorage.setItem(USER_KEY, JSON.stringify(userInfo));
  return userInfo;
}

function _storeTokens(data) {
  const expiresAt = Date.now() + (data.expires_in - 30) * 1000; // 30s buffer
  sessionStorage.setItem(TOKEN_KEY,   data.access_token);
  sessionStorage.setItem(EXPIRY_KEY,  String(expiresAt));
  if (data.refresh_token) {
    sessionStorage.setItem(REFRESH_KEY, data.refresh_token);
  }
}

/** Returns the raw access token (may be expired — prefer getValidToken()) */
export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

/** Returns a fresh access token, silently refreshing via refresh_token if needed.
 *  Throws if unable to refresh (forces re-login). */
export async function getValidToken() {
  const expiry = Number(sessionStorage.getItem(EXPIRY_KEY) || '0');
  if (Date.now() < expiry) {
    return sessionStorage.getItem(TOKEN_KEY); // still valid
  }

  const refreshToken = sessionStorage.getItem(REFRESH_KEY);
  if (!refreshToken) {
    throw new Error('Session expirée. Veuillez vous reconnecter.');
  }

  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'refresh_token',
      client_id:     CLIENT_ID,
      refresh_token: refreshToken,
    }),
  });

  if (!resp.ok) {
    // Refresh token itself is expired — force logout
    logout();
    throw new Error('Session expirée. Veuillez vous reconnecter.');
  }

  const data = await resp.json();
  _storeTokens(data);
  // Update user info from new token payload
  const userInfo = JSON.parse(atob(data.access_token.split('.')[1]));
  sessionStorage.setItem(USER_KEY, JSON.stringify(userInfo));
  return data.access_token;
}

export function getUserInfo() {
  const raw = sessionStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function hasRole(role) {
  return getUserInfo()?.realm_access?.roles?.includes(role) ?? false;
}

export function logout() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(REFRESH_KEY);
  sessionStorage.removeItem(EXPIRY_KEY);
  sessionStorage.removeItem(USER_KEY);
}

/** Call on app start to check if stored session is still valid.
 *  Returns userInfo if OK, null if session is gone/unrefreshable. */
export async function checkSession() {
  if (!sessionStorage.getItem(TOKEN_KEY)) return null;
  try {
    await getValidToken();
    return getUserInfo();
  } catch {
    logout();
    return null;
  }
}
