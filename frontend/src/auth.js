const KEYCLOAK_URL = 'http://localhost:8080';
const REALM = 'cti-realm';
const CLIENT_ID = 'cti-client';
const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;

const TOKEN_KEY   = 'cti_token';
const REFRESH_KEY = 'cti_refresh_token';
const EXPIRY_KEY  = 'cti_token_expiry';
const USER_KEY    = 'cti_user';

function getStorage() {
  if (localStorage.getItem(TOKEN_KEY)) return localStorage;
  return sessionStorage;
}

export async function login(username, password, rememberMe = false) {
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
  const storage = rememberMe ? localStorage : sessionStorage;
  _storeTokens(data, storage);
  const userInfo = JSON.parse(atob(data.access_token.split('.')[1]));
  storage.setItem(USER_KEY, JSON.stringify(userInfo));
  return userInfo;
}

function _storeTokens(data, storage) {
  const expiresAt = Date.now() + (data.expires_in - 30) * 1000; // 30s buffer
  storage.setItem(TOKEN_KEY,   data.access_token);
  storage.setItem(EXPIRY_KEY,  String(expiresAt));
  if (data.refresh_token) {
    storage.setItem(REFRESH_KEY, data.refresh_token);
  }
}

/** Returns the raw access token (may be expired — prefer getValidToken()) */
export function getToken() {
  return getStorage().getItem(TOKEN_KEY);
}

/** Returns a fresh access token, silently refreshing via refresh_token if needed.
 *  Throws if unable to refresh (forces re-login). */
export async function getValidToken() {
  const storage = getStorage();
  const expiry = Number(storage.getItem(EXPIRY_KEY) || '0');
  if (Date.now() < expiry) {
    return storage.getItem(TOKEN_KEY); // still valid
  }

  const refreshToken = storage.getItem(REFRESH_KEY);
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
  _storeTokens(data, storage);
  // Update user info from new token payload
  const userInfo = JSON.parse(atob(data.access_token.split('.')[1]));
  storage.setItem(USER_KEY, JSON.stringify(userInfo));
  return data.access_token;
}

export function getUserInfo() {
  const raw = getStorage().getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function hasRole(role) {
  return getUserInfo()?.realm_access?.roles?.includes(role) ?? false;
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(EXPIRY_KEY);
  localStorage.removeItem(USER_KEY);

  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(REFRESH_KEY);
  sessionStorage.removeItem(EXPIRY_KEY);
  sessionStorage.removeItem(USER_KEY);
}

/** Call on app start to check if stored session is still valid.
 *  Returns userInfo if OK, null if session is gone/unrefreshable. */
export async function checkSession() {
  if (!getStorage().getItem(TOKEN_KEY)) return null;
  try {
    await getValidToken();
    return getUserInfo();
  } catch {
    logout();
    return null;
  }
}
