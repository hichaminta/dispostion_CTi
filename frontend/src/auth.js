const API_URL = '/api/auth/token';

const TOKEN_KEY   = 'cti_token';
const EXPIRY_KEY  = 'cti_token_expiry';
const USER_KEY    = 'cti_user';

function getStorage() {
  if (localStorage.getItem(TOKEN_KEY)) return localStorage;
  return sessionStorage;
}

export async function login(username, password, rememberMe = false) {
  const resp = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', username, password }),
  });
  
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.detail || 'Identifiants incorrects');
  }
  
  const data = await resp.json();
  const storage = rememberMe ? localStorage : sessionStorage;
  
  const expiresAt = Date.now() + (data.expires_in - 30) * 1000;
  storage.setItem(TOKEN_KEY, data.access_token);
  storage.setItem(EXPIRY_KEY, String(expiresAt));
  
  const userInfo = JSON.parse(atob(data.access_token.split('.')[1]));
  storage.setItem(USER_KEY, JSON.stringify(userInfo));
  return userInfo;
}

export function getToken() {
  return getStorage().getItem(TOKEN_KEY);
}

export async function getValidToken() {
  const storage = getStorage();
  const expiry = Number(storage.getItem(EXPIRY_KEY) || '0');
  
  if (Date.now() < expiry) {
    return storage.getItem(TOKEN_KEY);
  }

  logout();
  throw new Error('Session expirée. Veuillez vous reconnecter.');
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
  localStorage.removeItem(EXPIRY_KEY);
  localStorage.removeItem(USER_KEY);

  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(EXPIRY_KEY);
  sessionStorage.removeItem(USER_KEY);
}

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
