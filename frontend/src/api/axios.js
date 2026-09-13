import axios from 'axios';
import { triggerReauth, triggerStepUp } from './reauth.js';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  withCredentials: true,
});

// Attach the bearer access token to every request.
api.interceptors.request.use(async (config) => {
  const token = localStorage.getItem('ad_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Single in-flight refresh so concurrent expired requests don't trigger N refreshes.
let pendingRefresh = null;

/** Refresh the short-lived access token using the httpOnly refresh cookie. */
async function refreshAccessToken() {
  if (pendingRefresh) {
    return pendingRefresh;
  }

  pendingRefresh = api
    .post('/auth/refresh')
    .then(({ data }) => {
      if (data.token) {
        localStorage.setItem('ad_token', data.token);
      }
      return data.token;
    })
    .finally(() => {
      pendingRefresh = null;
    });

  return pendingRefresh;
}

/**
 * Force logout: call /auth/logout server-side, clear local token, dispatch
 * the custom force-logout event so AuthContext clears its state.
 */
async function forceLogout() {
  try {
    await api.post('/auth/logout');
  } catch {
    // ignore server-side logout errors
  }
  localStorage.removeItem('ad_token');
  window.dispatchEvent(new Event('ad:force-logout'));
}

// On 401, try to refresh once and retry the failed request.
// On 403 with `stepUpRequired: true`, prompt for step-up MFA, retry on success.
// On 403 with `reauthenticationRequired: true`, prompt for risk-based reauth, retry on success.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { config, response } = error;
    const status = response ? response.status : null;
    const body = response?.data || {};

    // Backend force-terminated the session (high-risk grace period expired).
    // Clear everything and force a reload to the login page.
    // This check MUST come before the token refresh logic — a terminated
    // session cannot be recovered by refreshing the access token because
    // the refresh token has already been revoked server-side.
    if (status === 401 && response?.data?.sessionTerminated) {
      localStorage.removeItem('ad_token');
      window.dispatchEvent(new Event('ad:force-logout'));
      return Promise.reject(error);
    }

    // ── 401: Token expired — attempt a single refresh. ──────────────────────
    if (status === 401 && !config.__isRetry) {
      config.__isRetry = true;
      try {
        const token = await refreshAccessToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
          return api(config);
        }
      } catch {
        // Refresh failed — fall through to logout.
      }
      await forceLogout();
      return Promise.reject(error);
    }

    // ── 403: Step-up MFA required ─────────────────────────────────────────────
    // Run BEFORE the risk-based reauth check so that step-up takes priority
    // when the user is on a sensitive-action path. A step-up verification does
    // NOT clear requiresReauthentication on the backend, so a subsequent request
    // will still trigger the risk-based flow if needed.
    if (
      status === 403 &&
      body.stepUpRequired === true &&
      !config.__stepUpRetry
    ) {
      config.__stepUpRetry = true;
      try {
        // `action` is an optional human-readable description the backend can
        // include to make the modal copy more specific.
        const actionLabel = body.action || null;
        await triggerStepUp(actionLabel);
        config.headers.Authorization = `Bearer ${localStorage.getItem('ad_token')}`;
        return api(config);
      } catch {
        // User cancelled or step-up verification failed — force logout.
        await forceLogout();
      }
      return Promise.reject(error);
    }

    // ── 403: Risk-based re-authentication required ───────────────────────────
    if (
      status === 403 &&
      body.reauthenticationRequired &&
      !config.__reauthRetry
    ) {
      config.__reauthRetry = true;
      try {
        await triggerReauth();
        config.headers.Authorization = `Bearer ${localStorage.getItem('ad_token')}`;
        return api(config);
      } catch {
        await forceLogout();
      }
      return Promise.reject(error);
    }

    return Promise.reject(error);
  }
);

export { refreshAccessToken };
export default api;