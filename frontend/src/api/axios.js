import axios from 'axios';
import { triggerReauth } from './reauth.js';

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

// On 401, try to refresh once and retry the failed request.
// On 403 with `reauthenticationRequired`, prompt the user to re-authenticate
// via the active session, then retry the original request.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { config, response } = error;
    const status = response ? response.status : null;

    if (status === 401 && !config.__isRetry) {
      config.__isRetry = true;
      try {
        const token = await refreshAccessToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
          return api(config);
        }
      } catch (refreshError) {
        localStorage.removeItem('ad_token');
      }
    }

    if (
      status === 403 &&
      response?.data?.reauthenticationRequired &&
      !config.__reauthRetry
    ) {
      config.__reauthRetry = true;
      try {
        await triggerReauth();
        config.headers.Authorization = `Bearer ${localStorage.getItem('ad_token')}`;
        return api(config);
      } catch (reauthError) {
        // User cancelled or re-authentication failed: force a logout.
        try {
          await api.post('/auth/logout');
        } catch {
          // ignore
        }
        localStorage.removeItem('ad_token');
        window.dispatchEvent(new Event('ad:force-logout'));
      }
    }

    return Promise.reject(error);
  }
);

export { refreshAccessToken };
export default api;
