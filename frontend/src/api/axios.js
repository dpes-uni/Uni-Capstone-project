import axios from 'axios';

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

    return Promise.reject(error);
  }
);

export { refreshAccessToken };
export default api;
