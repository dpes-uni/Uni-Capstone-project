import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  withCredentials: true,
});

// Attach the bearer token (if we have one in localStorage) to every request.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ad_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;
