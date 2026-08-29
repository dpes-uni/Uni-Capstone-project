import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api, { refreshAccessToken } from '../api/axios.js';
import { isExpired } from '../utils/token.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadMe = useCallback(async () => {
    const token = localStorage.getItem('ad_token');
    if (!token) {
      setLoading(false);
      return;
    }

    // If the access token already expired, trade the refresh cookie for a fresh one first.
    if (isExpired(token)) {
      try {
        const newToken = await refreshAccessToken();
        if (!newToken) {
          localStorage.removeItem('ad_token');
          setUser(null);
          setLoading(false);
          return;
        }
      } catch {
        localStorage.removeItem('ad_token');
        setUser(null);
        setLoading(false);
        return;
      }
    }

    try {
      const { data } = await api.get('/auth/me');
      setUser(data.user);
    } catch {
      localStorage.removeItem('ad_token');
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  const loginWithToken = (token, userData) => {
    localStorage.setItem('ad_token', token);
    setUser(userData);
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      // ignore network errors on logout
    }
    localStorage.removeItem('ad_token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, setUser, loading, loginWithToken, logout, refresh: loadMe }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
