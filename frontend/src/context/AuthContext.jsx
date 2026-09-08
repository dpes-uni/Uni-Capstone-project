import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import api, { refreshAccessToken } from '../api/axios.js';
import { isExpired } from '../utils/token.js';
import SessionWarningPopup from '../components/SessionWarningPopup';
import RiskWarningPopup from '../components/RiskWarningPopup';

const AuthContext = createContext(null);

const IDLE_TIMEOUT_MS = 1.5 * 60 * 1000; // 1.5 minutes of inactivity
const WARNING_DURATION_MS = 30 * 1000; // 30 second warning before timeout

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showWarning, setShowWarning] = useState(false);
  const [timeUntilExpire, setTimeUntilExpire] = useState(0);

  const lastActivityRef = useRef(Date.now());

  const handleActivity = useCallback(() => {
    lastActivityRef.current = Date.now();
    const timeSinceLast = Date.now() - lastActivityRef.current;
    const timeLeft = Math.max(0, IDLE_TIMEOUT_MS - timeSinceLast);

    if (timeLeft < WARNING_DURATION_MS && timeLeft > 0) {
      setShowWarning(true);
      setTimeUntilExpire(timeLeft);
    }
  }, []);

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

  useEffect(() => {
    // Track user activity for idle timeout
    const idleTimeout = setInterval(() => {
      const timeSinceLast = Date.now() - lastActivityRef.current;
      const timeLeft = IDLE_TIMEOUT_MS - timeSinceLast;

      if (timeLeft <= 0) {
        clearInterval(idleTimeout);
        logout();
      } else if (timeLeft < WARNING_DURATION_MS) {
        setShowWarning(true);
        setTimeUntilExpire(timeLeft);
      }
    }, 1000);

    // Reset idle timer on user activity
    const activityListeners = ['mousemove', 'keydown', 'click', 'touchstart'].map(
      (type) => document.addEventListener(type, handleActivity, { passive: true })
    );

    return () => {
      clearInterval(idleTimeout);
      activityListeners.forEach((remove) => document.removeEventListener(type, remove));
    };
  }, [handleActivity]);

  // Warning popup effect - auto-close after warning duration or on user action
  useEffect(() => {
    if (!showWarning) return;

    const warningTimer = setTimeout(() => {
      logout();
    }, WARNING_DURATION_MS);

    const onUserActivity = () => {
      clearTimeout(warningTimer);
      setShowWarning(false);
      setTimeUntilExpire(0);
    };

    const activityListeners = ['mousemove', 'keydown', 'click', 'touchstart'].map(
      (type) => document.addEventListener(type, onUserActivity, { passive: true })
    );

    return () => {
      clearTimeout(warningTimer);
      activityListeners.forEach((remove) => document.removeEventListener(type, onUserActivity));
    };
  }, [showWarning, logout]);

  const loginWithToken = (token, userData) => {
    localStorage.setItem('ad_token', token);
    setUser(userData);
    lastActivityRef.current = Date.now();
    setShowWarning(false);
    setTimeUntilExpire(0);
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      // ignore network errors on logout
    }
    localStorage.removeItem('ad_token');
    setUser(null);
    setShowWarning(false);
    setTimeUntilExpire(0);
  };

  const value = {
    user,
    setUser,
    loading,
    loginWithToken,
    logout,
    showWarning,
    timeUntilExpire,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
      <SessionWarningPopup
        showWarning={showWarning}
        timeUntilExpire={timeUntilExpire}
        onLogOut={logout}
        onKeepSignedIn={() => setShowWarning(false)}
      />
      {user && <RiskWarningPopup onForceLogout={logout} />}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}