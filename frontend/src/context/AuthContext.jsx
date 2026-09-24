
import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from 'react';

import api, { refreshAccessToken } from '../api/axios.js';
import { isExpired } from '../utils/token.js';
import SessionWarningPopup from '../components/SessionWarningPopup';
import RiskWarningPopup from '../components/RiskWarningPopup';

const AuthContext = createContext(null);

const IDLE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes of inactivity
const WARNING_DURATION_MS = 30 * 1000; // 30 second warning

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showWarning, setShowWarning] = useState(false);
  const [timeUntilExpire, setTimeUntilExpire] = useState(0);

  const lastActivityRef = useRef(Date.now());

  /*
   * Logout
   * Defined before the effects that use it.
   */
  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      // Ignore network errors during logout.
    }

    localStorage.removeItem('ad_token');
    setUser(null);
    setShowWarning(false);
    setTimeUntilExpire(0);
  }, []);

  /*
   * Handle normal user activity.
   */
  const handleActivity = useCallback(() => {
    lastActivityRef.current = Date.now();

    setShowWarning(false);
    setTimeUntilExpire(0);
  }, []);

  /*
   * Load currently authenticated user.
   */
  const loadMe = useCallback(async () => {
    const token = localStorage.getItem('ad_token');

    if (!token) {
      setLoading(false);
      return;
    }

    // If access token has expired, try to refresh it.
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

  /*
   * Load user when AuthProvider starts.
   */
  useEffect(() => {
    loadMe();
  }, [loadMe]);

  /*
   * Idle timeout tracking.
   */
  useEffect(() => {
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

    const activityTypes = [
      'mousemove',
      'keydown',
      'click',
      'touchstart',
    ];

    activityTypes.forEach((type) => {
      document.addEventListener(type, handleActivity, {
        passive: true,
      });
    });

    return () => {
      clearInterval(idleTimeout);

      activityTypes.forEach((type) => {
        document.removeEventListener(type, handleActivity);
      });
    };
  }, [handleActivity, logout]);

  /*
   * Session warning popup.
   */
  useEffect(() => {
    if (!showWarning) {
      return;
    }

    const warningTimer = setTimeout(() => {
      logout();
    }, WARNING_DURATION_MS);

    const onUserActivity = () => {
      clearTimeout(warningTimer);

      setShowWarning(false);
      setTimeUntilExpire(0);
      lastActivityRef.current = Date.now();
    };

    const activityTypes = [
      'mousemove',
      'keydown',
      'click',
      'touchstart',
    ];

    activityTypes.forEach((type) => {
      document.addEventListener(type, onUserActivity, {
        passive: true,
      });
    });

    return () => {
      clearTimeout(warningTimer);

      activityTypes.forEach((type) => {
        document.removeEventListener(type, onUserActivity);
      });
    };
  }, [showWarning, logout]);

  /*
   * Login.
   */
  const loginWithToken = useCallback((token, userData) => {
    localStorage.setItem('ad_token', token);

    setUser(userData);

    lastActivityRef.current = Date.now();

    setShowWarning(false);
    setTimeUntilExpire(0);
  }, []);

  /*
   * Context value.
   */
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
        onKeepSignedIn={() => {
          lastActivityRef.current = Date.now();
          setShowWarning(false);
          setTimeUntilExpire(0);
        }}
      />

      {user && (
        <RiskWarningPopup
          onForceLogout={logout}
        />
      )}
    </AuthContext.Provider>
  );
}

/*
 * useAuth hook.
 */
export function useAuth() {
  const ctx = useContext(AuthContext);

  if (!ctx) {
    throw new Error(
      'useAuth must be used within an AuthProvider'
    );
  }

  return ctx;
}

