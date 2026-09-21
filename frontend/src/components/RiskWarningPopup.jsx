import React, { useState, useEffect, useCallback } from 'react';
import api from '../api/axios.js';

export default function RiskWarningPopup({ onForceLogout }) {
  const [show, setShow] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const [reason, setReason] = useState('');

  const handleForceLogout = useCallback(() => {
    setShow(false);
    setCountdown(0);
    setReason('');
    if (onForceLogout) onForceLogout();
  }, [onForceLogout]);

  // Poll the backend for session risk status.
  // When the popup is visible, poll every second so the countdown stays
  // synced with the server-side 30-second grace period.
  // When hidden, poll every 15 seconds to detect when a session becomes risky.
  useEffect(() => {
    let cancelled = false;

    const checkSession = async () => {
      try {
        const { data } = await api.get('/users/session-timeout');
        if (cancelled) return;

        if (data.highRiskTerminate) {
          // Grace period expired — force logout immediately
          handleForceLogout();
          return;
        }

        if (data.requiresReauthentication || data.riskLevel === 'high') {
          const secs = Math.max(0, Math.ceil((data.timeUntilExpire || 0) / 1000));
          setCountdown(secs);
          setReason(
            data.requiresReauthentication
              ? 'Suspicious activity detected on your session.'
              : 'High-risk activity detected on your session.'
          );
          setShow(true);
        } else {
          // Session is no longer risky (user re-authenticated)
          setShow(false);
          setCountdown(0);
          setReason('');
        }
      } catch {
        // Ignore errors — session check is best-effort
      }
    };

    checkSession();
    const interval = setInterval(checkSession, show ? 1000 : 15000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [show, handleForceLogout]);

  if (!show) return null;

  return (
    <div className="risk-warning-overlay">
      <div className="risk-warning-popup">
        <div className="risk-warning-icon">&#9888;</div>
        <h3>Session Termination Warning</h3>
        <p className="risk-warning-reason">{reason}</p>
        <p className="risk-warning-countdown">
          Your session will be terminated in <strong>{countdown}</strong> seconds.
        </p>
        <p className="risk-warning-save">Please save any unsaved work now.</p>
        <div className="risk-warning-actions">
          <button className="btn-primary" onClick={handleForceLogout}>
            Log out now
          </button>
        </div>
      </div>
    </div>
  );
}
