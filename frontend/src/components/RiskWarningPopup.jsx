import React, { useState, useEffect, useCallback } from 'react';
import api from '../api/axios.js';

const HIGH_RISK_TERMINATE_MS = 30 * 1000; // 30 seconds before forced termination

export default function RiskWarningPopup({ onForceLogout }) {
  const [show, setShow] = useState(false);
  const [countdown, setCountdown] = useState(30);
  const [reason, setReason] = useState('');

  const handleForceLogout = useCallback(() => {
    setShow(false);
    setCountdown(30);
    setReason('');
    if (onForceLogout) onForceLogout();
  }, [onForceLogout]);

  useEffect(() => {
    if (!show) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          handleForceLogout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [show, handleForceLogout]);

  useEffect(() => {
    let cancelled = false;
    let pollTimer = null;

    const checkSession = async () => {
      try {
        const { data } = await api.get('/users/session-timeout');
        if (cancelled) return;

        if (data.riskLevel === 'high' || data.requiresReauthentication || data.highRiskTerminate) {
          setReason(data.requiresReauthentication
            ? 'Suspicious activity detected on your session.'
            : 'High-risk activity detected on your session.');
          setShow(true);
        }
      } catch {
        // Ignore errors — session check is best-effort
      }
    };

    checkSession();
    pollTimer = setInterval(checkSession, 15000); // Check every 15 seconds

    return () => {
      cancelled = true;
      if (pollTimer) clearInterval(pollTimer);
    };
  }, []);

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