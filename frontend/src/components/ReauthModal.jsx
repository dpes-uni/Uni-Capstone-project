import React, { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/axios.js';
import {
  setReauthHandler,
  setStepUpHandler,
} from '../api/reauth.js';
import { useAuth } from '../context/AuthContext.jsx';

// Default per-action wording for step-up MFA. Keep this list short — these
// are the genuinely security-sensitive operations the backend enforces.
const STEP_UP_ACTION_COPY = {
  document_upload: 'upload this document',
  document_download: 'view this document',
  document_review: 'verify or reject this document',
  admin_document_download: 'view this document',
  user_role_change: 'change this user’s role',
};

export default function ReauthModal() {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState('reauth'); // 'reauth' | 'stepup'
  const [actionLabel, setActionLabel] = useState(null);
  const [reauthId, setReauthId] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [devOtp, setDevOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const resolverRef = useRef(null);

  // Reset modal state whenever it opens.
  const resetState = useCallback(() => {
    setError('');
    setCode('');
    setDevOtp('');
    setReauthId(null);
  }, []);

  const openModal = useCallback(
    (nextMode, label) => {
      resolverRef.current = { resolve: () => {}, reject: () => {} };
      setMode(nextMode);
      setActionLabel(label || null);
      setOpen(true);
      resetState();
      return new Promise((resolve, reject) => {
        resolverRef.current = { resolve, reject };
      });
    },
    [resetState]
  );

  // Risk-based re-authentication handler.
  const runReauth = useCallback(() => {
    return openModal('reauth', null).then(() => requestCode('/auth/reauth/request'));
  }, [openModal]);

  // Step-up MFA handler. `label` may be a short action key (e.g. 'document_upload')
  // or null for the generic prompt.
  const runStepUp = useCallback(
    (label) => {
      const copy =
        (label && STEP_UP_ACTION_COPY[label]) ||
        (typeof label === 'string' && label) ||
        null;
      return openModal('stepup', copy).then(() => requestCode('/auth/stepup/request'));
    },
    [openModal]
  );

  const requestCode = useCallback(async (endpoint) => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post(endpoint);
      setReauthId(data.reauthId);
      if (data.devOtpCode) {
        setDevOtp(data.devOtpCode);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Could not start verification.');
    } finally {
      setLoading(false);
    }
  }, []);

  const submit = useCallback(
    async (e) => {
      e.preventDefault();
      if (!reauthId) {
        return;
      }
      setLoading(true);
      setError('');
      try {
        const endpoint =
          mode === 'stepup' ? '/auth/stepup/verify' : '/auth/reauth/verify';
        await api.post(endpoint, { reauthId, code });
        setOpen(false);
        resolverRef.current?.resolve();
      } catch (err) {
        setError(err.response?.data?.message || 'Verification failed. Please try again.');
      } finally {
        setLoading(false);
      }
    },
    [reauthId, code, mode]
  );

  const cancel = useCallback(() => {
    setOpen(false);
    resolverRef.current?.reject(new Error('verification-cancelled'));
  }, []);

  useEffect(() => {
    setReauthHandler(runReauth);
    setStepUpHandler(runStepUp);
    return () => {
      setReauthHandler(null);
      setStepUpHandler(null);
    };
  }, [runReauth, runStepUp]);

  if (!open) {
    return null;
  }

  const isStepUp = mode === 'stepup';
  const title = isStepUp ? 'Additional verification required' : 'Verification required';
  const subtitle = isStepUp
    ? actionLabel
      ? `For your security, please confirm it’s you before you ${actionLabel}. A one-time code was sent to `
      : 'For your security, additional verification is required for this action. A one-time code was sent to '
    : 'For your security, we need to confirm it’s you. A one-time code was sent to ';

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
      <div className="modal-card">
        <h2 id="reauth-title">{title}</h2>
        <p className="modal-subtitle">
          {subtitle}
          <strong>{user?.email || 'your email'}</strong>.
        </p>

        {devOtp && (
          <p className="modal-dev-otp">
            Dev mode &mdash; your code is: <strong>{devOtp}</strong>
          </p>
        )}

        <form onSubmit={submit}>
          <label htmlFor="reauth-code">Verification code</label>
          <input
            id="reauth-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            disabled={loading}
            autoFocus
          />

          {error && <p className="modal-error">{error}</p>}

          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={cancel} disabled={loading}>
              Log out instead
            </button>
            <button type="submit" className="btn-primary" disabled={loading || code.length < 6}>
              {loading ? 'Verifying…' : 'Verify'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}