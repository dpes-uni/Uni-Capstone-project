import React, { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/axios.js';
import { setReauthHandler } from '../api/reauth.js';
import { useAuth } from '../context/AuthContext.jsx';

export default function ReauthModal() {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [reauthId, setReauthId] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [devOtp, setDevOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const resolverRef = useRef(null);

  // Called by the axios interceptor. Opens the dialog and resolves once the
  // user has successfully re-authenticated, or rejects if they cancel/abort.
  const run = useCallback(() => {
    return new Promise((resolve, reject) => {
      resolverRef.current = { resolve, reject };
      setOpen(true);
      setError('');
      setCode('');
      setDevOtp('');
      requestCode();
    });
  }, []);

  const requestCode = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post('/auth/reauth/request');
      setReauthId(data.reauthId);
      if (data.devOtpCode) {
        setDevOtp(data.devOtpCode);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Could not start re-authentication.');
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
        await api.post('/auth/reauth/verify', { reauthId, code });
        setOpen(false);
        resolverRef.current?.resolve();
      } catch (err) {
        setError(err.response?.data?.message || 'Verification failed. Please try again.');
      } finally {
        setLoading(false);
      }
    },
    [reauthId, code]
  );

  const cancel = useCallback(() => {
    setOpen(false);
    resolverRef.current?.reject(new Error('reauth-cancelled'));
  }, []);

  useEffect(() => {
    setReauthHandler(run);
    return () => setReauthHandler(null);
  }, [run]);

  if (!open) {
    return null;
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
      <div className="modal-card">
        <h2 id="reauth-title">Verification required</h2>
        <p className="modal-subtitle">
          For your security, we need to confirm it&rsquo;s you. A one-time code was sent to{' '}
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
