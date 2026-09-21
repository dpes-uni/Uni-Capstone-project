import React, { useState } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import api from '../api/axios.js';
import { useAuth } from '../context/AuthContext.jsx';
import RiskBadge from '../components/RiskBadge.jsx';

export default function MfaVerify() {
  const location = useLocation();
  const navigate = useNavigate();
  const { loginWithToken, setUser } = useAuth();

  const { loginId, email, risk, devOtpCode, adminLogin } = location.state || {};
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!loginId) {
    return (
      <div className="page auth-page">
        <div className="auth-card">
          <h2>Nothing to verify</h2>
          <p className="auth-subtitle">Please sign in again to request a new code.</p>
          <p className="auth-switch">
            <Link to="/login">Back to sign in</Link>
          </p>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const { data } = await api.post('/auth/verify-mfa', { loginId, code });
      loginWithToken(data.token, data.user);
      setUser(data.user);
      navigate(data.user.role === 'admin' ? '/admin' : '/client');
    } catch (err) {
      setError(err.response?.data?.message || 'Something went wrong, please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Check your email</h2>
        <p className="auth-subtitle">
          We sent a 6-digit verification code to <strong>{email || 'your email address'}</strong>. Enter it to complete your sign-in.
        </p>

        {risk?.reasons?.length > 0 && (
          <ul className="risk-reasons">
            {risk.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        )}

        {devOtpCode && (
          <div className="alert alert-info">
            <strong>Dev mode:</strong> no SMTP server is configured, so here is your code: <code>{devOtpCode}</code>
          </div>
        )}

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <label htmlFor="code">6-digit code</label>
          <input
            id="code"
            type="text"
            inputMode="numeric"
            maxLength={6}
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            required
          />

          <button type="submit" className="btn btn-primary btn-block" disabled={loading || code.length !== 6}>
            {loading ? 'Verifying…' : 'Verify and sign in'}
          </button>
        </form>

        <p className="auth-switch">
          <Link to="/login">Back to sign in</Link>
        </p>
      </div>
    </div>
  );
}
