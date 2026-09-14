import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import api from '../api/axios.js';

export default function AdminSignupVerify() {
  const location = useLocation();
  const navigate = useNavigate();
  const { signupId, email, devOtpCode } = location.state || {};
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!signupId) {
    return (
      <div className="page auth-page">
        <div className="auth-card">
          <h2>No pending signup</h2>
          <p className="auth-subtitle">Start the administrator signup again to request a new OTP.</p>
          <p className="auth-switch"><Link to="/admin/signup">Back to admin signup</Link></p>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (code.length !== 6) {
      setError('Enter the 6-digit OTP sent to your email.');
      return;
    }

    setLoading(true);
    try {
      const { data } = await api.post('/auth/admin-signup/verify', { signupId, code });
      navigate('/admin/login', {
        replace: true,
        state: { successMessage: data.message },
      });
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to verify the OTP.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Verify administrator email</h2>
        <p className="auth-subtitle">
          We sent a 6-digit verification code to <strong>{email}</strong>.
        </p>

        {devOtpCode && (
          <div className="alert alert-info">
            <strong>Development mode:</strong> SMTP is not configured. OTP: <code>{devOtpCode}</code>
          </div>
        )}

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <label htmlFor="admin-otp">6-digit OTP</label>
          <input
            id="admin-otp"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            required
          />

          <button type="submit" className="btn btn-primary btn-block" disabled={loading || code.length !== 6}>
            {loading ? 'Verifying…' : 'Verify & create admin account'}
          </button>
        </form>

        <p className="auth-switch"><Link to="/admin/signup">Start over</Link></p>
      </div>
    </div>
  );
}
