import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import api from '../api/axios.js';
import { useAuth } from '../context/AuthContext.jsx';

export default function AdminLogin() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { loginWithToken } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const successMessage = location.state?.successMessage || '';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/auth/login', { email, password, adminOnly: true });
      navigate('/verify-mfa', {
        state: { loginId: data.loginId, email, risk: data.risk, devOtpCode: data.devOtpCode, adminLogin: true },
      });
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to sign in.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Administrator sign in</h2>
        <p className="auth-subtitle">Use your administrator email and password.</p>
        {successMessage && <div className="alert alert-success">{successMessage}</div>}
        {error && <div className="alert alert-error">{error}</div>}
        <form onSubmit={handleSubmit}>
          <label htmlFor="admin-email">Email</label>
          <input id="admin-email" type="email" placeholder="admin@assuredocs.com" value={email}
            onChange={(e) => setEmail(e.target.value)} required />
          <label htmlFor="admin-password">Password</label>
          <input id="admin-password" type="password" placeholder="Enter your password" value={password}
            onChange={(e) => setPassword(e.target.value)} required />
          <button className="btn btn-primary btn-block" disabled={loading}>
            {loading ? 'Signing in…' : 'Admin sign in'}
          </button>
        </form>
        <p className="auth-switch">Need an admin account? <Link to="/admin/signup">Create administrator account</Link></p>
        <p className="auth-switch"><Link to="/login">Back to client sign in</Link></p>
      </div>
    </div>
  );
}
