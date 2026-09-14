import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import api from '../api/axios.js';

export default function AdminSignup() {
  const navigate = useNavigate();
  const location = useLocation();
  const [form, setForm] = useState({ name: '', email: '', password: '', password2: '', signupKey: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const update = (field) => (e) => setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (form.password !== form.password2) {
      setError('Passwords do not match.');
      return;
    }
    if (form.password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    setLoading(true);
    try {
      const { data } = await api.post('/auth/admin-signup', {
        name: form.name,
        email: form.email,
        password: form.password,
        signupKey: form.signupKey,
      });

      navigate('/admin/verify-otp', {
        state: {
          signupId: data.signupId,
          email: data.email,
          devOtpCode: data.devOtpCode,
        },
      });
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to start administrator signup.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Create administrator account</h2>
        <p className="auth-subtitle">Verify your email with a one-time code before the admin account is created.</p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <label htmlFor="admin-name">Full name</label>
          <input id="admin-name" type="text" placeholder="Administrator name" value={form.name} onChange={update('name')} required />

          <label htmlFor="admin-signup-email">Gmail / email</label>
          <input id="admin-signup-email" type="email" placeholder="admin@gmail.com" value={form.email} onChange={update('email')} required />

          <label htmlFor="admin-password">Password</label>
          <input id="admin-password" type="password" placeholder="At least 8 characters" value={form.password} onChange={update('password')} required />

          <label htmlFor="admin-password2">Confirm password</label>
          <input id="admin-password2" type="password" placeholder="Confirm password" value={form.password2} onChange={update('password2')} required />

          <label htmlFor="admin-signup-key">Administrator signup key</label>
          <input id="admin-signup-key" type="password" placeholder="Enter the private signup key" value={form.signupKey} onChange={update('signupKey')} required />

          <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
            {loading ? 'Sending OTP…' : 'Continue & send OTP'}
          </button>
        </form>

        <p className="auth-switch">
          Already an administrator? <Link to="/admin/login">Admin sign in</Link>
        </p>
        <p className="auth-switch">
          <Link to="/login">Back to client sign in</Link>
        </p>
      </div>
    </div>
  );
}
