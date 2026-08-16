import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import api from '../api/axios.js';

export default function Signup() {
  const [form, setForm] = useState({ name: '', email: '', password: '', password2: '', role: 'student' });
  const [signup, setSignup] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const update = (field) => (e) => setForm({ ...form, [field]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (form.password !== form.password2) return setError('Passwords do not match.');
    if (form.password.length < 8) return setError('Password must be at least 8 characters.');

    setLoading(true);
    try {
      const { data } = await api.post('/auth/register', {
        name: form.name,
        email: form.email,
        password: form.password,
        role: form.role,
      });
      setSignup(data);
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to start signup.');
    } finally {
      setLoading(false);
    }
  };

  const verify = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.post('/auth/register/verify', { signupId: signup.signupId, code });
      navigate('/login', { state: { successMessage: 'Account created successfully. Please sign in.' } });
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to verify the OTP.');
    } finally {
      setLoading(false);
    }
  };

  if (signup) {
    return (
      <div className="page auth-page">
        <div className="auth-card">
          <h2>Verify your email</h2>
          <p className="auth-subtitle">A 6-digit OTP was sent to <strong>{signup.email}</strong>.</p>
          {error && <div className="alert alert-error">{error}</div>}
          {signup.devOtpCode && (
            <div className="alert alert-info"><strong>Dev mode OTP:</strong> {signup.devOtpCode}</div>
          )}
          <form onSubmit={verify}>
            <label htmlFor="signup-code">6-digit OTP</label>
            <input id="signup-code" type="text" inputMode="numeric" maxLength={6} autoFocus
              placeholder="123456" value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} required />
            <button className="btn btn-primary btn-block" disabled={loading || code.length !== 6}>
              {loading ? 'Verifying…' : 'Verify email and create account'}
            </button>
          </form>
          <p className="auth-switch"><Link to="/signup">Start again</Link></p>
        </div>
      </div>
    );
  }

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Create your account</h2>
        <p className="auth-subtitle">A verification code will be sent to your Gmail before your account is created.</p>
        {error && <div className="alert alert-error">{error}</div>}
        <form onSubmit={handleSubmit}>
          <label htmlFor="name">Full name</label>
          <input id="name" type="text" placeholder="John Doe" value={form.name} onChange={update('name')} required />
          <label htmlFor="email">Email</label>
          <input id="email" type="email" placeholder="you@company.com" value={form.email} onChange={update('email')} required />
          <label htmlFor="role">Account type</label>
          <select id="role" value={form.role} onChange={update('role')}>
            <option value="student">Student</option><option value="agent">Agent</option><option value="institution">Institution</option>
          </select>
          <label htmlFor="password">Password</label>
          <input id="password" type="password" placeholder="At least 8 characters" value={form.password} onChange={update('password')} required />
          <label htmlFor="password2">Confirm password</label>
          <input id="password2" type="password" placeholder="Confirm password" value={form.password2} onChange={update('password2')} required />
          <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
            {loading ? 'Sending OTP…' : 'Continue and send OTP'}
          </button>
        </form>
        <p className="auth-switch">Already have an account? <Link to="/login">Sign in</Link></p>
      </div>
    </div>
  );
}
