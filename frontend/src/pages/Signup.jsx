import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/axios.js';

export default function Signup() {
  const [form, setForm] = useState({ name: '', email: '', password: '', password2: '', role: 'student' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const update = (field) => (e) => setForm({ ...form, [field]: e.target.value });

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
      const { data } = await api.post('/auth/register', {
        name: form.name,
        email: form.email,
        password: form.password,
        role: form.role,
      });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.message || 'Something went wrong, please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (result) {
    return (
      <div className="page auth-page">
        <div className="auth-card">
          <h2>Check your email</h2>
          <p className="auth-subtitle">{result.message}</p>

          {result.devVerificationLink && (
            <div className="alert alert-info">
              <p><strong>Dev mode:</strong> no SMTP server is configured, so here is your verification link:</p>
              <p>
                <Link to={`/verify-email/${result.devVerificationToken}`}>
                  {result.devVerificationLink}
                </Link>
              </p>
            </div>
          )}

          <p className="auth-switch">
            <Link to="/login">Back to sign in</Link>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Create your account</h2>
        <p className="auth-subtitle">Start verifying identities in minutes.</p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <label htmlFor="name">Full name</label>
          <input id="name" type="text" placeholder="John Doe" value={form.name} onChange={update('name')} required />

          <label htmlFor="email">Email</label>
          <input id="email" type="email" placeholder="you@company.com" value={form.email} onChange={update('email')} required />

          <label htmlFor="role">Account type</label>
          <select id="role" value={form.role} onChange={update('role')}>
            <option value="student">Student</option>
            <option value="agent">Agent</option>
            <option value="institution">Institution</option>
          </select>

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            placeholder="At least 8 characters"
            value={form.password}
            onChange={update('password')}
            required
          />

          <label htmlFor="password2">Confirm password</label>
          <input
            id="password2"
            type="password"
            placeholder="Confirm password"
            value={form.password2}
            onChange={update('password2')}
            required
          />

          <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
            {loading ? 'Creating account…' : 'Create account'}
          </button>
        </form>

        <p className="auth-switch">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
