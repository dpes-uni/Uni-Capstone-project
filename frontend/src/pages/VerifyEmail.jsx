import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/axios.js';

export default function VerifyEmail() {
  const { token } = useParams();
  const [status, setStatus] = useState('loading'); // loading | success | error
  const [message, setMessage] = useState('');

  useEffect(() => {
    let cancelled = false;

    api
      .get(`/auth/verify-email/${token}`)
      .then(({ data }) => {
        if (cancelled) return;
        setStatus('success');
        setMessage(data.message);
      })
      .catch((err) => {
        if (cancelled) return;
        setStatus('error');
        setMessage(err.response?.data?.message || 'Verification failed.');
      });

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div className="page auth-page">
      <div className="auth-card">
        <h2>Email verification</h2>
        {status === 'loading' && <p className="auth-subtitle">Verifying your email…</p>}
        {status === 'success' && <div className="alert alert-success">{message}</div>}
        {status === 'error' && <div className="alert alert-error">{message}</div>}

        <p className="auth-switch">
          <Link to="/login">Go to sign in</Link>
        </p>
      </div>
    </div>
  );
}
