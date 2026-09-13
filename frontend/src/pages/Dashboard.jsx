import React, { useEffect, useState, useCallback } from 'react';
import api from '../api/axios.js';
import RiskBadge from '../components/RiskBadge.jsx';

// DEBUG: Remove before submission
function DebugPanel() {
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const triggerRisk = useCallback(async () => {
    setLoading(true);
    setMsg('');
    try {
      const { data } = await api.post('/debug/trigger-session-risk');
      setMsg(data.message || 'Session flagged.');
    } catch (err) {
      setMsg(err.response?.data?.message || 'Failed to trigger risk.');
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <section className="panel" style={{ border: '2px dashed #e74c3c', background: '#fdf2f2' }}>
      <h2 style={{ color: '#e74c3c' }}>Debug: Session Risk Trigger</h2>
      <p>Click the button below to manually flag your session as high-risk. The termination popup will appear on the next API call, and the session will be terminated after 30 seconds.</p>
      <button className="btn-primary" onClick={triggerRisk} disabled={loading}>
        {loading ? 'Flagging…' : 'Simulate High-Risk Session'}
      </button>
      {msg && <p style={{ marginTop: '0.75rem', fontWeight: 600 }}>{msg}</p>}
    </section>
  );
}
// END DEBUG

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    api
      .get('/users/dashboard-summary')
      .then(({ data }) => {
        if (!cancelled) setSummary(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.message || 'Failed to load dashboard.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <div className="page page-loading">Loading dashboard…</div>;
  if (error) return <div className="page"><div className="alert alert-error">{error}</div></div>;

  const { user, stats, recentActivity } = summary;

  return (
    <div className="page dashboard-page">
      <header className="page-header">
        <h1>Welcome back, {user.name.split(' ')[0]}</h1>
        <p>Here's what's happening with your account.</p>
      </header>

      <section className="stat-grid">
        <div className="stat-card">
          <span className="stat-value">{stats.totalSuccessfulLogins}</span>
          <span className="stat-label">Successful logins</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{stats.highRiskLogins}</span>
          <span className="stat-label">High-risk logins flagged</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{stats.trustedDevices}</span>
          <span className="stat-label">Trusted devices</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{stats.assessmentsByStatus.verified || 0}</span>
          <span className="stat-label">Assessments verified</span>
        </div>
      </section>

      <section className="panel">
        <h2>Recent login activity</h2>
        {recentActivity.length === 0 ? (
          <p className="empty-state">No login activity yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Date</th>
                <th>IP address</th>
                <th>Risk</th>
                <th>MFA</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {recentActivity.map((a) => (
                <tr key={a._id}>
                  <td>{new Date(a.createdAt).toLocaleString()}</td>
                  <td>{a.ip}</td>
                  <td><RiskBadge level={a.riskLevel} /></td>
                  <td>{a.mfaRequired ? (a.mfaVerified ? 'Verified' : 'Pending') : 'Not required'}</td>
                  <td>{a.success ? 'Success' : 'Failed'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2>Account</h2>
        <dl className="detail-list">
          <dt>Email</dt>
          <dd>{user.email}</dd>
          <dt>Role</dt>
          <dd>{user.role}</dd>
          <dt>Verified</dt>
          <dd>{user.isVerified ? 'Yes' : 'No'}</dd>
          <dt>Last login</dt>
          <dd>{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : '—'}</dd>
        </dl>
      </section>

      {/* DEBUG: Remove before submission */}
      {import.meta.env.DEV && (
        <DebugPanel />
      )}
      {/* END DEBUG */}
    </div>
  );
}
