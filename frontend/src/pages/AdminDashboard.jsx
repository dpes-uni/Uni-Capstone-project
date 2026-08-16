import React, { useEffect, useState } from 'react';
import api from '../api/axios.js';

export default function AdminDashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const load = () => {
    setError('');
    api.get('/admin/overview')
      .then(({ data }) => setData(data))
      .catch((err) => setError(err.response?.data?.message || 'Failed to load admin dashboard.'));
  };

  useEffect(load, []);

  const changeRole = async (id, role) => {
    try {
      await api.patch(`/admin/users/${id}/role`, { role });
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update role.');
    }
  };

  if (!data) return <div className="page page-loading">{error || 'Loading administrator dashboard…'}</div>;

  return (
    <div className="page dashboard-page">
      <header className="page-header">
        <h1>Administrator Dashboard</h1>
        <p>Manage Assure Docs users and monitor authentication activity.</p>
      </header>

      {error && <div className="alert alert-error">{error}</div>}

      <section className="stat-grid">
        <div className="stat-card"><span className="stat-value">{data.stats.totalUsers}</span><span className="stat-label">Users</span></div>
        <div className="stat-card"><span className="stat-value">{data.stats.clients}</span><span className="stat-label">Clients</span></div>
        <div className="stat-card"><span className="stat-value">{data.stats.admins}</span><span className="stat-label">Administrators</span></div>
        <div className="stat-card"><span className="stat-value">{data.stats.verified}</span><span className="stat-label">Verified accounts</span></div>
      </section>

      <section className="panel">
        <h2>User management</h2>
        <table className="table">
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Verified</th><th>Last login</th><th>Change role</th></tr></thead>
          <tbody>
            {data.users.map((u) => (
              <tr key={u._id}>
                <td>{u.name}</td>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>{u.isVerified ? 'Yes' : 'No'}</td>
                <td>{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : '—'}</td>
                <td>
                  <select value={u.role} onChange={(e) => changeRole(u._id, e.target.value)}>
                    <option value="student">Student</option>
                    <option value="agent">Agent</option>
                    <option value="institution">Institution</option>
                    <option value="admin">Admin</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Recent authentication activity</h2>
        <table className="table">
          <thead><tr><th>Date</th><th>User</th><th>Risk</th><th>MFA</th><th>Result</th></tr></thead>
          <tbody>
            {data.recentActivity.map((a) => (
              <tr key={a._id}>
                <td>{new Date(a.createdAt).toLocaleString()}</td>
                <td>{a.user?.email || 'Unknown'}</td>
                <td>{a.riskLevel || '—'}</td>
                <td>{a.mfaRequired ? (a.mfaVerified ? 'Verified' : 'Pending') : 'Not required'}</td>
                <td>{a.success ? 'Success' : 'Failed'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
