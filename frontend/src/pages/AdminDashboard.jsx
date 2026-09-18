import React, { useEffect, useState } from 'react';
import api from '../api/axios.js';

const STATUS_LABELS = {
  pending: 'Pending',
  in_review: 'In review',
  verified: 'Verified',
  rejected: 'Rejected',
};

const DOC_TYPE_LABELS = {
  passport: 'Passport',
  national_id: 'National ID',
  drivers_license: "Driver's license",
  academic_transcript: 'Academic transcript',
  other: 'Other',
};

export default function AdminDashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const [assessments, setAssessments] = useState([]);
  const [assessmentsLoading, setAssessmentsLoading] = useState(true);
  const [assessmentsError, setAssessmentsError] = useState('');
  const [viewingId, setViewingId] = useState(null);
  const [reviewingId, setReviewingId] = useState(null);

  const load = () => {
    setError('');
    api.get('/admin/overview')
      .then(({ data }) => setData(data))
      .catch((err) => setError(err.response?.data?.message || 'Failed to load admin dashboard.'));
  };

  const loadAssessments = () => {
    setAssessmentsLoading(true);
    api.get('/admin/assessments')
      .then(({ data }) => setAssessments(data.assessments))
      .catch((err) => setAssessmentsError(err.response?.data?.message || 'Failed to load assessments.'))
      .finally(() => setAssessmentsLoading(false));
  };

  useEffect(load, []);
  useEffect(loadAssessments, []);

  const changeRole = async (id, role) => {
    try {
      await api.patch(`/admin/users/${id}/role`, { role });
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update role.');
    }
  };

  const viewDocument = async (id) => {
    setAssessmentsError('');
    setViewingId(id);
    try {
      const response = await api.get(`/admin/assessments/${id}/document`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(response.data);
      window.open(url, '_blank', 'noopener,noreferrer');
    } catch (err) {
      setAssessmentsError('Failed to open document.');
    } finally {
      setViewingId(null);
    }
  };

  const review = async (id, status) => {
    setAssessmentsError('');
    setReviewingId(id);
    try {
      await api.patch(`/admin/assessments/${id}/review`, { status });
      loadAssessments();
    } catch (err) {
      setAssessmentsError(err.response?.data?.message || 'Failed to update assessment.');
    } finally {
      setReviewingId(null);
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
        <h2>Document verification</h2>
        <p>Review identity documents uploaded by clients, agents, and institutions.</p>
        {assessmentsError && <div className="alert alert-error">{assessmentsError}</div>}
        {assessmentsLoading ? (
          <p className="empty-state">Loading…</p>
        ) : assessments.length === 0 ? (
          <p className="empty-state">No assessments submitted yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Applicant</th>
                <th>Submitted by</th>
                <th>Document</th>
                <th>File</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assessments.map((a) => (
                <tr key={a._id}>
                  <td><code>{a.referenceId}</code></td>
                  <td>{a.applicantName}</td>
                  <td>
                    {a.owner?.name || 'Unknown'}
                    <br />
                    <small>{a.owner?.email}</small>
                  </td>
                  <td>{DOC_TYPE_LABELS[a.documentType] || a.documentType}</td>
                  <td>
                    {a.documentFile?.storedName ? (
                      <span title={a.documentFile.originalName}>
                        {a.documentFile.originalName?.length > 20
                          ? `${a.documentFile.originalName.slice(0, 20)}…`
                          : a.documentFile.originalName}
                      </span>
                    ) : (
                      <span className="empty-state">Not uploaded</span>
                    )}
                  </td>
                  <td>{STATUS_LABELS[a.status] || a.status}</td>
                  <td>
                    <div className="row-actions">
                      {a.documentFile?.storedName ? (
                        <>
                          <button
                            className="btn btn-outline btn-sm"
                            disabled={viewingId === a._id}
                            onClick={() => viewDocument(a._id)}
                          >
                            {viewingId === a._id ? 'Opening…' : 'View'}
                          </button>
                          <button
                            className="btn btn-primary btn-sm"
                            disabled={reviewingId === a._id || a.status === 'verified'}
                            onClick={() => review(a._id, 'verified')}
                          >
                            Verify
                          </button>
                          <button
                            className="btn btn-outline btn-sm"
                            disabled={reviewingId === a._id || a.status === 'rejected'}
                            onClick={() => review(a._id, 'rejected')}
                          >
                            Reject
                          </button>
                        </>
                      ) : (
                        <span className="empty-state">Awaiting upload</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
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

      {import.meta.env.DEV && (
        <section className="panel">
          <h2>AI Security Demo</h2>
          <p>Open the development-only AI security monitoring dashboard.</p>
          <button
            className="btn btn-primary btn-sm"
            onClick={() => window.open('/admin/ai-demo', '_blank', 'noopener,noreferrer')}
          >
            AI Security Demo
          </button>
        </section>
      )}

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
