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

export default function Assessments() {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ applicantName: '', documentType: 'passport', notes: '' });

  const load = () => {
    setLoading(true);
    api
      .get('/assessments')
      .then(({ data }) => setAssessments(data.assessments))
      .catch((err) => setError(err.response?.data?.message || 'Failed to load assessments.'))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setCreating(true);
    try {
      await api.post('/assessments', form);
      setForm({ applicantName: '', documentType: 'passport', notes: '' });
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create assessment.');
    } finally {
      setCreating(false);
    }
  };

  const updateStatus = async (id, status) => {
    try {
      await api.patch(`/assessments/${id}`, { status });
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update assessment.');
    }
  };

  const remove = async (id) => {
    if (!window.confirm('Delete this assessment?')) return;
    try {
      await api.delete(`/assessments/${id}`);
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to delete assessment.');
    }
  };

  return (
    <div className="page assessments-page">
      <header className="page-header">
        <h1>Verification assessments</h1>
        <p>Track identity and document verification cases from submission to decision.</p>
      </header>

      {error && <div className="alert alert-error">{error}</div>}

      <section className="panel">
        <h2>New assessment</h2>
        <form className="inline-form" onSubmit={handleCreate}>
          <input
            type="text"
            placeholder="Applicant name"
            value={form.applicantName}
            onChange={(e) => setForm({ ...form, applicantName: e.target.value })}
            required
          />
          <select
            value={form.documentType}
            onChange={(e) => setForm({ ...form, documentType: e.target.value })}
          >
            {Object.entries(DOC_TYPE_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder="Notes (optional)"
            value={form.notes}
            onChange={(e) => setForm({ ...form, notes: e.target.value })}
          />
          <button type="submit" className="btn btn-primary" disabled={creating}>
            {creating ? 'Adding…' : 'Add assessment'}
          </button>
        </form>
      </section>

      <section className="panel">
        <h2>All assessments</h2>
        {loading ? (
          <p className="empty-state">Loading…</p>
        ) : assessments.length === 0 ? (
          <p className="empty-state">No assessments yet — add one above.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Applicant</th>
                <th>Document</th>
                <th>Risk score</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assessments.map((a) => (
                <tr key={a._id}>
                  <td><code>{a.referenceId}</code></td>
                  <td>{a.applicantName}</td>
                  <td>{DOC_TYPE_LABELS[a.documentType] || a.documentType}</td>
                  <td>{a.riskScore}</td>
                  <td>
                    <select value={a.status} onChange={(e) => updateStatus(a._id, e.target.value)}>
                      {Object.entries(STATUS_LABELS).map(([value, label]) => (
                        <option key={value} value={value}>{label}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <button className="btn btn-outline btn-sm" onClick={() => remove(a._id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
