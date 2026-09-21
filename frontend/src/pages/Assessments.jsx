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
  const [uploadingId, setUploadingId] = useState(null);
  const [viewingId, setViewingId] = useState(null);

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

  const remove = async (id) => {
    if (!window.confirm('Delete this assessment?')) return;
    try {
      await api.delete(`/assessments/${id}`);
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to delete assessment.');
    }
  };

  const handleFileChange = async (id, file) => {
    if (!file) return;
    setError('');
    setUploadingId(id);
    try {
      const formData = new FormData();
      formData.append('document', file);
      await api.post(`/assessments/${id}/document`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to upload document.');
    } finally {
      setUploadingId(null);
    }
  };

  const viewDocument = async (id) => {
    setError('');
    setViewingId(id);
    try {
      const response = await api.get(`/assessments/${id}/document`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(response.data);
      window.open(url, '_blank', 'noopener,noreferrer');
    } catch (err) {
      setError('Failed to open document.');
    } finally {
      setViewingId(null);
    }
  };

  return (
    <div className="page assessments-page">
      <header className="page-header">
        <h1>Verification assessments</h1>
        <p>Submit identity documents for verification and track their status.</p>
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
        <p className="hint">
          After adding an assessment, upload the identity document below so an administrator can verify it.
        </p>
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
                  <td>{DOC_TYPE_LABELS[a.documentType] || a.documentType}</td>
                  <td>
                    {a.documentFile?.storedName ? (
                      <span title={a.documentFile.originalName}>
                        {a.documentFile.originalName?.length > 20
                          ? `${a.documentFile.originalName.slice(0, 20)}…`
                          : a.documentFile.originalName}
                      </span>
                    ) : (
                      <span className="empty-state">No file</span>
                    )}
                  </td>
                  <td>{STATUS_LABELS[a.status] || a.status}</td>
                  <td>
                    <div className="row-actions">
                      <label className="btn btn-outline btn-sm upload-label">
                        {uploadingId === a._id
                          ? 'Uploading…'
                          : a.documentFile?.storedName
                          ? 'Replace file'
                          : 'Upload file'}
                        <input
                          type="file"
                          accept=".pdf,.jpg,.jpeg,.png,.webp"
                          style={{ display: 'none' }}
                          disabled={uploadingId === a._id}
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            handleFileChange(a._id, file);
                            e.target.value = '';
                          }}
                        />
                      </label>
                      {a.documentFile?.storedName && (
                        <button
                          className="btn btn-outline btn-sm"
                          disabled={viewingId === a._id}
                          onClick={() => viewDocument(a._id)}
                        >
                          {viewingId === a._id ? 'Opening…' : 'View'}
                        </button>
                      )}
                      <button className="btn btn-outline btn-sm" onClick={() => remove(a._id)}>Delete</button>
                    </div>
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
