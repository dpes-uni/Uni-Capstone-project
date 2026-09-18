import React, { useState, useEffect, useCallback } from 'react';
import RiskBadge from '../components/RiskBadge.jsx';
import api from '../api/axios.js';

const TABS = [
  { key: 'overview', label: 'OVERVIEW', testId: 'tab-overview' },
  { key: 'session-context', label: 'SESSION CONTEXT', testId: 'tab-session-context' },
  { key: 'ai-input', label: 'AI INPUT FEATURES', testId: 'tab-ai-input' },
];

function formatDuration(ms) {
  if (ms == null || ms < 0) return '—';
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function formatDurationFromStart(startedAt) {
  if (!startedAt) return '—';
  return formatDuration(Date.now() - new Date(startedAt).getTime());
}

function formatTimeout(ms) {
  if (ms == null) return '—';
  if (ms <= 0) return 'Expired';
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function getSecurityDecision(riskDecision) {
  switch (riskDecision) {
    case 'reauth_required': return 'Reauthentication required';
    case 'block': return 'Block login';
    case 'require_verification': return 'Require additional verification';
    case 'monitor': return 'Monitor session — elevated risk observed';
    case 'continue': return 'Allow login — continue session';
    default: return 'Unknown';
  }
}

function field(value) {
  return value != null ? String(value) : '—';
}

export default function AIDemoPage() {
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [sessionData, setSessionData] = useState(null);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await api.get('/admin/session-status');
      setSessionData(data);
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load session status.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const active = sessionData?.active === true;
  const user = sessionData?.user || {};
  const sessionStatus = sessionData?.sessionStatus || {};
  const aiRisk = sessionData?.aiRisk || {};
  const timeout = sessionData?.timeout || {};
  const baseline = sessionData?.baseline;
  const activity = sessionData?.activity || {};

  const documentCount = (activity.documentsViewed || 0) + (activity.documentsDownloaded || 0) + (activity.documentsUploaded || 0);

  const baselineComparison = baseline ? [
    { label: 'Device', current: field(baseline.device), changed: false },
    { label: 'Browser', current: field(baseline.browser), changed: false },
    { label: 'IP Address', current: field(baseline.ip), changed: false },
    { label: 'Location', current: baseline.city && baseline.country ? `${field(baseline.city)}, ${field(baseline.country)}` : '—', changed: false },
    { label: 'VPN', current: baseline.vpnDetected ? 'VPN detected' : 'No VPN', changed: false },
  ] : [];

  const noSessionContent = (
    <section className="panel">
      <h2>No Active Session</h2>
      <p>No authenticated session is available. Start a session and sign in as an administrator to view live security data.</p>
    </section>
  );

  if (loading) {
    return (
      <div className="page dashboard-page">
        <header className="page-header">
          <h1>AI Security Demo</h1>
        </header>
        <div className="alert alert-info" data-testid="data-mode">DATA MODE: LIVE SESSION</div>
        <p>Loading session status…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page dashboard-page">
        <header className="page-header">
          <h1>AI Security Demo</h1>
        </header>
        <div className="alert alert-info" data-testid="data-mode">DATA MODE: LIVE SESSION</div>
        <div className="alert alert-danger" data-testid="error">{field(error)}</div>
        <button className="btn btn-primary btn-sm" data-testid="refresh" onClick={loadData}>Refresh</button>
      </div>
    );
  }

  return (
    <div className="page dashboard-page">
      <header className="page-header">
        <h1>AI Security Demo</h1>
        <p>Live session data from the authenticated backend. DATA MODE: LIVE SESSION.</p>
      </header>
      <div className="alert alert-info" data-testid="data-mode">DATA MODE: LIVE SESSION</div>
      <div role="tablist" aria-label="AI Security Demo tabs" style={{ display: 'flex', gap: '6px', marginBottom: '20px' }}>
        {TABS.map((tab) => (
          <button key={tab.key} type="button" role="tab" aria-selected={activeTab === tab.key} aria-controls={`panel-${tab.key}`} data-testid={tab.testId}
            className={activeTab === tab.key ? 'btn btn-primary btn-sm' : 'btn btn-outline btn-sm'} onClick={() => setActiveTab(tab.key)}>
            {tab.label}
          </button>
        ))}
      </div>
      <button className="btn btn-outline btn-sm" data-testid="refresh" onClick={loadData} style={{ marginBottom: '16px' }}>Refresh</button>

      {activeTab === 'overview' && (
        <section role="tabpanel" id="panel-overview" data-testid="panel-overview">
          {!active ? noSessionContent : (
            <>
              <section className="panel">
                <h2>Session Status</h2>
                <dl className="detail-list">
                  <dt>Session Status</dt><dd>{field(sessionStatus.active ? 'active' : 'inactive')}</dd>
                  <dt>User</dt><dd>{field(user.username)}</dd>
                  <dt>Role</dt><dd>{field(user.role)}</dd>
                  <dt>Session duration</dt><dd>{formatDurationFromStart(sessionData?.startedAt)}</dd>
                  <dt>Security Decision</dt><dd>{getSecurityDecision(sessionStatus.riskDecision)}</dd>
                </dl>
              </section>

              <section className="stat-grid">
                <div className="stat-card"><span className="stat-value">{field(aiRisk.score)}</span><span className="stat-label">AI Risk Score</span></div>
                <div className="stat-card"><span className="stat-value"><RiskBadge level={aiRisk.level} /></span><span className="stat-label">AI Risk Level</span></div>
                <div className="stat-card"><span className="stat-value">{field(sessionData?.accumulatedRisk)}</span><span className="stat-label">Accumulated Risk</span></div>
                <div className="stat-card"><span className="stat-value"><RiskBadge level={sessionData?.effectiveRiskLevel} /></span><span className="stat-label">Effective Risk</span></div>
              </section>

              <section className="panel">
                <h2>Recommended Action</h2>
                <p>{field(sessionStatus.recommendedAction)}</p>
              </section>

              <section className="panel">
                <h2>Risk Sources</h2>
                <table className="table">
                  <thead><tr><th>Source</th><th>Score</th><th>Level</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr><td>AI</td><td>{field(aiRisk.score)}</td><td><RiskBadge level={aiRisk.level} /></td><td>Session Predictor</td></tr>
                    <tr><td>Rule-Based</td><td>—</td><td>—</td><td>Login Risk Engine (not exposed by this endpoint)</td></tr>
                    <tr><td>Accumulated</td><td>{field(sessionData?.accumulatedRisk)}</td><td><RiskBadge level={sessionData?.effectiveRiskLevel} /></td><td>sessionMonitor accumulation / decay</td></tr>
                  </tbody>
                </table>
              </section>

              <section className="panel">
                <h2>Current Session Summary</h2>
                {baseline ? (
                  <p>{field(baseline.device)} / {field(baseline.operatingSystem)} / {field(baseline.browser)} — {field(baseline.ip)} ({field(baseline.city)}, {field(baseline.country)}){baseline.vpnDetected ? ' — VPN detected' : ' — No VPN'}</p>
                ) : (
                  <p>Baseline data not available.</p>
                )}
              </section>

              <section className="panel">
                <h2>Timeout State</h2>
                <dl className="detail-list">
                  <dt>Idle Timeout</dt><dd>{timeout.idleTimeout ? 'Expired' : 'Active'}</dd>
                  <dt>High Risk Terminate</dt><dd>{timeout.highRiskTerminate ? 'Expired' : 'Active'}</dd>
                  <dt>Time Until Expire</dt><dd>{formatTimeout(timeout.timeUntilExpire)}</dd>
                </dl>
              </section>
            </>
          )}
        </section>
      )}

      {activeTab === 'session-context' && (
        <section role="tabpanel" id="panel-session-context" data-testid="panel-session-context">
          {!active ? noSessionContent : (
            <>
              <div className="alert alert-info">Live monitored session context from the authenticated backend.</div>

              <section className="panel">
                <h2>Monitored Session Context</h2>
                <dl className="detail-list">
                  <dt>Device</dt><dd>{field(baseline?.device)}</dd>
                  <dt>Operating System</dt><dd>{field(baseline?.operatingSystem)}</dd>
                  <dt>Browser</dt><dd>{field(baseline?.browser)}</dd>
                  <dt>IP Address</dt><dd>{field(baseline?.ip)}</dd>
                  <dt>Country</dt><dd>{field(baseline?.country)}</dd>
                  <dt>City</dt><dd>{field(baseline?.city)}</dd>
                  <dt>VPN status</dt><dd>{baseline?.vpnDetected === true ? 'VPN detected' : 'No VPN'}</dd>
                  <dt>Session duration</dt><dd>{formatDurationFromStart(sessionData?.startedAt)}</dd>
                  <dt>Baseline refresh status</dt><dd>current</dd>
                </dl>
              </section>

              {baseline ? (
                <section className="panel">
                  <h2>Baseline Comparison</h2>
                  <table className="table">
                    <thead><tr><th>Attribute</th><th>Current</th><th>Status</th></tr></thead>
                    <tbody>
                      {baselineComparison.map((item) => (
                        <tr key={item.label}>
                          <td>{item.label}</td>
                          <td>{item.current}</td>
                          <td>{item.changed ? 'Changed' : 'Unchanged'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              ) : (
                <section className="panel">
                  <h2>Baseline Comparison</h2>
                  <p className="empty-state">Baseline data not available.</p>
                </section>
              )}

              <section className="panel">
                <h2>Context Changes</h2>
                <p className="empty-state">Context change detection is performed by the backend and not exposed by this endpoint.</p>
              </section>
            </>
          )}
        </section>
      )}

      {activeTab === 'ai-input' && (
        <section role="tabpanel" id="panel-ai-input" data-testid="panel-ai-input">
          {!active ? noSessionContent : (
            <>
              <div className="alert alert-info">Live session signals from the authenticated backend. Not every displayed value is a trained ML feature — some are monitored session context.</div>

              <section className="panel">
                <h2>AI Input Features / Session Signals</h2>
                <dl className="detail-list">
                  <dt>User Role</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(user.role)}</dd>
                  <dt>Session Duration</dt><dd><span className="signal-tag monitored">Monitored session context</span> {formatDurationFromStart(sessionData?.startedAt)}</dd>
                  <dt>Document Count</dt><dd><span className="signal-tag monitored">Monitored session context</span> {documentCount}</dd>
                  <dt>Verification Actions</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.verificationActions)}</dd>
                  <dt>Failed Actions</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.failedActions)}</dd>
                  <dt>Rapid Actions</dt><dd><span className="signal-tag monitored">Monitored session context</span> {activity.rapidActions ? 'Yes' : 'No'}</dd>
                  <dt>Unusual Activity</dt><dd className="unavailable">Not available from this endpoint</dd>
                  <dt>Context Changes</dt><dd className="unavailable">Not available from this endpoint</dd>
                </dl>
              </section>

              <section className="panel">
                <h2>Feature Pipeline</h2>
                <div className="feature-flow" data-testid="feature-flow" style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center', padding: '16px 0' }}>
                  <div className="flow-step" data-testid="flow-session-data" style={{ padding: '8px 16px', border: '1px solid var(--border)', borderRadius: '6px', background: 'var(--gray-light)', width: '100%', maxWidth: '400px', textAlign: 'center' }}>
                    <strong>Session Data</strong>
                  </div>
                  <div style={{ color: 'var(--gray)', fontSize: '18px' }}>↓</div>
                  <div className="flow-step" data-testid="flow-feature-prep" style={{ padding: '8px 16px', border: '1px solid var(--border)', borderRadius: '6px', background: 'var(--gray-light)', width: '100%', maxWidth: '400px', textAlign: 'center' }}>
                    <strong>Feature Preparation</strong>
                  </div>
                  <div style={{ color: 'var(--gray)', fontSize: '18px' }}>↓</div>
                  <div className="flow-step" data-testid="flow-session-predictor" style={{ padding: '8px 16px', border: '1px solid var(--border)', borderRadius: '6px', background: 'var(--gray-light)', width: '100%', maxWidth: '400px', textAlign: 'center' }}>
                    <strong>Python Session Predictor</strong>
                  </div>
                  <div style={{ color: 'var(--gray)', fontSize: '18px' }}>↓</div>
                  <div className="flow-step" data-testid="flow-risk-prediction" style={{ padding: '8px 16px', border: '1px solid var(--border)', borderRadius: '6px', background: 'var(--accent-light)', width: '100%', maxWidth: '400px', textAlign: 'center' }}>
                    <strong>Risk Prediction</strong>
                  </div>
                </div>
              </section>

              <section className="panel">
                <h2>Model Output</h2>
                <dl className="detail-list">
                  <dt>Risk Score</dt><dd>{field(aiRisk.score)}</dd>
                  <dt>Risk Level</dt><dd><RiskBadge level={aiRisk.level} /></dd>
                </dl>
              </section>
            </>
          )}
        </section>
      )}
    </div>
  );
}
