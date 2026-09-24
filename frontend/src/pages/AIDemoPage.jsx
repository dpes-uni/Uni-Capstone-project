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

/**
 * Resolve the Recommended Action to display.
 *
 * Priority:
 *   1. AI recommended action — only when the live session predictor has
 *      actually assessed the session.
 *   2. Session status recommended action from the backend.
 *   3. Existing risk-decision mapping.
 *   4. Transparent "Awaiting first monitored action" state — never a blank
 *      dash for a normal unassessed session.
 */
function resolveRecommendedAction(aiRisk, sessionStatus) {
  const aiAssessed = aiRisk?.status === 'assessed';

  if (aiAssessed && aiRisk?.recommendedAction) {
    return aiRisk.recommendedAction;
  }

  if (sessionStatus?.recommendedAction) {
    return sessionStatus.recommendedAction;
  }

  const decision = getSecurityDecision(sessionStatus?.riskDecision);
  if (decision && decision !== 'Unknown') {
    return decision;
  }

  return 'Awaiting first monitored action';
}

export default function AIDemoPage() {
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await api.get('/admin/active-sessions');
      const nextSessions = Array.isArray(data?.sessions) ? data.sessions : [];
      setSessions(nextSessions);
      setSelectedSessionId((prev) => {
        if (prev && nextSessions.some((s) => s.id === prev)) {
          return prev;
        }
        return nextSessions.length > 0 ? nextSessions[0].id : null;
      });
    } catch (err) {
      setError(err?.response?.data?.message || 'Unable to load live monitored sessions.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const selectedSession = sessions.find((s) => s.id === selectedSessionId) || null;

  const sessionData = selectedSession;
  const active = sessionData != null;
  const user = sessionData?.user || {};
  const sessionStatus = sessionData?.sessionStatus || {};
  const aiRisk = sessionData?.aiRisk || {};
  const loginRisk = sessionData?.loginRisk || {};
  const ruleBasedRisk = loginRisk?.ruleBased || {};
  const loginAiRisk = loginRisk?.ai || {};
  const timeout = sessionData?.timeout || {};
  const baseline = sessionData?.baseline;
  const sessionContext = sessionData?.sessionContext;
  const contextChanges = sessionData?.contextChanges;
  const activity = sessionData?.activity || {};

  const documentCount = (activity.documentsViewed || 0) + (activity.documentsDownloaded || 0) + (activity.documentsUploaded || 0);

  const contextChangeRows = [
    { key: 'deviceChanged', label: 'Device', current: field(sessionContext?.device) },
    { key: 'browserChanged', label: 'Browser', current: field(sessionContext?.browser) },
    { key: 'osChanged', label: 'Operating System', current: field(sessionContext?.operatingSystem) },
    { key: 'ipChanged', label: 'IP Address', current: field(sessionContext?.ip) },
    { key: 'locationChanged', label: 'Location', current: sessionContext?.city && sessionContext?.country ? `${field(sessionContext.city)}, ${field(sessionContext.country)}` : '—' },
    { key: 'vpnChanged', label: 'VPN', current: sessionContext?.vpnDetected ? 'VPN detected' : 'No VPN' },
  ];

  const aiAssessed = aiRisk.status === 'assessed';

  const noSessionContent = (
    <section className="panel">
      <h2>No Active Monitored Sessions</h2>
      <p>No active monitored sessions are available. Start a session and sign in as an administrator to view live security data.</p>
    </section>
  );

  if (loading) {
    return (
      <div className="page dashboard-page">
        <header className="page-header">
          <h1>AI Security Demo</h1>
        </header>
        <div className="alert alert-info" data-testid="data-mode">DATA MODE: LIVE SESSION</div>
        <p>Loading live monitored sessions…</p>
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
        <p>Live multi-user session data from the authenticated backend. DATA MODE: LIVE SESSION.</p>
      </header>
      <div className="alert alert-info" data-testid="data-mode">DATA MODE: LIVE SESSION</div>

      <section className="panel" style={{ marginBottom: '16px' }}>
        <h2>Active Monitored Sessions: {sessions.length}</h2>
        {sessions.length === 0 ? (
          <p className="empty-state">No Active Monitored Sessions</p>
        ) : (
          <ul className="session-list" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {sessions.map((session) => {
              const sessUser = session?.user || {};
              const sessAiRisk = session?.aiRisk || {};
              const sessEffective = session?.effectiveRiskLevel || 'low';
              const sessReauth = session?.sessionStatus?.requiresReauthentication;
              const isSelected = session.id === selectedSessionId;
              return (
                <li key={session.id} style={{ marginBottom: '10px' }}>
                  <button
                    type="button"
                    className={isSelected ? 'btn btn-primary btn-sm' : 'btn btn-outline btn-sm'}
                    data-testid={`session-select-${session.id}`}
                    onClick={() => setSelectedSessionId(session.id)}
                    style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '4px', width: '100%', textAlign: 'left' }}
                  >
                    <span>
                      <strong>{field(sessUser.role)}</strong> — {field(sessUser.username)}
                    </span>
                    <span>
                      AI Risk: {field(sessAiRisk.score)} / {field(sessAiRisk.level)}
                    </span>
                    <span>
                      Effective Risk: {sessEffective}
                      {sessReauth ? ' — Reauthentication Required' : ''}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

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
                <h2>AI Model Output</h2>
                <dl className="detail-list">
                  <dt>AI Assessment</dt><dd>{aiAssessed ? 'Assessed' : 'Not assessed'}</dd>
                  <dt>AI Risk Score</dt><dd>{aiAssessed ? field(aiRisk.score) : 'Not assessed'}</dd>
                  <dt>AI Risk Level</dt><dd>{aiAssessed ? <RiskBadge level={aiRisk.level} /> : 'Not assessed'}</dd>
                  <dt>Unusual Activity Prediction</dt><dd>{aiAssessed ? field(aiRisk.unusualActivity) : 'Not assessed'}</dd>
                  <dt>AI Confidence</dt><dd>{aiAssessed ? field(aiRisk.confidence) : 'Not assessed'}</dd>
                  <dt>AI Reason</dt><dd>{aiAssessed ? field(aiRisk.reason) : 'Not assessed'}</dd>
                  <dt>AI Recommended Action</dt><dd>{aiAssessed ? field(aiRisk.recommendedAction) : 'Not assessed'}</dd>
                </dl>
              </section>

              <section className="panel">
                <h2>Recommended Action</h2>
                <p>{resolveRecommendedAction(aiRisk, sessionStatus)}</p>
              </section>

              <section className="panel">
                <h2>Risk Sources</h2>
                <table className="table">
                  <thead><tr><th>Source</th><th>Score</th><th>Level</th><th>Description</th></tr></thead>
                  <tbody>
                    <tr>
                      <td>AI</td>
                      <td>{aiAssessed ? field(aiRisk.score) : 'Not assessed'}</td>
                      <td>{aiAssessed ? <RiskBadge level={aiRisk.level} /> : 'Not assessed'}</td>
                      <td>Session Predictor</td>
                    </tr>
                    <tr>
                      <td>Rule-Based</td>
                      <td>{ruleBasedRisk.score != null ? field(ruleBasedRisk.score) : 'Not available'}</td>
                      <td>{ruleBasedRisk.level != null ? <RiskBadge level={ruleBasedRisk.level} /> : 'Not available'}</td>
                      <td>Login Risk Engine</td>
                    </tr>
                    <tr>
                      <td>Login AI</td>
                      <td>{loginAiRisk.score != null ? field(loginAiRisk.score) : 'Not available'}</td>
                      <td>{loginAiRisk.level != null ? <RiskBadge level={loginAiRisk.level} /> : 'Not available'}</td>
                      <td>Login AI service</td>
                    </tr>
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
                  <dt>Reauthentication Required</dt><dd>{timeout.reauthRequired ? 'Yes' : 'No'}</dd>
                  <dt>High Risk Terminate</dt><dd>{timeout.highRiskTerminate ? 'Expired' : 'Active'}</dd>
                  <dt>Reauth Window Expired</dt><dd>{timeout.reauthWindowExpired ? 'Yes' : 'No'}</dd>
                  <dt>Time Until Reauth Expire</dt><dd>{formatTimeout(timeout.timeUntilReauthExpire)}</dd>
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
                <h2>Baseline Context</h2>
                <dl className="detail-list">
                  <dt>Device</dt><dd>{field(baseline?.device)}</dd>
                  <dt>Operating System</dt><dd>{field(baseline?.operatingSystem)}</dd>
                  <dt>Browser</dt><dd>{field(baseline?.browser)}</dd>
                  <dt>IP Address</dt><dd>{field(baseline?.ip)}</dd>
                  <dt>Country</dt><dd>{field(baseline?.country)}</dd>
                  <dt>City</dt><dd>{field(baseline?.city)}</dd>
                  <dt>VPN status</dt><dd>{baseline?.vpnDetected === true ? 'VPN detected' : 'No VPN'}</dd>
                </dl>
              </section>

              <section className="panel">
                <h2>Current Session Context</h2>
                <dl className="detail-list">
                  <dt>Device</dt><dd>{field(sessionContext?.device)}</dd>
                  <dt>Operating System</dt><dd>{field(sessionContext?.operatingSystem)}</dd>
                  <dt>Browser</dt><dd>{field(sessionContext?.browser)}</dd>
                  <dt>IP Address</dt><dd>{field(sessionContext?.ip)}</dd>
                  <dt>Country</dt><dd>{field(sessionContext?.country)}</dd>
                  <dt>City</dt><dd>{field(sessionContext?.city)}</dd>
                  <dt>VPN status</dt><dd>{sessionContext?.vpnDetected === true ? 'VPN detected' : 'No VPN'}</dd>
                </dl>
              </section>

              <section className="panel">
                <h2>Baseline Comparison</h2>
                <table className="table">
                  <thead><tr><th>Attribute</th><th>Current</th><th>Status</th></tr></thead>
                  <tbody>
                    {contextChangeRows.map((item) => (
                      <tr key={item.key}>
                        <td>{item.label}</td>
                        <td>{item.current}</td>
                        <td>{contextChanges?.[item.key] ? 'Changed' : 'Unchanged'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>

              <section className="panel">
                <h2>Context Changes</h2>
                {contextChanges ? (
                  Object.entries(contextChanges).filter(([, value]) => value === true).length === 0 ? (
                    <p className="empty-state">No context changes detected</p>
                  ) : (
                    <ul className="context-changes" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                      {contextChangeRows
                        .filter((item) => contextChanges?.[item.key] === true)
                        .map((item) => (
                          <li key={item.key}>
                            {item.label}: <strong>Changed</strong>
                          </li>
                        ))}
                    </ul>
                  )
                ) : (
                  <p className="empty-state">Context change data not available.</p>
                )}
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
                  <dt>Documents Viewed</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.documentsViewed)}</dd>
                  <dt>Documents Downloaded</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.documentsDownloaded)}</dd>
                  <dt>Documents Uploaded</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.documentsUploaded)}</dd>
                  <dt>Verification Actions</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.verificationActions)}</dd>
                  <dt>Failed Actions</dt><dd><span className="signal-tag monitored">Monitored session context</span> {field(activity.failedActions)}</dd>
                  <dt>Rapid Actions</dt><dd><span className="signal-tag monitored">Monitored session context</span> {activity.rapidActions ? 'Yes' : 'No'}</dd>
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
                <h2>AI MODEL OUTPUT</h2>
                <dl className="detail-list">
                  <dt>Unusual Activity Prediction</dt><dd>{aiAssessed ? field(aiRisk.unusualActivity) : 'Not assessed'}</dd>
                  <dt>Risk Score</dt><dd>{aiAssessed ? field(aiRisk.score) : 'Not assessed'}</dd>
                  <dt>Risk Level</dt><dd>{aiAssessed ? <RiskBadge level={aiRisk.level} /> : 'Not assessed'}</dd>
                  <dt>Confidence</dt><dd>{aiAssessed ? field(aiRisk.confidence) : 'Not assessed'}</dd>
                  <dt>Reason</dt><dd>{aiAssessed ? field(aiRisk.reason) : 'Not assessed'}</dd>
                </dl>
              </section>
            </>
          )}
        </section>
      )}
    </div>
  );
}
