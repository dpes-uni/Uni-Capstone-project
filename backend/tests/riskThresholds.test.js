/**
 * Unit tests for adaptive risk threshold enforcement (Section 2).
 *
 * Verifies that session risk decisions are driven by validated
 * risk score / risk level rather than a fragile exact match on
 * the AI's recommended_action string.
 */

process.env.RISK_MEDIUM_THRESHOLD = '30';
process.env.RISK_HIGH_THRESHOLD = '61';
process.env.RISK_CRITICAL_THRESHOLD = '81';

jest.mock('../src/services/aiService', () => ({
  extractDeviceInfo: jest.fn(() => ({
    device: 'Desktop',
    browser: 'Chrome',
    operatingSystem: 'Windows',
  })),
  assessSessionRisk: jest.fn(),
}));

jest.mock('../src/services/ipService', () => ({
  getIpGeolocation: jest.fn(async () => ({
    country: 'Australia',
    city: 'Sydney',
    org: '',
    asn: null,
  })),
  detectVpn: jest.fn(() => false),
}));

const sessionMonitor = require('../src/services/sessionMonitor');
const aiService = require('../src/services/aiService');

const mockReq = (overrides = {}) => ({
  user: { _id: 'u1', email: 'a@test.com', role: 'student' },
  headers: { 'user-agent': 'jest' },
  ip: '127.0.0.1',
  ...overrides,
});

const setRisk = (result) => aiService.assessSessionRisk.mockResolvedValueOnce(result);

describe('Section 2 — adaptive risk thresholds', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('low risk → continue, no re-authentication', async () => {
    setRisk({
      risk_score: 20,
      risk_level: 'low',
      recommended_action: 'Allow Login',
      reason: 'normal',
    });

    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    expect(res.requiresReauthentication).toBe(false);
    expect(res.riskDecision).toBe('continue');
  });

  test('medium risk → no re-authentication, existing elevated response', async () => {
    setRisk({
      risk_score: 45,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'medium',
    });

    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    expect(res.requiresReauthentication).toBe(false);
    expect(res.riskDecision).toBe('continue');
  });

  test('high risk → require re-authentication', async () => {
    setRisk({
      risk_score: 70,
      risk_level: 'high',
      recommended_action: 'Require Additional Verification',
      reason: 'high',
    });

    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');
  });

  test('critical risk → require re-authentication (strongest existing response)', async () => {
    setRisk({
      risk_score: 92,
      risk_level: 'critical',
      recommended_action: 'Block Login',
      reason: 'critical',
    });

    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');
  });

  test('high risk with unexpected recommended_action still triggers re-authentication', async () => {
    setRisk({
      risk_score: 75,
      risk_level: 'high',
      recommended_action: 'Some Future Wording We Did Not Anticipate',
      reason: 'high',
    });

    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');
    // recommended_action is preserved on the session for UI / logging.
    expect(sessionMonitor.getSessionStatus(mockReq()).lastRiskResult.recommended_action)
      .toBe('Some Future Wording We Did Not Anticipate');
  });

  test('normal session remains unaffected across many events', async () => {
    setRisk({ risk_score: 10, risk_level: 'low', recommended_action: 'Allow Login', reason: 'ok' });
    setRisk({ risk_score: 15, risk_level: 'low', recommended_action: 'Allow Login', reason: 'ok' });
    setRisk({ risk_score: 22, risk_level: 'low', recommended_action: 'Allow Login', reason: 'ok' });

    const r1 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    const r2 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    const r3 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    expect(r1.requiresReauthentication).toBe(false);
    expect(r2.requiresReauthentication).toBe(false);
    expect(r3.requiresReauthentication).toBe(false);
  });

  test('existing re-authentication clearing still works after high-risk', async () => {
    setRisk({ risk_score: 70, risk_level: 'high', recommended_action: 'Require Additional Verification', reason: 'high' });
    await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');

    const cleared = sessionMonitor.clearSessionReauthentication(mockReq());
    expect(cleared).toBe(true);
    expect(sessionMonitor.isSessionReauthenticationRequired(mockReq())).toBe(false);
  });

  test('classifySessionRisk falls back to score when level is missing', () => {
    expect(sessionMonitor.classifySessionRisk({ risk_score: 90 })).toBe('critical');
    expect(sessionMonitor.classifySessionRisk({ risk_score: 65 })).toBe('high');
    expect(sessionMonitor.classifySessionRisk({ risk_score: 40 })).toBe('low');
    expect(sessionMonitor.classifySessionRisk(null)).toBe('low');
  });

  test('threshold configuration from env is honoured', () => {
    // Existing thresholds from .env.example: medium=30, high=61, critical=81.
    expect(sessionMonitor.classifySessionRisk({ risk_score: 80, risk_level: 'medium' })).toBe('high');
    expect(sessionMonitor.classifySessionRisk({ risk_score: 81, risk_level: 'medium' })).toBe('critical');
    expect(sessionMonitor.classifySessionRisk({ risk_score: 30, risk_level: 'medium' })).toBe('medium');
  });

  test('VPN comparison correctly detects VPN status flip', async () => {
    const baseline = { vpnDetected: false };
    const sameAsBaseline = { vpnDetected: false };
    const flipped = { vpnDetected: true };

    expect(sessionMonitor.compareSessionContext(baseline, sameAsBaseline).vpnChanged).toBe(false);
    expect(sessionMonitor.compareSessionContext(baseline, flipped).vpnChanged).toBe(true);
  });
});
