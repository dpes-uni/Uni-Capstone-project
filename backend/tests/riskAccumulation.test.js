/**
 * Unit tests for session risk accumulation and decay (Section 3).
 *
 * Verifies that:
 *  - suspicious events accumulate a bounded risk value (0-100)
 *  - low-risk events do not accumulate
 *  - time-based decay reduces the accumulated value
 *  - the existing re-authentication flow still triggers
 *  - re-authentication clears the accumulated state
 */

process.env.RISK_MEDIUM_THRESHOLD = '30';
process.env.RISK_HIGH_THRESHOLD = '61';
process.env.RISK_CRITICAL_THRESHOLD = '81';
process.env.SESSION_RISK_CONTRIBUTION = '15';
process.env.SESSION_RISK_DECAY_PER_SECOND = '0.05';

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

const setRisk = (result) =>
  aiService.assessSessionRisk.mockResolvedValueOnce(result);

const lowRisk = () => ({
  risk_score: 20,
  risk_level: 'low',
  recommended_action: 'Allow Login',
  reason: 'low',
});

const medRisk = () => ({
  risk_score: 50,
  risk_level: 'medium',
  recommended_action: 'Require Email OTP',
  reason: 'med',
});

describe('Section 3 — session risk accumulation and decay', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('1. normal low-risk session leaves accumulated risk at 0', async () => {
    setRisk(lowRisk());
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    expect(res.accumulatedRisk).toBe(0);
    expect(res.requiresReauthentication).toBe(false);
  });

  test('2. one suspicious event increases accumulated risk', async () => {
    setRisk(medRisk());
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    expect(res.accumulatedRisk).toBeCloseTo(15, 2);
  });

  test('3. multiple distinct suspicious events accumulate', async () => {
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    const r1 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    const r2 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    const r3 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    // Approximate due to microsecond decay between rapid calls.
    expect(r1.accumulatedRisk).toBeCloseTo(15, 2);
    expect(r2.accumulatedRisk).toBeCloseTo(30, 2);
    expect(r3.accumulatedRisk).toBeCloseTo(45, 2);
  });

  test('4. low-risk events do not accumulate beyond existing risk', async () => {
    setRisk(medRisk());
    setRisk(lowRisk());
    setRisk(lowRisk());
    const r1 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    const r2 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    const r3 = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    expect(r1.accumulatedRisk).toBeCloseTo(15, 2);
    expect(r2.accumulatedRisk).toBeCloseTo(15, 2);
    expect(r3.accumulatedRisk).toBeLessThanOrEqual(15);
  });

  test('5. accumulated risk is bounded at 100', async () => {
    // Use a higher contribution via direct accumulateRisk to reach the cap.
    for (let i = 0; i < 10; i++) setRisk(medRisk());
    let last = 0;
    for (let i = 0; i < 10; i++) {
      const r = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
      last = r.accumulatedRisk;
    }
    // Cap must hold even when many suspicious events fire.
    expect(last).toBeLessThanOrEqual(100);
  });

  test('6. accumulated risk does not fall below 0', async () => {
    setRisk(medRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    // Force a long elapsed time
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.accumulatedRiskUpdatedAt = Date.now() - 10_000_000;
    const status = sessionMonitor.getSessionStatus(req);
    expect(status.accumulatedRisk).toBeGreaterThanOrEqual(0);
  });

  test('7. accumulated risk decays over time without suspicious activity', async () => {
    jest.useFakeTimers({ doNotFake: ['nextTick'] });
    setRisk(medRisk());
    const req = mockReq();
    const r1 = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(r1.accumulatedRisk).toBe(15);
    jest.advanceTimersByTime(60_000);
    const status = sessionMonitor.getSessionStatus(req);
    // 15 - (60 * 0.05) = 12
    expect(status.accumulatedRisk).toBeCloseTo(12, 1);
    jest.useRealTimers();
  });

  test('8. high accumulated risk triggers existing re-authentication', async () => {
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    const req = mockReq();
    let last;
    for (let i = 0; i < 5; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    // 5 * 15 = 75, above HIGH threshold 61
    expect(last.accumulatedRisk).toBeCloseTo(75, 1);
    expect(last.requiresReauthentication).toBe(true);
    expect(last.riskDecision).toBe('reauth_required');
  });

  test('9. successful re-authentication clears accumulated risk', async () => {
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    setRisk(medRisk());
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    const cleared = sessionMonitor.clearSessionReauthentication(req);
    expect(cleared).toBe(true);
    const status = sessionMonitor.getSessionStatus(req);
    expect(status.accumulatedRisk).toBe(0);
    expect(status.requiresReauthentication).toBe(false);
  });

  test('10. AI result is preserved alongside accumulated risk', async () => {
    setRisk({
      risk_score: 45,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'ml says medium',
    });
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    expect(res.riskResult).toBeDefined();
    expect(res.riskResult.risk_level).toBe('medium');
    expect(res.riskResult.recommended_action).toBe('Require Email OTP');
    expect(res.riskResult.reason).toBe('ml says medium');
    expect(res.accumulatedRisk).toBeCloseTo(15, 2);
  });
});
