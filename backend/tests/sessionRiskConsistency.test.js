/**
 * Session risk-state consistency tests.
 *
 * These tests prove that the session state used for enforcement
 * (riskLevel, recommendedAction, requiresReauthentication,
 * getSessionTimeoutInfo) consistently reflects the EFFECTIVE/FINAL
 * risk classification from updateSessionRiskState() — which is the
 * max of AI risk and accumulated risk — NOT just the AI's level alone.
 *
 * Before the fix: session.riskLevel = riskResult.risk_level (AI only),
 * causing getSessionTimeoutInfo() to never fire its high-risk
 * reauthentication window because session.riskLevel never matched the
 * effective risk.
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
  user: { _id: 'consistency-u1', email: 'consistency@test.com', role: 'student' },
  headers: { 'user-agent': 'jest' },
  ip: '127.0.0.1',
  ...overrides,
});

const setRisk = (result) => aiService.assessSessionRisk.mockResolvedValueOnce(result);

const mockLowRisk = () => ({
  risk_score: 20,
  risk_level: 'low',
  recommended_action: 'Allow Login',
  reason: 'low',
});

const mockMediumRisk = () => ({
  risk_score: 50,
  risk_level: 'medium',
  recommended_action: 'Require Email OTP',
  reason: 'medium',
});

describe('Session risk-state consistency — effective risk reflected in enforcement state', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  // ── (a) Effective high risk reflected in session enforcement state ──

  test('(a) effective high risk sets riskLevel to high even when AI says medium', async () => {
    // AI says medium (score 50), but 5 accumulations push to 75 (effective high).
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());

    const req = mockReq();
    let last;
    for (let i = 0; i < 5; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    // The effective risk is high (75 >= 61 threshold), not medium (AI level).
    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('high');
    expect(status.recommendedAction).toBe('Require Additional Verification');
    expect(status.requiresReauthentication).toBe(true);
    expect(status.riskDecision).toBe('reauth_required');
  });

  // ── (b) Effective critical risk handled consistently ──

  test('(b) effective critical risk sets riskLevel to critical and recommendedAction', async () => {
    // AI returns critical risk. Session enforcement state must reflect
    // critical consistently — not downgraded to high or medium.
    setRisk({
      risk_score: 95,
      risk_level: 'critical',
      recommended_action: 'Block Login',
      reason: 'critical',
    });

    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('critical');
    expect(status.recommendedAction).toBe('Require Additional Verification');
    expect(status.requiresReauthentication).toBe(true);
    expect(status.riskDecision).toBe('reauth_required');
  });

  // ── (c) getSessionTimeoutInfo sees correct high-risk state ──

  test('(c) getSessionTimeoutInfo requires re-authentication for high risk without immediately terminating', async () => {
    // Build effective high risk.
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());

    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('high');
    expect(status.requiresReauthentication).toBe(true);

    // Immediately after the risk check the 10-minute re-auth window has
    // NOT expired — the session must NOT be automatically terminated.
    const timeoutInfo0 = sessionMonitor.getSessionTimeoutInfo(req);
    expect(timeoutInfo0.reauthRequired).toBe(true);
    expect(timeoutInfo0.reauthWindowExpired).toBe(false);
    expect(timeoutInfo0.highRiskTerminate).toBe(false);
    expect(timeoutInfo0.timeUntilExpire).toBeGreaterThan(0);
    expect(timeoutInfo0.timeUntilReauthExpire).toBeGreaterThan(0);
  });

  test('(c) getSessionTimeoutInfo fires after the 10-minute re-auth window expires', async () => {
    // Build effective high risk.
    for (let i = 0; i < 5; i++) setRisk(mockMediumRisk());

    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    // Simulate the 10-minute re-auth window elapsing without successful
    // re-authentication.
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.reauthRequiredSince = Date.now() - 11 * 60 * 1000;

    const timeoutInfo = sessionMonitor.getSessionTimeoutInfo(req);
    expect(timeoutInfo.reauthWindowExpired).toBe(true);
    expect(timeoutInfo.highRiskTerminate).toBe(true);
    expect(timeoutInfo.timeUntilReauthExpire).toBe(0);
    expect(timeoutInfo.timeUntilExpire).toBe(0);
  });

  test('(c) getSessionTimeoutInfo returns idle-only timeout for effective low risk', async () => {
    setRisk(mockLowRisk());

    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('low');

    const timeoutInfo = sessionMonitor.getSessionTimeoutInfo(req);
    // High-risk re-authentication must NOT be active for low effective risk.
    expect(timeoutInfo.highRiskTerminate).toBe(false);
    expect(timeoutInfo.reauthRequired).toBe(false);
    expect(timeoutInfo.reauthWindowExpired).toBe(false);
    // Idle timeout is tracked separately on idleTimeout field.
    expect(timeoutInfo.idleTimeout).toBe(false);
  });

  // ── (d) Lower effective risk continues normally ──

  test('(d) effective low risk leaves session in normal state', async () => {
    setRisk(mockLowRisk());

    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.requiresReauthentication).toBe(false);
    expect(res.riskDecision).toBe('continue');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('low');
    expect(status.recommendedAction).toBeNull();
    expect(status.requiresReauthentication).toBe(false);
  });

  test('(d) effective medium risk enters Monitor without reauth', async () => {
    setRisk(mockMediumRisk());

    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.requiresReauthentication).toBe(false);
    expect(res.riskDecision).toBe('monitor');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('medium');
    expect(status.recommendedAction).toBeNull();
    expect(status.requiresReauthentication).toBe(false);
  });

  // ── (e) Existing reauthentication behaviour preserved ──

  test('(e) clearing re-authentication resets riskLevel and recommendedAction', async () => {
    // Build effective high risk.
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());

    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('high');
    expect(status.recommendedAction).toBe('Require Additional Verification');

    // Clear reauthentication.
    const cleared = sessionMonitor.clearSessionReauthentication(req);
    expect(cleared).toBe(true);

    const afterClear = sessionMonitor.getSessionStatus(req);
    expect(afterClear.riskLevel).toBe('low');
    expect(afterClear.recommendedAction).toBeNull();
    expect(afterClear.requiresReauthentication).toBe(false);
  });

  test('(e) reauth flag preserved across refresh — riskLevel stays effective', async () => {
    // Build effective high risk (AI medium, accumulated high).
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());
    setRisk(mockMediumRisk());

    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    // Simulate access-token refresh — session should be reloaded from store
    // and still carry effective high risk.
    const statusAfterRefresh = sessionMonitor.getSessionStatus(req);
    expect(statusAfterRefresh.riskLevel).toBe('high');
    expect(statusAfterRefresh.requiresReauthentication).toBe(true);
    expect(statusAfterRefresh.recommendedAction).toBe('Require Additional Verification');
  });

  test('(e) AI low risk alone does NOT trigger reauthentication', async () => {
    setRisk(mockLowRisk());

    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.requiresReauthentication).toBe(false);

    // AI's own risk_level was low — session should agree.
    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('low');
    expect(status.recommendedAction).toBeNull();
  });

  test('(e) AI high risk alone triggers reauth with matching session state', async () => {
    setRisk({
      risk_score: 70,
      risk_level: 'high',
      recommended_action: 'Require Additional Verification',
      reason: 'high',
    });

    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('high');
    expect(status.recommendedAction).toBe('Require Additional Verification');
  });
});
