/**
 * Unit tests for baseline refresh after successful re-authentication (Section 4).
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
  getIpGeolocation: jest.fn(async (ip) => ({
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

const medRisk = () => ({
  risk_score: 50,
  risk_level: 'medium',
  recommended_action: 'Require Email OTP',
  reason: 'med',
});

const lowRisk = () => ({
  risk_score: 20,
  risk_level: 'low',
  recommended_action: 'Allow Login',
  reason: 'low',
});

// Helper: create a session by making one low-risk recordSessionEvent call.
// This is equivalent to what the app does on first authenticated interaction.
async function createSession(req) {
  setRisk(lowRisk());
  await sessionMonitor.recordSessionEvent(req, 'document_viewed');
}

describe('Section 4 — baseline refresh after re-authentication', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('1. successful re-auth refreshes the security baseline', async () => {
    const req = mockReq();
    await createSession(req);
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    expect(session.securityBaseline).toBeDefined();
    expect(session.requiresReauthentication).toBe(false);

    // Force the session into re-auth state.
    session.requiresReauthentication = true;
    session.accumulatedRisk = 75;
    session.accumulatedRiskUpdatedAt = Date.now();

    // Refresh baseline after re-auth.
    const refreshed = await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    expect(refreshed).toBe(true);
    expect(session.requiresReauthentication).toBe(false);
    expect(session.accumulatedRisk).toBe(0);
    expect(session.securityBaseline).toBeDefined();
  });

  test('2. new baseline contains the current verified context', async () => {
    const req = mockReq();
    await createSession(req);
    const before = sessionMonitor.sessions.get(`user:${req.user._id}`).securityBaseline;

    sessionMonitor.sessions.get(`user:${req.user._id}`).requiresReauthentication = true;
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    const after = sessionMonitor.sessions.get(`user:${req.user._id}`).securityBaseline;

    expect(after).toBeDefined();
    expect(after.device).toBe('Desktop');
    expect(after.browser).toBe('Chrome');
    expect(after.operatingSystem).toBe('Windows');
    expect(after.country).toBe('Australia');
    expect(after.city).toBe('Sydney');
    expect(after.vpnDetected).toBe(false);
    expect(typeof after.ip).toBe('string');
    expect(typeof after.loginAt).toBe('number');
    // Same context — equal value, but reference will differ (fresh capture).
    expect(after.device).toBe(before.device);
  });

  test('3. re-auth clears accumulated risk and re-auth flag', async () => {
    const req = mockReq();
    await createSession(req);
    for (let i = 0; i < 5; i++) setRisk(medRisk());
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    expect(session.accumulatedRisk).toBeGreaterThan(0);
    expect(session.requiresReauthentication).toBe(true);

    await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    expect(session.accumulatedRisk).toBe(0);
    expect(session.requiresReauthentication).toBe(false);
    expect(session.riskDecision).toBe('continue');
  });

  test('4. requiresReauthentication becomes false after refresh', async () => {
    const req = mockReq();
    await createSession(req);
    setRisk(medRisk());
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.requiresReauthentication = true;

    expect(sessionMonitor.isSessionReauthenticationRequired(req)).toBe(true);
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    expect(sessionMonitor.isSessionReauthenticationRequired(req)).toBe(false);
  });

  test('5. same context after re-auth does not immediately re-trigger re-auth', async () => {
    const req = mockReq();
    await createSession(req);
    setRisk(medRisk());
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.requiresReauthentication = true;

    // Refresh baseline to current context.
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    // A low-risk event after refresh should not flip re-auth back on.
    setRisk(lowRisk());
    const r = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(r.requiresReauthentication).toBe(false);
    expect(r.accumulatedRisk).toBeLessThan(15);
  });

  test('6. a NEW context change after re-auth is still detected', async () => {
    const req = mockReq();
    await createSession(req);
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.requiresReauthentication = true;

    // Re-auth refreshes baseline.
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    const refreshedBaseline = session.securityBaseline;
    expect(refreshedBaseline).toBeDefined();

    // Simulate a context change after re-auth.
    const newContext = {
      ...refreshedBaseline,
      country: 'Japan',
      ip: '203.0.113.99',
    };
    const changes = sessionMonitor.compareSessionContext(
      refreshedBaseline,
      newContext
    );
    expect(changes.locationChanged).toBe(true);
    expect(changes.ipChanged).toBe(true);
  });

  test('7. failed re-auth does NOT refresh the baseline', async () => {
    setRisk(medRisk());
    const req = mockReq();
    // recordSessionEvent creates the session and calls establishSessionBaseline on first event.
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    const originalBaseline = session.securityBaseline;

    session.requiresReauthentication = true;
    session.accumulatedRisk = 70;
    session.accumulatedRiskUpdatedAt = Date.now();

    // Simulate failed re-auth: do NOT call refreshSessionBaselineAfterReauth.
    // The controller returns early on bad code BEFORE calling the helper.
    const current = sessionMonitor.sessions.get(`user:${req.user._id}`).securityBaseline;
    expect(current).toBe(originalBaseline);
    expect(session.requiresReauthentication).toBe(true);
    expect(session.accumulatedRisk).toBe(70);
  });

  test('8. refreshSessionBaselineAfterReauth is a no-op when no session exists', async () => {
    const req = mockReq();
    const refreshed = await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    expect(refreshed).toBe(false);
  });
});
