/**
 * Unit tests for security risk-event logging (Section 5).
 *
 * Tests that meaningful security events are recorded to MongoDB without
 * storing sensitive values (passwords, OTP, tokens). DB failures are
 * handled gracefully and do not break protected operations.
 */

process.env.RISK_MEDIUM_THRESHOLD = '30';
process.env.RISK_HIGH_THRESHOLD = '61';
process.env.RISK_CRITICAL_THRESHOLD = '81';
process.env.SESSION_RISK_CONTRIBUTION = '15';
process.env.SESSION_RISK_DECAY_PER_SECOND = '0.05';

// Mock the SecurityEvent model so DB operations are unit-testable.
jest.mock('../src/models/SecurityEvent', () => ({
  create: jest.fn(),
}));

// Mock the securityEventService to avoid importing a real mongoose model.
jest.mock('../src/services/securityEventService', () => ({
  recordSecurityEvent: jest.fn(() => Promise.resolve()),
}));

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
    country: ip === '1.2.3.4' ? 'Germany' : 'Australia',
    city: ip === '1.2.3.4' ? 'Berlin' : 'Sydney',
    org: '',
    asn: null,
  })),
  detectVpn: jest.fn(() => false),
}));

const sessionMonitor = require('../src/services/sessionMonitor');
const securityEventService = require('../src/services/securityEventService');
const SecurityEvent = require('../src/models/SecurityEvent');
const aiService = require('../src/services/aiService');

const mockReq = (overrides = {}) => ({
  user: { _id: 'u1', email: 'a@test.com', role: 'student' },
  headers: { 'user-agent': 'TestBrowser/1.0' },
  ip: '127.0.0.1',
  ...overrides,
});

const setRisk = (result) =>
  aiService.assessSessionRisk.mockResolvedValueOnce(result);

const lowRisk = () => ({
  risk_score: 20,
  risk_level: 'low',
  recommended_action: 'Allow Login',
  reason: 'normal behaviour',
});

const medRisk = () => ({
  risk_score: 50,
  risk_level: 'medium',
  recommended_action: 'Require Email OTP',
  reason: 'unusual activity',
});

const highRisk = () => ({
  risk_score: 70,
  risk_level: 'high',
  recommended_action: 'Require Additional Verification',
  reason: 'high risk',
});

describe('Section 5 — security risk-event logging', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('1. CONTEXT_CHANGE event is recorded when a meaningful context change occurs', async () => {
    setRisk(lowRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    jest.clearAllMocks();

    // Second event with a changed context (different IP/country).
    setRisk(lowRisk());
    const reqChanged = mockReq({ ip: '1.2.3.4' });
    await sessionMonitor.recordSessionEvent(reqChanged, 'document_viewed');

    const contextChangeCalls = securityEventService.recordSecurityEvent.mock.calls.filter(
      (call) => call[0].eventType === 'CONTEXT_CHANGE'
    );
    expect(contextChangeCalls.length).toBe(1);
    const event = contextChangeCalls[0][0];
    expect(event.eventType).toBe('CONTEXT_CHANGE');
    expect(event.user).toBe('u1');
    expect(event.contextChanges.locationChanged).toBe(true);
    expect(event.ip).toBe('1.2.3.4');
    expect(event.userAgent).toBe('TestBrowser/1.0');
  });

  test('2. CONTEXT_CHANGE is not recorded for trivial IP-only changes (same country)', async () => {
    setRisk(lowRisk());
    const req = mockReq({ ip: '10.0.0.99' });
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    jest.clearAllMocks();

    setRisk(lowRisk());
    const reqSameCountry = mockReq({ ip: '10.0.0.88' });
    await sessionMonitor.recordSessionEvent(reqSameCountry, 'document_viewed');

    const contextChangeCalls = securityEventService.recordSecurityEvent.mock.calls.filter(
      (call) => call[0].eventType === 'CONTEXT_CHANGE'
    );
    expect(contextChangeCalls.length).toBe(0);
  });

  test('3. REAUTH_REQUIRED event is recorded when session risk reaches re-auth threshold', async () => {
    setRisk(highRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const reauthCalls = securityEventService.recordSecurityEvent.mock.calls.filter(
      (call) => call[0].eventType === 'REAUTH_REQUIRED'
    );
    expect(reauthCalls.length).toBe(1);
    const event = reauthCalls[0][0];
    expect(event.eventType).toBe('REAUTH_REQUIRED');
    expect(event.user).toBe('u1');
    expect(event.riskScore).toBe(70);
    expect(event.riskLevel).toBe('high');
    expect(event.accumulatedRisk).toBeCloseTo(15, 1);
    expect(event.ip).toBe('127.0.0.1');
  });

  test('4. RISK_THRESHOLD_REACHED event is recorded alongside REAUTH_REQUIRED', async () => {
    setRisk(highRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const thresholdCalls = securityEventService.recordSecurityEvent.mock.calls.filter(
      (call) => call[0].eventType === 'RISK_THRESHOLD_REACHED'
    );
    expect(thresholdCalls.length).toBe(1);
    expect(thresholdCalls[0][0].riskScore).toBe(70);
    expect(thresholdCalls[0][0].reason).toBe('high risk');
  });

  test('5. REAUTH_SUCCESS event is recorded after successful baseline refresh', async () => {
    setRisk(medRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.requiresReauthentication = true;
    jest.clearAllMocks();

    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    const successCalls = securityEventService.recordSecurityEvent.mock.calls.filter(
      (call) => call[0].eventType === 'REAUTH_SUCCESS'
    );
    expect(successCalls.length).toBe(1);
    expect(successCalls[0][0].eventType).toBe('REAUTH_SUCCESS');
    expect(successCalls[0][0].user).toBe('u1');
    expect(successCalls[0][0].ip).toBe('127.0.0.1');
  });

  test('6. No sensitive authentication values are stored in security events', async () => {
    setRisk(highRisk());
    const req = mockReq({ headers: { 'user-agent': 'Chrome' } });
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const allCalls = securityEventService.recordSecurityEvent.mock.calls;
    for (const call of allCalls) {
      const event = call[0];
      expect(Object.keys(event)).not.toContain('password');
      expect(Object.keys(event)).not.toContain('otp');
      expect(Object.keys(event)).not.toContain('token');
      expect(Object.keys(event)).not.toContain('secret');
      expect(Object.keys(event)).not.toContain('code');
      expect(event.password).toBeUndefined();
      expect(event.otp).toBeUndefined();
      expect(event.token).toBeUndefined();
    }
  });

  test('7. DB failure during event recording does not crash the protected operation', async () => {
    securityEventService.recordSecurityEvent.mockRejectedValueOnce(
      new Error('MongoDB unavailable')
    );
    setRisk(highRisk());
    const req = mockReq();

    // Must NOT throw — recordSecurityEvent handles its own errors.
    const result = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(result).toBeDefined();
    expect(result.requiresReauthentication).toBe(true);
  });

  test('8. Existing Section 1 context tests still pass (no regression)', async () => {
    const baseline = {
      device: 'Desktop', browser: 'Chrome', operatingSystem: 'Windows',
      ip: '203.0.113.1', country: 'Australia', city: 'Sydney', vpnDetected: false,
    };
    const changed = { ...baseline, device: 'Mobile' };
    const result = sessionMonitor.compareSessionContext(baseline, changed);
    expect(result.deviceChanged).toBe(true);
    expect(result.browserChanged).toBe(false);
  });

  test('9. Existing Section 2 threshold tests still pass (no regression)', async () => {
    expect(sessionMonitor.classifySessionRisk({ risk_score: 20, risk_level: 'low' })).toBe('low');
    expect(sessionMonitor.classifySessionRisk({ risk_score: 70, risk_level: 'high' })).toBe('high');
    expect(sessionMonitor.classifySessionRisk({ risk_score: 90, risk_level: 'critical' })).toBe('critical');
    expect(sessionMonitor.classifySessionRisk(null)).toBe('low');
  });

  test('10. Existing Section 3 accumulation tests still pass (no regression)', async () => {
    setRisk(medRisk());
    setRisk(medRisk());
    const req = mockReq();
    const r1 = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    const r2 = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(r1.accumulatedRisk).toBeCloseTo(15, 2);
    expect(r2.accumulatedRisk).toBeCloseTo(30, 2);
  });

  test('11. Existing Section 4 baseline refresh tests still pass (no regression)', async () => {
    setRisk(medRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.requiresReauthentication = true;
    session.accumulatedRisk = 75;

    const refreshed = await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    expect(refreshed).toBe(true);
    expect(session.requiresReauthentication).toBe(false);
    expect(session.accumulatedRisk).toBe(0);
  });
});
