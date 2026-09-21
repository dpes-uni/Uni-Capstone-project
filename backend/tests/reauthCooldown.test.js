/**
 * Re-authentication cooldown tests (Category 3).
 *
 * Covers:
 *  - Accumulated risk behaviour (5 tests)
 *  - Monitor state for moderate risk (5 tests)
 *  - Re-authentication triggers (3 tests)
 *  - Cooldown behaviour after successful re-auth (5 tests)
 *  - Critical/high security override during cooldown (1 test)
 *  - Existing behaviour preserved (1 test)
 *
 * Uses real environment values with explicit overrides per describe block.
 */

process.env.RISK_MEDIUM_THRESHOLD = '30';
process.env.RISK_HIGH_THRESHOLD = '61';
process.env.RISK_CRITICAL_THRESHOLD = '81';
process.env.SESSION_RISK_CONTRIBUTION = '15';
process.env.SESSION_RISK_DECAY_PER_SECOND = '0.05';
process.env.REAUTH_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes

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
  user: { _id: 'cooldown-u1', email: 'cooldown@test.com', role: 'student' },
  headers: { 'user-agent': 'jest' },
  ip: '127.0.0.1',
  ...overrides,
});

const setRisk = (result) => aiService.assessSessionRisk.mockResolvedValueOnce(result);

const setRiskTimes = (n, riskFn) => {
  for (let i = 0; i < n; i++) setRisk(riskFn());
};

const lowRisk = () => ({
  risk_score: 20,
  risk_level: 'low',
  recommended_action: 'Allow Login',
  reason: 'low',
});

const medRisk = () => ({
  risk_score: 35,
  risk_level: 'medium',
  recommended_action: 'Require Email OTP',
  reason: 'medium',
});

const highRisk = () => ({
  risk_score: 70,
  risk_level: 'high',
  recommended_action: 'Require Additional Verification',
  reason: 'high',
});

const criticalRisk = () => ({
  risk_score: 95,
  risk_level: 'critical',
  recommended_action: 'Block Login',
  reason: 'critical',
});

// ──────────────────────────────────────────────────────────
// 1. Accumulated risk behaviour
// ──────────────────────────────────────────────────────────

describe('Accumulated risk', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('accumulated risk grows with each medium event', async () => {
    setRiskTimes(3, medRisk);
    const req = mockReq();

    const r1 = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(r1.accumulatedRisk).toBeCloseTo(15, 1);

    const r2 = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(r2.accumulatedRisk).toBeCloseTo(30, 1);

    const r3 = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(r3.accumulatedRisk).toBeCloseTo(45, 1);
  });

  test('accumulated risk caps at 100', async () => {
    // Create session with a low-risk event first, then manually
    // set accumulated risk near the cap and verify additional
    // contributions are capped at 100.
    setRisk(lowRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.accumulatedRisk = 95;
    session.accumulatedRiskUpdatedAt = Date.now();

    setRisk(medRisk());
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    // 95 + 15 = 110 → capped at 100.
    expect(session.accumulatedRisk).toBe(100);
  });

  test('accumulated risk decays over time', async () => {
    setRisk(medRisk());
    const req = mockReq();

    // Build up accumulated risk.
    let last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(last.accumulatedRisk).toBeCloseTo(15, 1);

    // Manually age the session so decay applies on next status check.
    const session = sessionMonitor.sessions.get(`user:${req.user._id}`);
    session.accumulatedRiskUpdatedAt = Date.now() - 60_000; // 60 seconds ago.

    // getSessionStatus applies decay.
    const status = sessionMonitor.getSessionStatus(req);
    expect(status.accumulatedRisk).toBeLessThan(15);
  });

  test('accumulated risk reaching high threshold triggers re-auth', async () => {
    // 5 × 15 = 75 > 61 (high threshold).
    setRiskTimes(5, medRisk);
    const req = mockReq();
    let last;
    for (let i = 0; i < 5; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    expect(last.accumulatedRisk).toBeCloseTo(75, 1);
    expect(last.requiresReauthentication).toBe(true);
    expect(last.riskDecision).toBe('reauth_required');
  });

  test('accumulated risk resets after clearSessionReauthentication', async () => {
    setRisk(medRisk());
    const req = mockReq();

    // Build up risk.
    let last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(last.accumulatedRisk).toBeCloseTo(15, 1);

    const cleared = sessionMonitor.clearSessionReauthentication(req);
    expect(cleared).toBe(true);

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.accumulatedRisk).toBe(0);
    expect(status.riskDecision).toBe('continue');
  });
});

// ──────────────────────────────────────────────────────────
// 2. Monitor state
// ──────────────────────────────────────────────────────────

describe('Monitor state — moderate risk stays active', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('single medium risk event enters Monitor', async () => {
    setRisk(medRisk());
    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.riskDecision).toBe('monitor');
    expect(res.requiresReauthentication).toBe(false);
  });

  test('Monitor state does not require MFA', async () => {
    setRisk(medRisk());
    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.requiresReauthentication).toBe(false);
  });

  test('risk is observable in Monitor state', async () => {
    setRisk(medRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('medium');
    expect(status.riskDecision).toBe('monitor');
    expect(status.accumulatedRisk).toBeCloseTo(15, 1);
  });

  test('multiple medium events accumulate without triggering re-auth below threshold', async () => {
    // 3 × 15 = 45 < 61 → still Monitor.
    setRiskTimes(3, medRisk);
    const req = mockReq();
    let last;
    for (let i = 0; i < 3; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    expect(last.riskDecision).toBe('monitor');
    expect(last.requiresReauthentication).toBe(false);
    expect(last.accumulatedRisk).toBeCloseTo(45, 1);
  });

  test('Monitor state is reflected in getSessionStatus', async () => {
    setRisk(medRisk());
    const req = mockReq();
    await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskDecision).toBe('monitor');
    expect(status.riskLevel).toBe('medium');
    expect(status.requiresReauthentication).toBe(false);
    expect(status.recommendedAction).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────
// 3. Re-authentication triggers
// ──────────────────────────────────────────────────────────

describe('Re-authentication triggers', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('accumulated risk at high threshold triggers re-auth', async () => {
    setRiskTimes(5, medRisk);
    const req = mockReq();
    let last;
    for (let i = 0; i < 5; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    expect(last.accumulatedRisk).toBeCloseTo(75, 1);
    expect(last.riskDecision).toBe('reauth_required');
    expect(last.requiresReauthentication).toBe(true);
  });

  test('critical individual event triggers re-auth immediately', async () => {
    setRisk(criticalRisk());
    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');
  });

  test('successful re-auth clears re-auth flag and sets cooldown', async () => {
    // Build effective high risk via accumulation.
    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    const statusBefore = sessionMonitor.getSessionStatus(req);
    expect(statusBefore.requiresReauthentication).toBe(true);

    // Complete re-authentication.
    const result = await sessionMonitor.refreshSessionBaselineAfterReauth(req);
    expect(result).toBe(true);

    const statusAfter = sessionMonitor.getSessionStatus(req);
    expect(statusAfter.requiresReauthentication).toBe(false);
    expect(statusAfter.riskDecision).toBe('continue');
    expect(statusAfter.accumulatedRisk).toBe(0);
    // Cooldown should be active.
    expect(statusAfter.reauthCooldownUntil).toBeGreaterThan(Date.now());
  });
});

// ──────────────────────────────────────────────────────────
// 4. Cooldown behaviour
// ──────────────────────────────────────────────────────────

describe('Re-authentication cooldown', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('after re-auth, moderate events remain Monitor during cooldown', async () => {
    // Build effective high risk to trigger re-auth.
    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    // Successful re-auth starts cooldown.
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    // During cooldown, a new moderate event → Monitor (not re-auth).
    setRisk(medRisk());
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(res.riskDecision).toBe('monitor');
    expect(res.requiresReauthentication).toBe(false);
  });

  test('cooldown timer is set after successful re-auth', async () => {
    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.reauthCooldownUntil).toBeGreaterThan(Date.now());
    expect(sessionMonitor.isInReauthCooldown(status)).toBe(true);
  });

  test('cooldown expires automatically after timeout', async () => {
    jest.useFakeTimers();

    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }

    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    let status = sessionMonitor.getSessionStatus(req);
    expect(sessionMonitor.isInReauthCooldown(status)).toBe(true);

    // Advance past cooldown.
    jest.advanceTimersByTime(6 * 60 * 1000);

    status = sessionMonitor.getSessionStatus(req);
    // getSessionStatus expires elapsed cooldowns.
    expect(status.reauthCooldownUntil).toBeNull();

    jest.useRealTimers();
  });

  test('during cooldown, risk monitoring and accumulation continue', async () => {
    jest.useFakeTimers();

    // Build high risk and re-auth to start cooldown.
    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    // Continue accumulating during cooldown.
    setRiskTimes(3, medRisk);
    let last;
    for (let i = 0; i < 3; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    // Accumulated risk should continue growing.
    expect(last.accumulatedRisk).toBeCloseTo(45, 1);
    // Still Monitor (45 < 61).
    expect(last.riskDecision).toBe('monitor');

    jest.useRealTimers();
  });

  test('isInReauthCooldown helper correctly identifies active cooldown', async () => {
    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    const status = sessionMonitor.getSessionStatus(req);
    expect(sessionMonitor.isInReauthCooldown(status)).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────
// 5. Critical / high security override during cooldown
// ──────────────────────────────────────────────────────────

describe('Security override during cooldown', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('critical event during cooldown overrides cooldown and triggers re-auth', async () => {
    // Build high risk, re-auth to start cooldown.
    setRiskTimes(5, medRisk);
    const req = mockReq();
    for (let i = 0; i < 5; i++) {
      await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    await sessionMonitor.refreshSessionBaselineAfterReauth(req);

    // Critical event during cooldown should override cooldown.
    setRisk(criticalRisk());
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');

    const status = sessionMonitor.getSessionStatus(req);
    // After re-auth, accumulatedRisk was reset to 0.
    // One critical event adds one contribution (15).
    expect(status.accumulatedRisk).toBeCloseTo(15, 1);
  });
});

// ──────────────────────────────────────────────────────────
// 6. Existing behaviour preserved
// ──────────────────────────────────────────────────────────

describe('Existing behaviour preserved', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('low risk remains in continue state', async () => {
    setRisk(lowRisk());
    const req = mockReq();
    const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

    expect(res.riskDecision).toBe('continue');
    expect(res.requiresReauthentication).toBe(false);

    const status = sessionMonitor.getSessionStatus(req);
    expect(status.riskLevel).toBe('low');
  });
});
