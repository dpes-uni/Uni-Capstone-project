/**
 * Contract tests for GET /api/admin/active-sessions.
 *
 * Verifies the new response fields added to the live data contract:
 *   1. Each session exposes a full timeout object (idleTimeout,
 *      highRiskTerminate, reauthRequired, reauthWindowExpired,
 *      timeUntilReauthExpire, timeUntilExpire).
 *   2. Each session exposes aiRisk.recommendedAction.
 *   3. Each session exposes loginRisk.ruleBased and loginRisk.ai.
 *   4. loginRisk.ai is null when the AI component was unavailable.
 *   5. Normal inactivity timeout is 10 minutes (timeUntilExpire starts at
 *      10 minutes for a freshly seeded low-risk session).
 *
 * Uses the same mocked-auth harness as sessionStatus.test.js.
 */

const request = require('supertest');

const ADMIN_USER = { _id: 'admin-001', role: 'admin', email: 'admin@test.com' };
const STUDENT_USER = { _id: 'student-001', role: 'student', email: 'student@test.com' };

const setTestUser = (user) => ({ 'x-test-user': JSON.stringify(user) });

jest.mock('../src/middleware/auth.js', () => ({
  authenticateSession: (req, res, next) => next(),
  protect: (req, res, next) => {
    const raw = req.headers['x-test-user'];
    if (raw) {
      try {
        req.user = JSON.parse(raw);
        return next();
      } catch (e) {
        /* malformed user header */
      }
    }
    req.user = null;
    return res.status(401).json({ message: 'Not authorized, no token provided' });
  },
  stepUpProtect: (req, res, next) => {
    const raw = req.headers['x-test-user'];
    if (raw) {
      try {
        req.user = JSON.parse(raw);
        return next();
      } catch (e) {
        /* ignore */
      }
    }
    req.user = null;
    return res.status(401).json({ message: 'Not authorized, no token provided' });
  },
}));

jest.mock('../src/middleware/roles.js', () => ({
  requireRole: (...roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    next();
  },
}));

const app = require('../src/app');
const sessionMonitor = require('../src/services/sessionMonitor');

const seedSession = (userId, data = {}) => {
  const key = `user:${userId}`;
  sessionMonitor.sessions.set(key, {
    userId,
    username: 'test.admin@university.edu',
    userRole: 'admin',
    startedAt: new Date(Date.now() - 23 * 60000).toISOString(),
    lastActivity: Date.now(),
    documentsViewed: 5,
    documentsDownloaded: 2,
    documentsUploaded: 1,
    verificationActions: 3,
    failedActions: 0,
    actionTimestamps: [Date.now()],
    requiresReauthentication: false,
    lastRiskResult: { risk_score: 12, risk_level: 'low', recommended_action: 'Allow Login', reason: 'low' },
    lastRiskCheckedAt: Date.now(),
    riskDecision: 'continue',
    accumulatedRisk: 12,
    riskLevel: 'low',
    loginRisk: {
      ruleBased: { score: 20, level: 'low' },
      ai: { score: 12, level: 'low' },
    },
    securityBaseline: {
      device: 'Desktop',
      browser: 'Chrome',
      operatingSystem: 'Windows',
      ip: '192.168.1.42',
      country: 'United States',
      city: 'Springfield',
      vpnDetected: false,
      loginAt: Date.now(),
    },
    ...data,
  });
};

describe('GET /api/admin/active-sessions — new contract fields', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    sessionMonitor.sessions.clear();
  });

  test('each session exposes a full timeout object', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];
    expect(session.timeout).toHaveProperty('idleTimeout');
    expect(session.timeout).toHaveProperty('highRiskTerminate');
    expect(session.timeout).toHaveProperty('reauthRequired');
    expect(session.timeout).toHaveProperty('reauthWindowExpired');
    expect(session.timeout).toHaveProperty('timeUntilReauthExpire');
    expect(session.timeout).toHaveProperty('timeUntilExpire');
  });

  test('each session exposes aiRisk.recommendedAction', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];
    expect(session.aiRisk).toHaveProperty('recommendedAction');
    expect(session.aiRisk.recommendedAction).toBe('Allow Login');
  });

  test('each session exposes loginRisk.ruleBased and loginRisk.ai', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];
    expect(session.loginRisk).toHaveProperty('ruleBased');
    expect(session.loginRisk).toHaveProperty('ai');
    expect(session.loginRisk.ruleBased).toHaveProperty('score');
    expect(session.loginRisk.ruleBased).toHaveProperty('level');
    expect(session.loginRisk.ai).toHaveProperty('score');
    expect(session.loginRisk.ai).toHaveProperty('level');
  });

  test('loginRisk.ai is null when the AI component was unavailable', async () => {
    seedSession(ADMIN_USER._id, {
      loginRisk: {
        ruleBased: { score: 20, level: 'low' },
        ai: { score: null, level: null },
      },
    });
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];
    expect(session.loginRisk.ai.score).toBeNull();
    expect(session.loginRisk.ai.level).toBeNull();
    expect(session.loginRisk.ruleBased.score).toBe(20);
    expect(session.loginRisk.ruleBased.level).toBe('low');
  });

  test('normal inactivity timeout is 10 minutes for a low-risk session', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];
    // Fresh low-risk session: idle timeout not yet expired, and the
    // remaining inactivity time is within the 10-minute window.
    expect(session.timeout.idleTimeout).toBe(false);
    expect(session.timeout.reauthRequired).toBe(false);
    expect(session.timeout.timeUntilExpire).toBeGreaterThan(0);
    expect(session.timeout.timeUntilExpire).toBeLessThanOrEqual(10 * 60 * 1000);
  });

  test('high-risk session pending re-authentication preserves re-auth window semantics', async () => {
    seedSession(ADMIN_USER._id, {
      riskLevel: 'high',
      requiresReauthentication: true,
      reauthRequiredSince: Date.now(),
    });
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];
    expect(session.timeout.reauthRequired).toBe(true);
    expect(session.timeout.highRiskTerminate).toBe(false);
    expect(session.timeout.timeUntilExpire).toBeGreaterThan(0);
  });
});