/**
 * Tests for GET /api/admin/session-status endpoint.
 *
 * Verifies:
 *  1. Authenticated admin receives live session data
 *  2. Unauthenticated requests are rejected (401)
 *  3. Non-admin authenticated requests are rejected (403)
 *  4. Active session returns all expected fields
 *  5. No active session returns { active: false }
 *  6. Sensitive secrets are not returned
 *  7. Unavailable fields are null / 0 / false, not fabricated
 *
 * Auth and role middleware are mocked so tests focus on the
 * controller / route logic without MongoMemoryServer.
 */

const request = require('supertest');
const sessionMonitor = require('../src/services/sessionMonitor');

const ADMIN_USER = { _id: 'admin-001', role: 'admin', email: 'admin@test.com' };
const STUDENT_USER = { _id: 'student-001', role: 'student', email: 'student@test.com' };

const setTestUser = (user) => ({ 'x-test-user': JSON.stringify(user) });

// --- Mock auth: bypass JWT verification and DB user lookup. ---
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
      } catch (e) { /* ignore */ }
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

describe('GET /api/admin/session-status', () => {
  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET = 'test-secret';
  });

  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    sessionMonitor.sessions.clear();
  });

  // --- 1 & 2: Authentication ---

  test('unauthenticated request is rejected with 401', async () => {
    const res = await request(app).get('/api/admin/session-status');
    expect(res.status).toBe(401);
  });

  test('non-admin user is rejected with 403', async () => {
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(STUDENT_USER));
    expect(res.status).toBe(403);
  });

  // --- 3 & 4: Active session from live data ---

  test('authenticated admin with active session receives live session data', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('active', true);
    expect(res.body).toHaveProperty('user');
    expect(res.body.user).toHaveProperty('username');
    expect(res.body).toHaveProperty('sessionStatus');
    expect(res.body).toHaveProperty('aiRisk');
    expect(res.body).toHaveProperty('accumulatedRisk');
    expect(res.body).toHaveProperty('effectiveRiskLevel');
    expect(res.body).toHaveProperty('timeout');
    expect(res.body).toHaveProperty('baseline');
    expect(res.body).toHaveProperty('activity');
  });

  test('active session contains expected live fields', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const body = res.body;

    expect(body.sessionStatus.active).toBe(true);
    expect(body.sessionStatus).toHaveProperty('requiresReauthentication');
    expect(body.sessionStatus).toHaveProperty('riskDecision');
    expect(body.sessionStatus).toHaveProperty('recommendedAction');

    expect(body.aiRisk).toHaveProperty('score');
    expect(body.aiRisk).toHaveProperty('level');

    expect(body.timeout).toHaveProperty('idleTimeout');
    expect(body.timeout).toHaveProperty('highRiskTerminate');
    expect(body.timeout).toHaveProperty('timeUntilExpire');

    expect(body.activity).toHaveProperty('documentsViewed');
    expect(body.activity).toHaveProperty('documentsDownloaded');
    expect(body.activity).toHaveProperty('documentsUploaded');
    expect(body.activity).toHaveProperty('verificationActions');
    expect(body.activity).toHaveProperty('failedActions');
    expect(body.activity).toHaveProperty('rapidActions');
  });

  // --- 5: No active session ---

  test('no active session returns { active: false }', async () => {
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ active: false });
  });

  // --- 6: Secrets not returned ---

  test('does not return sensitive secrets', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const json = JSON.stringify(res.body);

    expect(json).not.toContain('JWT_SECRET');
    expect(json).not.toContain('refreshToken');
    expect(json).not.toContain('otp');
    expect(json).not.toContain('password');
    expect(json).not.toContain('salt');
    expect(json).not.toContain('verify');
    expect(json).not.toContain('otpSecret');
  });

  // --- 7: Unavailable fields not fabricated ---

  test('unavailable fields are null or 0 or false, never fabricated', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const body = res.body;

    expect(body.sessionContext).toBeNull();
    expect(body.contextChanges).toBeNull();

    if (body.aiRisk.score === null) {
      expect(body.aiRisk.level).toBeNull();
    }

    expect(typeof body.user.username).toBe('string');
    expect(body.user.role === null || typeof body.user.role === 'string').toBe(true);

    expect(body.baseline === null || typeof body.baseline === 'object').toBe(true);
  });
});
