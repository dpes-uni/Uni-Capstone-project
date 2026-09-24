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
    expect(body.aiRisk).toHaveProperty('unusualActivity');
    expect(body.aiRisk).toHaveProperty('confidence');
    expect(body.aiRisk).toHaveProperty('reason');
    expect(body.aiRisk).toHaveProperty('assessedAt');
    expect(body.aiRisk).toHaveProperty('status');

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

    // No current context / context changes have been observed on this session.
    expect(body.sessionContext).toBeNull();
    expect(body.contextChanges).toBeNull();

    if (body.aiRisk.score === null) {
      expect(body.aiRisk.level).toBeNull();
    }

    expect(typeof body.user.username).toBe('string');
    expect(body.user.role === null || typeof body.user.role === 'string').toBe(true);

    expect(body.baseline === null || typeof body.baseline === 'object').toBe(true);
  });

  // --- 8: Live context data is exposed, not replaced with null ---

  test('returns the live session context and context changes when present', async () => {
    const contextData = {
      currentSessionContext: {
        device: 'Mobile',
        browser: 'Safari',
        operatingSystem: 'iOS',
        ip: '10.0.0.7',
        country: 'United Kingdom',
        city: 'London',
        vpnDetected: true,
        loginAt: Date.now(),
      },
      contextChanges: {
        deviceChanged: true,
        browserChanged: true,
        osChanged: true,
        ipChanged: true,
        locationChanged: true,
        vpnChanged: true,
      },
    };

    seedSession(ADMIN_USER._id, contextData);
    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const body = res.body;

    expect(body.baseline).not.toBeNull();
    expect(body.sessionContext).not.toBeNull();
    expect(body.contextChanges).not.toBeNull();

    // The endpoint must not replace real supplied context data with null.
    expect(body.sessionContext.device).toBe('Mobile');
    expect(body.sessionContext.browser).toBe('Safari');
    expect(body.sessionContext.operatingSystem).toBe('iOS');
    expect(body.sessionContext.ip).toBe('10.0.0.7');
    expect(body.sessionContext.country).toBe('United Kingdom');
    expect(body.sessionContext.city).toBe('London');
    expect(body.sessionContext.vpnDetected).toBe(true);

    expect(body.contextChanges).toHaveProperty('deviceChanged');
    expect(body.contextChanges).toHaveProperty('browserChanged');
    expect(body.contextChanges).toHaveProperty('osChanged');
    expect(body.contextChanges).toHaveProperty('ipChanged');
    expect(body.contextChanges).toHaveProperty('locationChanged');
    expect(body.contextChanges).toHaveProperty('vpnChanged');
    expect(body.contextChanges.deviceChanged).toBe(true);
    expect(body.contextChanges.vpnChanged).toBe(true);
  });

  test('returns the real zeroed context-change flags after session initialization', async () => {
    seedSession(ADMIN_USER._id, {
      currentSessionContext: {
        device: 'Desktop',
        browser: 'Chrome',
        operatingSystem: 'Windows',
        ip: '192.168.1.42',
        country: 'United States',
        city: 'Springfield',
        vpnDetected: false,
        loginAt: Date.now(),
      },
      contextChanges: {
        deviceChanged: false,
        browserChanged: false,
        osChanged: false,
        ipChanged: false,
        locationChanged: false,
        vpnChanged: false,
      },
    });

    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const body = res.body;

    expect(body.sessionContext).not.toBeNull();
    expect(body.contextChanges).not.toBeNull();
    expect(body.contextChanges.deviceChanged).toBe(false);
    expect(body.contextChanges.browserChanged).toBe(false);
    expect(body.contextChanges.osChanged).toBe(false);
    expect(body.contextChanges.ipChanged).toBe(false);
    expect(body.contextChanges.locationChanged).toBe(false);
    expect(body.contextChanges.vpnChanged).toBe(false);
  });

  // --- 9: AI prediction and confidence are exposed ---

  test('exposes the real AI prediction and confidence when assessed', async () => {
    seedSession(ADMIN_USER._id, {
      lastRiskResult: {
        risk_score: 72,
        risk_level: 'high',
        recommended_action: 'Require Additional Verification',
        unusual_activity: true,
        confidence: 0.91,
        reason: 'Session ML prediction: unusual_activity=True, confidence=91.0%',
      },
      lastRiskCheckedAt: new Date('2026-01-01T10:00:00Z'),
    });

    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const body = res.body;

    expect(body.aiRisk.status).toBe('assessed');
    expect(body.aiRisk.score).toBe(72);
    expect(body.aiRisk.level).toBe('high');
    expect(body.aiRisk.unusualActivity).toBe(true);
    expect(body.aiRisk.confidence).toBe(0.91);
    expect(body.aiRisk.reason).toBe('Session ML prediction: unusual_activity=True, confidence=91.0%');
    expect(body.aiRisk.assessedAt).toEqual(new Date('2026-01-01T10:00:00Z').toISOString());

    // effectiveRiskLevel is a separate backend classification.
    expect(body).toHaveProperty('effectiveRiskLevel');
  });

  test('returns not_assessed with null AI fields when the AI has not assessed the session', async () => {
    seedSession(ADMIN_USER._id, {
      lastRiskResult: null,
      lastRiskCheckedAt: null,
    });

    const res = await request(app)
      .get('/api/admin/session-status')
      .set('x-test-user', JSON.stringify(ADMIN_USER));
    const body = res.body;

    expect(body.aiRisk.status).toBe('not_assessed');
    expect(body.aiRisk.score).toBeNull();
    expect(body.aiRisk.level).toBeNull();
    expect(body.aiRisk.unusualActivity).toBeNull();
    expect(body.aiRisk.confidence).toBeNull();
    expect(body.aiRisk.reason).toBeNull();
    expect(body.aiRisk.assessedAt).toBeNull();

    // The effective session risk is never replaced by a fake AI level.
    expect(body.effectiveRiskLevel).toBe('low');
  });
});

describe('GET /api/admin/active-sessions', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    sessionMonitor.sessions.clear();
  });

  test('unauthenticated request is rejected with 401', async () => {
    const res = await request(app).get('/api/admin/active-sessions');
    expect(res.status).toBe(401);
  });

  test('non-admin user is rejected with 403', async () => {
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(STUDENT_USER));
    expect(res.status).toBe(403);
  });

  test('admin receives all seeded active sessions', async () => {
    seedSession(ADMIN_USER._id);
    seedSession(STUDENT_USER._id);

    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('active', true);
    expect(res.body).toHaveProperty('count', 2);
    expect(res.body.sessions).toHaveLength(2);
  });

  test('two or more different users appear in the response', async () => {
    seedSession(ADMIN_USER._id);
    seedSession(STUDENT_USER._id);

    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const ids = res.body.sessions.map((s) => s.id);
    expect(ids).toContain('user:admin-001');
    expect(ids).toContain('user:student-001');
    expect(new Set(ids).size).toBe(2);
  });

  test('admin and student can both exist in the returned sessions array', async () => {
    seedSession(ADMIN_USER._id);
    seedSession(STUDENT_USER._id, {
      userRole: 'student',
      username: 'test.student@university.edu',
    });

    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const byId = Object.fromEntries(
      res.body.sessions.map((s) => [s.id, s])
    );

    expect(byId['user:admin-001'].user.role).toBe('admin');
    expect(byId['user:student-001'].user.role).toBe('student');
  });

  test('each returned session contains the expected monitoring fields', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const session = res.body.sessions[0];

    expect(session).toHaveProperty('user');
    expect(session.user).toHaveProperty('id');
    expect(session.user).toHaveProperty('username');
    expect(session.user).toHaveProperty('role');

    expect(session).toHaveProperty('startedAt');
    expect(session).toHaveProperty('lastActivity');

    expect(session).toHaveProperty('sessionStatus');
    expect(session.sessionStatus).toHaveProperty('requiresReauthentication');
    expect(session.sessionStatus).toHaveProperty('riskDecision');
    expect(session.sessionStatus).toHaveProperty('recommendedAction');

    expect(session).toHaveProperty('aiRisk');
    expect(session.aiRisk).toHaveProperty('score');
    expect(session.aiRisk).toHaveProperty('level');
    expect(session.aiRisk).toHaveProperty('unusualActivity');
    expect(session.aiRisk).toHaveProperty('confidence');
    expect(session.aiRisk).toHaveProperty('reason');
    expect(session.aiRisk).toHaveProperty('assessedAt');
    expect(session.aiRisk).toHaveProperty('status');

    expect(session).toHaveProperty('accumulatedRisk');
    expect(session).toHaveProperty('effectiveRiskLevel');

    expect(session).toHaveProperty('baseline');
    expect(session).toHaveProperty('sessionContext');
    expect(session).toHaveProperty('contextChanges');

    expect(session).toHaveProperty('activity');
    expect(session.activity).toHaveProperty('documentsViewed');
    expect(session.activity).toHaveProperty('documentsDownloaded');
    expect(session.activity).toHaveProperty('documentsUploaded');
    expect(session.activity).toHaveProperty('verificationActions');
    expect(session.activity).toHaveProperty('failedActions');
    expect(session.activity).toHaveProperty('rapidActions');
  });

  test('does not return tokens, passwords, OTPs or secrets', async () => {
    seedSession(ADMIN_USER._id);
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    const json = JSON.stringify(res.body);

    expect(json).not.toContain('JWT_SECRET');
    expect(json).not.toContain('refreshToken');
    expect(json).not.toContain('otp');
    expect(json).not.toContain('password');
    expect(json).not.toContain('salt');
    expect(json).not.toContain('verify');
    expect(json).not.toContain('otpSecret');
    expect(json).not.toContain('user-agent');
    expect(json).not.toContain('cookie');
  });

  test('empty sessions map returns count 0 and an empty sessions array', async () => {
    const res = await request(app)
      .get('/api/admin/active-sessions')
      .set('x-test-user', JSON.stringify(ADMIN_USER));

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('active', true);
    expect(res.body).toHaveProperty('count', 0);
    expect(res.body.sessions).toEqual([]);
  });
});
