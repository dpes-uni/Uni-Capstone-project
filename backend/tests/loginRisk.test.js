/**
 * Focused tests for login risk components and active-sessions timeout data.
 *
 * Covers:
 *   1. Login risk components persist on the activity record (rule + AI).
 *   2. AI unavailable produces null AI component data.
 *   3. Session initialization exposes stored component values.
 *   4. /admin/active-sessions returns timeout + loginRisk + aiRisk.recommendedAction.
 *   5. Normal inactivity timeout is 10 minutes.
 */

const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

let mongo;
let app;
let sessionMonitor;

jest.mock('../src/services/aiService', () => {
  const actual = jest.requireActual('../src/services/aiService');
  return {
    ...actual,
    extractDeviceInfo: jest.fn(() => ({
      device: 'Desktop',
      browser: 'Chrome',
      operatingSystem: 'Windows',
    })),
    buildLoginAttempt: jest.fn(async () => ({})),
    assessRisk: jest.fn(),
    assessSessionRisk: jest.fn(),
  };
});

jest.mock('../src/services/ipService', () => ({
  getIpGeolocation: jest.fn(async () => ({
    country: 'Australia',
    city: 'Sydney',
    org: '',
    asn: null,
  })),
  detectVpn: jest.fn(() => false),
}));

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-secret-login-risk';
  process.env.NODE_ENV = 'test';
  process.env.REQUIRE_SMTP = 'false';
  process.env.OTP_EXPIRES_MINUTES = '10';

  mongo = await MongoMemoryServer.create();
  process.env.MONGO_URI = mongo.getUri();
  await connectDB();

  app = require('../src/app');
  sessionMonitor = require('../src/services/sessionMonitor');
}, 60000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongo.stop();
});

const LOGIN_AUDIT = require('../src/models/LoginActivity');

async function signupAndLogin({ aiResult, aiUnavailable = false }) {
  const aiService = require('../src/services/aiService');
  if (aiUnavailable) {
    aiService.assessRisk.mockRejectedValueOnce(new Error('AI service unavailable'));
  } else {
    aiService.assessRisk.mockResolvedValueOnce(aiResult);
  }
  aiService.assessSessionRisk.mockResolvedValueOnce({
    risk_score: 20,
    risk_level: 'low',
    recommended_action: 'Allow Login',
    unusual_activity: false,
    confidence: 0.9,
    reason: 'ok',
  });

  const email = `loginrisk_${Date.now()}_${Math.floor(Math.random() * 1000)}@test.com`;
  const reg = await request(app)
    .post('/api/auth/register')
    .send({ name: 'Login Risk Tester', email, password: 'password123', role: 'student' });
  expect(reg.statusCode).toBe(201);

  const verify = await request(app)
    .post('/api/auth/register/verify')
    .send({ signupId: reg.body.signupId, code: reg.body.devOtpCode });
  expect(verify.statusCode).toBe(201);

  const login = await request(app)
    .post('/api/auth/login')
    .send({ email, password: 'password123' });
  expect(login.statusCode).toBe(200);

  const mfa = await request(app)
    .post('/api/auth/verify-mfa')
    .send({ loginId: login.body.loginId, code: login.body.devOtpCode });
  expect(mfa.statusCode).toBe(200);

  return { token: mfa.body.token, userId: mfa.body.user.id };
}

describe('Login risk components persisted on the activity record', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('rule and AI components are persisted when the AI service responds', async () => {
    const { userId } = await signupAndLogin({
      aiResult: {
        risk_score: 65,
        risk_level: 'medium',
        recommended_action: 'Require Email OTP',
        reason: 'new device',
      },
    });

    const docs = await LOGIN_AUDIT.find({
      user: new mongoose.Types.ObjectId(userId),
    });
    expect(docs.length).toBeGreaterThan(0);
    const doc = docs[0];

    // Rule component is always populated from scoreLogin().
    expect(typeof doc.ruleRiskScore).toBe('number');
    expect(doc.ruleRiskScore).toBeGreaterThanOrEqual(0);
    expect(typeof doc.ruleRiskLevel).toBe('string');

    // AI component is populated when the service responded.
    expect(doc.aiRiskScore).toBe(65);
    expect(doc.aiRiskLevel).toBe('medium');

    // Combined final values are preserved.
    expect(typeof doc.riskScore).toBe('number');
    expect(typeof doc.riskLevel).toBe('string');
  });

  test('AI unavailable produces null AI component data', async () => {
    const { userId } = await signupAndLogin({
      aiUnavailable: true,
    });

    const docs = await LOGIN_AUDIT.find({
      user: new mongoose.Types.ObjectId(userId),
    });
    expect(docs.length).toBeGreaterThan(0);
    const doc = docs[0];

    expect(typeof doc.ruleRiskScore).toBe('number');
    expect(typeof doc.ruleRiskLevel).toBe('string');

    // AI was genuinely unavailable — null, not fabricated.
    expect(doc.aiRiskScore).toBeNull();
    expect(doc.aiRiskLevel).toBeNull();
  });
});

describe('Session initialization exposes stored component values', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('verifyMfa copies persisted login risk components onto the monitored session', async () => {
    const { userId } = await signupAndLogin({
      aiResult: {
        risk_score: 65,
        risk_level: 'medium',
        recommended_action: 'Require Email OTP',
        reason: 'new device',
      },
    });

    const session = sessionMonitor.sessions.get(`user:${userId}`);
    expect(session).not.toBeUndefined();

    expect(session.loginRisk).toBeDefined();
    expect(session.loginRisk.ruleBased).toBeDefined();
    expect(typeof session.loginRisk.ruleBased.score).toBe('number');
    expect(typeof session.loginRisk.ruleBased.level).toBe('string');
    expect(session.loginRisk.ai).toBeDefined();
    expect(session.loginRisk.ai.score).toBe(65);
    expect(session.loginRisk.ai.level).toBe('medium');
  });

  test('verifyMfa stores null AI component when AI was unavailable', async () => {
    const { userId } = await signupAndLogin({ aiUnavailable: true });

    const session = sessionMonitor.sessions.get(`user:${userId}`);
    expect(session).not.toBeUndefined();

    expect(session.loginRisk.ai.score).toBeNull();
    expect(session.loginRisk.ai.level).toBeNull();
    expect(typeof session.loginRisk.ruleBased.score).toBe('number');
    expect(typeof session.loginRisk.ruleBased.level).toBe('string');
  });
});

// The full /api/admin/active-sessions contract (timeout + loginRisk +
// aiRisk.recommendedAction) is covered separately in
// activeSessionsContract.test.js, which uses the mocked-auth harness.

describe('Normal inactivity timeout is 10 minutes', () => {
  test('SESSION_IDLE_TIMEOUT_MS is 10 minutes', () => {
    const sessionMonitor = require('../src/services/sessionMonitor');
    // The constant is not exported; verify indirectly by checking that a
    // fresh session is not idle-timed-out after 5 minutes of inactivity.
    sessionMonitor.sessions.clear();
    const req = { user: { _id: 'timeout-test-1' }, headers: { 'user-agent': 'jest' }, ip: '127.0.0.1' };

    return sessionMonitor.initializeSession(req).then((session) => {
      // Force lastActivity to 5 minutes ago — well under the 10-minute limit.
      session.lastActivity = Date.now() - 5 * 60 * 1000;
      const info = sessionMonitor.getSessionTimeoutInfo(req);
      expect(info.idleTimeout).toBe(false);
      expect(info.timeUntilExpire).toBeGreaterThan(0);
      expect(info.timeUntilExpire).toBeLessThanOrEqual(10 * 60 * 1000);
    });
  });

  test('SESSION_IDLE_TIMEOUT_MS fires after 10 minutes of inactivity', () => {
    const sessionMonitor = require('../src/services/sessionMonitor');
    sessionMonitor.sessions.clear();
    const req = { user: { _id: 'timeout-test-2' }, headers: { 'user-agent': 'jest' }, ip: '127.0.0.1' };

    return sessionMonitor.initializeSession(req).then((session) => {
      // 11 minutes ago — past the 10-minute limit.
      session.lastActivity = Date.now() - 11 * 60 * 1000;
      const info = sessionMonitor.getSessionTimeoutInfo(req);
      expect(info.idleTimeout).toBe(true);
      expect(info.timeUntilExpire).toBe(0);
    });
  });
});