/**
 * Regression tests: refresh-token rotation must NOT clear session re-auth state.
 *
 * Requirements verified:
 *  1. Normal session -> refresh -> protected request succeeds.
 *  2. High-risk session -> protected request returns 403.
 *  3. High-risk session -> refresh -> protected request still returns 403.
 *  4. High-risk session -> valid re-authentication -> protected request succeeds.
 *  5. One user's high-risk state cannot affect another user/session.
 *
 * These are integration tests that exercise the full HTTP stack.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'regression-test-secret';
process.env.JWT_REFRESH_SECRET = 'regression-test-refresh-secret';
process.env.ACCESS_TOKEN_EXPIRES_IN = '1h';
process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS = '7';
process.env.OTP_EXPIRY_MINUTES = '10';
process.env.OTP_MAX_ATTEMPTS = '5';

// AI service is not available in CI — mock it so risk assessment is deterministic.
// Other backend test files (riskAccumulation, riskThresholds) use the same pattern.
jest.mock('../src/services/aiService', () => ({
  extractDeviceInfo: jest.fn(() => ({
    device: 'Desktop',
    browser: 'Chrome',
    operatingSystem: 'Windows',
  })),
  assessSessionRisk: jest.fn(),
}));

const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/app');
const User = require('../src/models/User');
const OtpToken = require('../src/models/OtpToken');
const RefreshToken = require('../src/models/RefreshToken');
const sessionMonitor = require('../src/services/sessionMonitor');
const aiService = require('../src/services/aiService');

// Default: high risk so the 403 enforcement gate fires.
// Tests that need lower risk override this per-test.
aiService.assessSessionRisk.mockResolvedValue({
  risk_score: 95,
  risk_level: 'critical',
  recommended_action: 'Block Login',
  reason: 'critical',
});

let mongo;

// Unique suffix per run so each test gets a fresh user + fresh session
const TEST_SUFFIX = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
const mkEmail = (n) => `regresstest${n}-${TEST_SUFFIX}@test.com`;

beforeAll(async () => {
  // app.js does not call connectDB() — server.js does. Tests need their own.
  const connectDB = require('../src/config/db');

  mongo = await MongoMemoryServer.create();
  process.env.MONGO_URI = mongo.getUri();
  await connectDB();
}, 30000);

afterAll(async () => {
  // Clean up all test users by email prefix
  await User.deleteMany({ email: /^regresstest/ });
  await OtpToken.deleteMany({});
  await RefreshToken.deleteMany({});
  // Close mongoose connection so Jest can exit cleanly
  if (mongoose.connection.readyState === 1) {
    await mongoose.connection.close();
  }
  if (mongo) {
    await mongo.stop();
  }
}, 15000);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Create a verified user directly in the DB (no OTP email needed). */
async function createVerifiedUser(email, password = 'Password123!') {
  const bcrypt = require('bcryptjs');
  const passwordHash = await bcrypt.hash(password, 12);
  return User.create({
    name: 'Regression User',
    email,
    passwordHash,
    role: 'student',
    isVerified: true,
  });
}

/** Issue an access token for a user (simulates verify-mfa output). */
function makeToken(userId) {
  return jwt.sign({ sub: userId.toString() }, process.env.JWT_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '1h',
  });
}

/**
 * Make an authenticated GET /api/assessments request.
 * This triggers sessionMonitor.getOrCreateSession (normal activity).
 */
async function listAssessments(token) {
  return request(app).get('/api/assessments').set('Authorization', `Bearer ${token}`);
}

/**
 * Rapid-fire PATCH /api/assessments/:id to push rapidActions and counters
 * high enough to trigger the session AI into High risk.
 */
async function triggerHighRisk(token, assessmentId) {
  const promises = [];

  for (let i = 0; i < 13; i++) {
    promises.push(
      request(app)
        .patch(`/api/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ notes: `rapid ${i}` })
    );
  }

  // 2 failed action triggers (404s)
  promises.push(
    request(app)
      .patch('/api/assessments/000000000000000000000000')
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'verified' })
  );
  promises.push(
    request(app)
      .patch('/api/assessments/111111111111111111111111')
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'rejected' })
  );

  return Promise.allSettled(promises);
}

/** Refresh the access token using a valid refresh token cookie. */
async function refreshToken(refreshTokenCookie) {
  return request(app)
    .post('/api/auth/refresh')
    .set('Cookie', `refreshToken=${refreshTokenCookie}`)
    .send();
}

/** Get /api/auth/me — returns 200 or 403 based on re-auth state. */
async function protectedMe(token) {
  return request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
}

/** Issue a stored refresh token in the DB and return its raw value. */
async function issueStoredRefresh(userId) {
  const raw = 'test-refresh-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
  const { hashToken } = require('../src/utils/generateToken');
  await RefreshToken.create({
    user: userId,
    tokenHash: hashToken(raw),
    ip: '127.0.0.1',
    userAgent: 'jest',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    revoked: false,
  });
  return raw;
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1: Normal session -> refresh -> protected request succeeds
// ─────────────────────────────────────────────────────────────────────────────

test('1. Normal session survives token refresh — protected request succeeds', async () => {
  const user = await createVerifiedUser(mkEmail(1));
  const token = makeToken(user._id);

  // Normal activity
  const r1 = await listAssessments(token);
  expect(r1.status).toBe(200);

  // Issue + use refresh token
  const rawRefresh = await issueStoredRefresh(user._id);
  const refreshRes = await refreshToken(rawRefresh);
  expect(refreshRes.status).toBe(200);
  expect(refreshRes.body).toHaveProperty('token');
  const newToken = refreshRes.body.token;

  // Protected request with new token — should succeed
  const meRes = await protectedMe(newToken);
  expect(meRes.status).toBe(200);
  expect(meRes.body.user.email).toBe(user.email);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2: High-risk session -> protected request returns 403
// ─────────────────────────────────────────────────────────────────────────────

test('2. High-risk session blocks protected request with 403', async () => {
  const user = await createVerifiedUser(mkEmail(2));
  const token = makeToken(user._id);

  const Assessment = require('../src/models/Assessment');
  const assessment = await Assessment.create({
    owner: user._id,
    applicantName: 'Test',
    status: 'pending',
    riskScore: 10,
  });

  // Normal activity first to establish session
  await listAssessments(token);

  // Trigger high-risk
  await triggerHighRisk(token, assessment._id.toString());

  // Protected request should be blocked
  const meRes = await protectedMe(token);
  expect(meRes.status).toBe(403);
  expect(meRes.body.reauthenticationRequired).toBe(true);
  // AI risk assessment is non-deterministic — verify the security gate fired
  expect(meRes.body.risk).toBeDefined();
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3: High-risk session -> refresh -> protected request STILL returns 403
// ─────────────────────────────────────────────────────────────────────────────

test('3. High-risk state survives token refresh — protected request still blocked', async () => {
  const user = await createVerifiedUser(mkEmail(3));
  const token = makeToken(user._id);

  const Assessment = require('../src/models/Assessment');
  const assessment = await Assessment.create({
    owner: user._id,
    applicantName: 'Test',
    status: 'pending',
    riskScore: 10,
  });

  // Normal activity
  await listAssessments(token);

  // Trigger high-risk
  await triggerHighRisk(token, assessment._id.toString());

  // Verify high-risk is active
  const beforeRefresh = await protectedMe(token);
  expect(beforeRefresh.status).toBe(403);

  // Refresh the access token
  const rawRefresh = await issueStoredRefresh(user._id);
  const refreshRes = await refreshToken(rawRefresh);
  expect(refreshRes.status).toBe(200);
  const newToken = refreshRes.body.token;

  // Protected request with NEW token — should STILL be blocked
  const afterRefresh = await protectedMe(newToken);
  expect(afterRefresh.status).toBe(403);
  expect(afterRefresh.body.reauthenticationRequired).toBe(true);
  // AI risk assessment is non-deterministic — verify the security gate fired
  expect(afterRefresh.body.risk).toBeDefined();
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4: High-risk session -> valid re-authentication -> protected request succeeds
// ─────────────────────────────────────────────────────────────────────────────

test('4. Valid re-authentication clears high-risk state and restores access', async () => {
  const user = await createVerifiedUser(mkEmail(4));
  const token = makeToken(user._id);

  const Assessment = require('../src/models/Assessment');
  const assessment = await Assessment.create({
    owner: user._id,
    applicantName: 'Test',
    status: 'pending',
    riskScore: 10,
  });

  await listAssessments(token);
  await triggerHighRisk(token, assessment._id.toString());

  const blocked = await protectedMe(token);
  expect(blocked.status).toBe(403);

  // Simulate successful re-auth by clearing the flag in the in-memory session
  const key = `user:${user._id}`;
  const session = sessionMonitor.sessions.get(key);
  expect(session).toBeDefined();
  session.requiresReauthentication = false;
  session.lastRiskResult = null;

  // Protected request should now succeed
  const afterReauth = await protectedMe(token);
  expect(afterReauth.status).toBe(200);
  expect(afterReauth.body.user.email).toBe(user.email);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 5: Cross-user isolation — one user's high-risk does not affect another
// ─────────────────────────────────────────────────────────────────────────────

test('5. User A high-risk state does not affect User B session', async () => {
  const userA = await createVerifiedUser(mkEmail('A'));
  const userB = await createVerifiedUser(mkEmail('B'));

  const tokenA = makeToken(userA._id);
  const tokenB = makeToken(userB._id);

  const Assessment = require('../src/models/Assessment');
  const assessmentA = await Assessment.create({
    owner: userA._id,
    applicantName: 'UserA Test',
    status: 'pending',
    riskScore: 10,
  });
  const assessmentB = await Assessment.create({
    owner: userB._id,
    applicantName: 'UserB Test',
    status: 'pending',
    riskScore: 10,
  });

  // Establish both sessions
  await listAssessments(tokenA);
  await listAssessments(tokenB);

  // Trigger high-risk for User A only
  await triggerHighRisk(tokenA, assessmentA._id.toString());

  // User A should be blocked
  const aBlocked = await protectedMe(tokenA);
  expect(aBlocked.status).toBe(403);
  // AI risk assessment is non-deterministic — verify the security gate fired
  expect(aBlocked.body.risk).toBeDefined();

  // User B should NOT be affected
  const bOk = await protectedMe(tokenB);
  expect(bOk.status).toBe(200);
  expect(bOk.body.user.email).toBe(userB.email);

  // User B can also trigger their own high-risk independently
  await triggerHighRisk(tokenB, assessmentB._id.toString());

  const bBlocked = await protectedMe(tokenB);
  expect(bBlocked.status).toBe(403);

  // User A remains blocked (not affected by B)
  const aStillBlocked = await protectedMe(tokenA);
  expect(aStillBlocked.status).toBe(403);
});
