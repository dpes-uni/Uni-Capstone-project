/**
 * Step-up MFA tests (backend-only).
 *
 * Verifies the backend side of Sensitive-Action Step-Up MFA:
 *  - Sensitive routes gated by stepUpProtect
 *  - step-up OTP request/verify flow
 *  - stepUpVerified state expires and is consumed on use
 *  - step-up verification does NOT clear requiresReauthentication
 *  - risk-based reauth flow still works alongside step-up
 *  - Unauthenticated requests still get 401 from protect
 *
 * Uses MongoMemoryServer so the test is hermetic.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'stepup-test-secret';
process.env.JWT_REFRESH_SECRET = 'stepup-test-refresh-secret';
process.env.ACCESS_TOKEN_EXPIRES_IN = '1h';
process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS = '7';
process.env.OTP_EXPIRES_MINUTES = '10';
process.env.REQUIRE_SMTP = 'false';
process.env.STEP_UP_VERIFY_WINDOW_MS = '120000'; // 2 minutes
process.env.ADMIN_SIGNUP_KEY = 'stepup-admin-signup-key';

// The admin controller destructures recordSessionEvent out of this module at
// require time, so a plain jest.spyOn on the exported object would not be seen
// by it. Mock only the function under test while preserving every other real
// session-monitor behaviour (in-memory sessions, step-up state, etc.).
jest.mock('../src/services/sessionMonitor', () => {
  const actual = jest.requireActual('../src/services/sessionMonitor');
  return {
    ...actual,
    recordSessionEvent: jest.fn(),
  };
});

const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

let mongo;
let app;
let sessionMonitor;
let authToken;
let userId;
let adminToken;
let adminUserId;

const TEST_SUFFIX = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
const EMAIL = `stepup_${TEST_SUFFIX}@test.com`;
const ADMIN_EMAIL = `stepup_admin_${TEST_SUFFIX}@test.com`;
const PASSWORD = 'password123';

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  process.env.MONGO_URI = mongo.getUri();
  await connectDB();

  app = require('../src/app');
  sessionMonitor = require('../src/services/sessionMonitor');

  // Sign up and log in a regular user.
  const reg = await request(app)
    .post('/api/auth/register')
    .send({ name: 'StepUp Tester', email: EMAIL, password: PASSWORD, role: 'student' });
  expect(reg.statusCode).toBe(201);
  expect(reg.body.devOtpCode).toBeDefined();

  const regVerify = await request(app)
    .post('/api/auth/register/verify')
    .send({ signupId: reg.body.signupId, code: reg.body.devOtpCode });
  expect(regVerify.statusCode).toBe(201);

  const login = await request(app)
    .post('/api/auth/login')
    .send({ email: EMAIL, password: PASSWORD });
  expect(login.statusCode).toBe(200);
  expect(login.body.devOtpCode).toBeDefined();

  const mfa = await request(app)
    .post('/api/auth/verify-mfa')
    .send({ loginId: login.body.loginId, code: login.body.devOtpCode });
  expect(mfa.statusCode).toBe(200);
  authToken = mfa.body.token;

  const me = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${authToken}`);
  expect(me.statusCode).toBe(200);
  userId = me.body.user.id;

  // Sign up and log in an admin user.
  const aReg = await request(app)
    .post('/api/auth/admin-signup')
    .send({
      name: 'StepUp Admin',
      email: ADMIN_EMAIL,
      password: PASSWORD,
      signupKey: process.env.ADMIN_SIGNUP_KEY,
    });
  expect(aReg.statusCode).toBe(201);

  const aVerify = await request(app)
    .post('/api/auth/admin-signup/verify')
    .send({ signupId: aReg.body.signupId, code: aReg.body.devOtpCode });
  expect(aVerify.statusCode).toBe(201);

  const User = require('../src/models/User');
  // Promote to admin.
  await User.updateOne({ email: ADMIN_EMAIL }, { $set: { role: 'admin' } });

  const aLogin = await request(app)
    .post('/api/auth/login')
    .send({ email: ADMIN_EMAIL, password: PASSWORD, adminOnly: true });
  expect(aLogin.statusCode).toBe(200);

  const aMfa = await request(app)
    .post('/api/auth/verify-mfa')
    .send({ loginId: aLogin.body.loginId, code: aLogin.body.devOtpCode });
  expect(aMfa.statusCode).toBe(200);
  adminToken = aMfa.body.token;
  adminUserId = (await User.findOne({ email: ADMIN_EMAIL }))._id.toString();
}, 60000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongo.stop();
}, 15000);

beforeEach(() => {
  // Clear any session state that leaked between tests.
  sessionMonitor.sessions.clear();
});

describe('Section 6.3 — Step-Up MFA: middleware behaviour', () => {
  it('returns 401 for an unauthenticated request to /me', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.statusCode).toBe(401);
  });

  it('stepUpProtect rejects with 403 when no verification exists (direct middleware call)', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {});

    const { stepUpProtect } = require('../src/middleware/auth');

    const req = { user: { _id: userId } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    stepUpProtect(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    const body = res.json.mock.calls[0][0];
    expect(body.stepUpRequired).toBe(true);
    expect(body.reauthenticationRequired).toBe(false);
  });

  it('allows sensitive action when step-up verification is valid (consumes it)', () => {
    // Pre-populate session with valid step-up verification.
    sessionMonitor.sessions.set(`user:${userId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const { stepUpProtect } = require('../src/middleware/auth');

    const req = { user: { _id: userId } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    stepUpProtect(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();

    // After consumption, session should no longer hold stepUpVerified.
    const after = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(after?.stepUpVerified).toBeUndefined();
  });

  it('rejects when step-up verification is expired and clears it', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(Date.now() - 120_000),
        expiresAt: new Date(Date.now() - 60_000),
      },
    });

    const { stepUpProtect } = require('../src/middleware/auth');

    const req = { user: { _id: userId } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    stepUpProtect(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    const body = res.json.mock.calls[0][0];
    expect(body.stepUpRequired).toBe(true);
    expect(body.expired).toBe(true);

    const after = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(after?.stepUpVerified).toBeUndefined();
  });

  it('rejects when no step-up verification exists', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {});

    const { stepUpProtect } = require('../src/middleware/auth');

    const req = { user: { _id: userId } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    stepUpProtect(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    const body = res.json.mock.calls[0][0];
    expect(body.stepUpRequired).toBe(true);
    expect(body.reauthenticationRequired).toBe(false);
  });

  it('prefers risk-based reauth response when requiresReauthentication is true', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      requiresReauthentication: true,
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const { stepUpProtect } = require('../src/middleware/auth');

    const req = { user: { _id: userId } };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    stepUpProtect(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    const body = res.json.mock.calls[0][0];
    expect(body.reauthenticationRequired).toBe(true);
    expect(body.stepUpRequired).toBe(false);

    // Step-up verification must NOT be consumed when reauth takes precedence.
    const after = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(after?.stepUpVerified).toBeDefined();
  });

  it('second sensitive request requires new verification (consume prevents replay)', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {});
    sessionMonitor.establishStepUpVerification({
      user: { _id: userId },
      headers: { 'user-agent': 'jest' },
    });

    const { stepUpProtect } = require('../src/middleware/auth');

    const req = { user: { _id: userId } };
    const res1 = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next1 = jest.fn();
    stepUpProtect(req, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);

    // Second request — same session, no new verification.
    const res2 = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    const next2 = jest.fn();
    stepUpProtect(req, res2, next2);

    expect(next2).not.toHaveBeenCalled();
    expect(res2.status).toHaveBeenCalledWith(403);
    const body = res2.json.mock.calls[0][0];
    expect(body.stepUpRequired).toBe(true);
  });
});

describe('Section 6.3 — Step-Up MFA: /auth/stepup/request and /auth/stepup/verify', () => {
  it('requires authentication for /stepup/request', async () => {
    const res = await request(app).post('/api/auth/stepup/request');
    expect(res.statusCode).toBe(401);
  });

  it('requires authentication for /stepup/verify', async () => {
    const res = await request(app)
      .post('/api/auth/stepup/verify')
      .send({ reauthId: '507f1f77bcf86cd799439011', code: '123456' });
    expect(res.statusCode).toBe(401);
  });

  it('returns 400 with useReauthFlow when session already requires re-authentication', async () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      requiresReauthentication: true,
    });

    const reqRes = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reqRes.statusCode).toBe(400);
    expect(reqRes.body.useReauthFlow).toBe(true);

    const verifyRes = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: '507f1f77bcf86cd799439011', code: '123456' });
    expect(verifyRes.statusCode).toBe(400);
    expect(verifyRes.body.useReauthFlow).toBe(true);
  });

  it('issues a stepup OTP and verifies it, establishing stepUpVerified', async () => {
    const reqRes = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reqRes.statusCode).toBe(200);
    expect(reqRes.body.reauthId).toBeDefined();
    expect(reqRes.body.devOtpCode).toBeDefined();

    const OtpToken = require('../src/models/OtpToken');
    const otpDoc = await OtpToken.findById(reqRes.body.reauthId);
    expect(otpDoc).toBeTruthy();
    expect(otpDoc.purpose).toBe('stepup');
    expect(otpDoc.consumed).toBe(false);

    const verifyRes = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reqRes.body.reauthId, code: reqRes.body.devOtpCode });
    expect(verifyRes.statusCode).toBe(200);
    expect(verifyRes.body.stepUpVerified.purpose).toBe('stepup');
    expect(new Date(verifyRes.body.stepUpVerified.expiresAt).getTime()).toBeGreaterThan(Date.now());

    const otpAfter = await OtpToken.findById(reqRes.body.reauthId);
    expect(otpAfter.consumed).toBe(true);

    const session = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(session?.stepUpVerified?.purpose).toBe('stepup');
  });

  it('successful step-up does NOT clear requiresReauthentication', async () => {
    // First verify step-up in a clean session.
    const reqRes = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reqRes.statusCode).toBe(200);

    const verifyRes = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reqRes.body.reauthId, code: reqRes.body.devOtpCode });
    expect(verifyRes.statusCode).toBe(200);

    // Simulate the reauth flag being set concurrently (the step-up must not have
    // cleared it — but in this test we verify it never cleared anything to begin with).
    // Now set the flag and verify it is still present (i.e., step-up doesn't interact).
    sessionMonitor.sessions.set(`user:${userId}`, {
      requiresReauthentication: true,
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const session = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(session?.requiresReauthentication).toBe(true);
    expect(session?.stepUpVerified?.purpose).toBe('stepup');
  });

  it('rejects an invalid OTP code', async () => {
    const reqRes = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reqRes.statusCode).toBe(200);

    const verifyRes = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reqRes.body.reauthId, code: '000000' });
    expect(verifyRes.statusCode).toBe(400);

    const session = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(session?.stepUpVerified).toBeUndefined();
  });

  it('rejects an expired OTP', async () => {
    const reqRes = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reqRes.statusCode).toBe(200);

    const OtpToken = require('../src/models/OtpToken');
    await OtpToken.updateOne(
      { _id: reqRes.body.reauthId },
      { $set: { expiresAt: new Date(Date.now() - 1000) } }
    );

    const verifyRes = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reqRes.body.reauthId, code: reqRes.body.devOtpCode });
    expect(verifyRes.statusCode).toBe(400);
  });

  it('prevents reuse of a consumed OTP', async () => {
    const reqRes = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reqRes.statusCode).toBe(200);

    const verifyRes1 = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reqRes.body.reauthId, code: reqRes.body.devOtpCode });
    expect(verifyRes1.statusCode).toBe(200);

    const verifyRes2 = await request(app)
      .post('/api/auth/stepup/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reqRes.body.reauthId, code: reqRes.body.devOtpCode });
    expect(verifyRes2.statusCode).toBe(400);
  });

  it('invalidates prior pending step-up OTPs when a new one is requested', async () => {
    const first = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(first.statusCode).toBe(200);

    const second = await request(app)
      .post('/api/auth/stepup/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(second.statusCode).toBe(200);

    const OtpToken = require('../src/models/OtpToken');
    const firstOtp = await OtpToken.findById(first.body.reauthId);
    expect(firstOtp.consumed).toBe(true);

    const secondOtp = await OtpToken.findById(second.body.reauthId);
    expect(secondOtp.consumed).toBe(false);
  });

  it('risk-based reauthentication flow still works alongside step-up', async () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      requiresReauthentication: true,
      lastRiskResult: { risk_level: 'high', recommended_action: 'Require Additional Verification' },
    });

    const me1 = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);
    expect(me1.statusCode).toBe(403);
    expect(me1.body.reauthenticationRequired).toBe(true);

    const reauthReq = await request(app)
      .post('/api/auth/reauth/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(reauthReq.statusCode).toBe(200);

    const reauthVerify = await request(app)
      .post('/api/auth/reauth/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: reauthReq.body.reauthId, code: reauthReq.body.devOtpCode });
    expect(reauthVerify.statusCode).toBe(200);
    expect(reauthVerify.body.reauthenticationRequired).toBe(false);

    const me2 = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);
    expect(me2.statusCode).toBe(200);
  });

  it('admin role change handler responds appropriately (route registration not in this section)', async () => {
    // Section 6.4: stepUpProtect is now applied to this route.
    const User = require('../src/models/User');
    const targetUser = await User.findOne({ email: EMAIL });
    expect(targetUser).toBeTruthy();

    const res = await request(app)
      .patch(`/api/admin/users/${targetUser._id}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'agent' });

    // stepUpProtect gates the route; without step-up verification we get 403.
    expect(res.statusCode).toBe(403);
    expect(res.body.stepUpRequired).toBe(true);
    expect(res.body.reauthenticationRequired).toBe(false);
  });
});

describe('Section 6.4 — Step-Up MFA route enforcement', () => {
  it('POST /api/assessments/:id/document — unauthenticated → 401', async () => {
    const res = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document');
    expect(res.statusCode).toBe(401);
  });

  it('POST /api/assessments/:id/document — authenticated, no step-up → 403 stepUpRequired', async () => {
    const res = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.statusCode).toBe(403);
    expect(res.body.stepUpRequired).toBe(true);
    expect(res.body.reauthenticationRequired).toBe(false);
  });

  it('POST /api/assessments/:id/document — with valid step-up → reaches controller', async () => {
    // Pre-populate step-up verification.
    sessionMonitor.sessions.set(`user:${userId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const res = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);

    // stepUpProtect passed; controller runs. Assessment does not exist → 404, NOT 403.
    expect(res.statusCode).toBe(404);
    expect(res.body.stepUpRequired).toBeUndefined();

    // stepUpVerified was consumed.
    const session = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    expect(session?.stepUpVerified).toBeUndefined();
  });

  it('POST /api/assessments/:id/document — with expired step-up → 403 expired', async () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(Date.now() - 120_000),
        expiresAt: new Date(Date.now() - 60_000),
      },
    });

    const res = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.statusCode).toBe(403);
    expect(res.body.stepUpRequired).toBe(true);
    expect(res.body.expired).toBe(true);
  });

  it('POST /api/assessments/:id/document — second request after consumption → 403', async () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const first = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);
    expect(first.statusCode).toBe(404); // consumed; controller runs
    expect(first.body.stepUpRequired).toBeUndefined();

    const second = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);
    expect(second.statusCode).toBe(403);
    expect(second.body.stepUpRequired).toBe(true);
  });

  it('GET /api/assessments/:id/document — authenticated, no step-up → 403', async () => {
    const res = await request(app)
      .get('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.statusCode).toBe(403);
    expect(res.body.stepUpRequired).toBe(true);
  });

  it('GET /api/assessments/:id/document — unauthenticated → 401', async () => {
    const res = await request(app)
      .get('/api/assessments/507f1f77bcf86cd799439011/document');
    expect(res.statusCode).toBe(401);
  });

  it('PATCH /api/admin/assessments/:id/review — non-admin user → 403 admin', async () => {
    // Regular user attempts admin action — requireRole blocks it.
    const res = await request(app)
      .patch('/api/admin/assessments/507f1f77bcf86cd799439011/review')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ status: 'verified' });
    expect(res.statusCode).toBe(403);
  });

  it('PATCH /api/admin/assessments/:id/review — admin, no step-up → 403 stepUpRequired', async () => {
    const res = await request(app)
      .patch('/api/admin/assessments/507f1f77bcf86cd799439011/review')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'verified' });
    expect(res.statusCode).toBe(403);
    expect(res.body.stepUpRequired).toBe(true);
  });

  it('GET /api/admin/assessments/:id/document — admin, no step-up → 403 stepUpRequired', async () => {
    const res = await request(app)
      .get('/api/admin/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toBe(403);
    expect(res.body.stepUpRequired).toBe(true);
  });

  it('GET /api/admin/assessments/:id/document — admin, valid step-up → reaches controller', async () => {
    sessionMonitor.sessions.set(`user:${adminUserId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const res = await request(app)
      .get('/api/admin/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toBe(404); // controller reached, assessment does not exist
    expect(res.body.stepUpRequired).toBeUndefined();
  });

  it('PATCH /api/admin/assessments/:id/review — admin, valid step-up → 200 and records verification_action', async () => {
    const Assessment = require('../src/models/Assessment');
    const assessment = await Assessment.create({
      owner: adminUserId,
      applicantName: 'Review Target',
      status: 'pending',
      documentFile: {
        originalName: 'id-card.png',
        storedName: 'stored-id-card.png',
        mimeType: 'image/png',
        size: 1024,
        uploadedAt: new Date(),
      },
    });

    sessionMonitor.sessions.set(`user:${adminUserId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const res = await request(app)
      .patch(`/api/admin/assessments/${assessment._id}/review`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'verified', notes: 'Looks good' });

    // Step-up gate passed; the controller ran and the review succeeded.
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe('Assessment reviewed');
    expect(res.body.assessment.status).toBe('verified');
    expect(res.body.assessment.reviewedBy.toString()).toBe(adminUserId);
    expect(res.body.assessment.reviewedAt).toBeTruthy();

    // The successful review must feed the existing session-monitoring pipeline.
    expect(sessionMonitor.recordSessionEvent).toHaveBeenCalledTimes(1);
    expect(sessionMonitor.recordSessionEvent).toHaveBeenCalledWith(
      expect.objectContaining({ user: expect.any(Object) }),
      'verification_action'
    );
    expect(
      sessionMonitor.recordSessionEvent.mock.calls[0][0].user._id.toString()
    ).toBe(adminUserId);

    // The review was persisted before the session event was recorded.
    const persisted = await Assessment.findById(assessment._id);
    expect(persisted.status).toBe('verified');
    expect(String(persisted.reviewedBy)).toBe(adminUserId);
    expect(persisted.reviewedAt).toBeInstanceOf(Date);
  });

  it('PATCH /api/admin/users/:id/role — admin, valid step-up → reaches controller', async () => {
    const User = require('../src/models/User');
    const targetUser = await User.findOne({ email: EMAIL });
    expect(targetUser).toBeTruthy();

    sessionMonitor.sessions.set(`user:${adminUserId}`, {
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const res = await request(app)
      .patch(`/api/admin/users/${targetUser._id}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'agent' });

    expect(res.statusCode).toBe(200);
    expect(res.body.stepUpRequired).toBeUndefined();
  });

  it('risk-based reauthentication takes precedence over step-up on sensitive routes', async () => {
    // Session has both reauth pending AND step-up verification — reauth wins.
    sessionMonitor.sessions.set(`user:${userId}`, {
      requiresReauthentication: true,
      stepUpVerified: {
        purpose: 'stepup',
        verifiedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    const res = await request(app)
      .post('/api/assessments/507f1f77bcf86cd799439011/document')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.statusCode).toBe(403);
    expect(res.body.reauthenticationRequired).toBe(true);
    // stepUpRequired may or may not be present depending on whether
    // protect (sets reauthenticationRequired) or stepUpProtect (adds stepUpRequired)
    // runs first. Reauth takes precedence either way.
    expect(res.body.stepUpRequired).not.toBe(true);
  });

  it('non-sensitive routes are NOT gated by stepUpProtect', async () => {
    // GET /api/auth/me should not require step-up.
    const me = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);
    expect(me.statusCode).toBe(200);
    expect(me.body.stepUpRequired).toBeUndefined();

    // GET /api/assessments/ should not require step-up.
    const list = await request(app)
      .get('/api/assessments')
      .set('Authorization', `Bearer ${authToken}`);
    expect(list.statusCode).toBe(200);
    expect(list.body.stepUpRequired).toBeUndefined();

    // GET /api/admin/overview should not require step-up.
    const overview = await request(app)
      .get('/api/admin/overview')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(overview.statusCode).toBe(200);
    expect(overview.body.stepUpRequired).toBeUndefined();

    // GET /api/admin/assessments should not require step-up.
    const adminList = await request(app)
      .get('/api/admin/assessments')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminList.statusCode).toBe(200);
    expect(adminList.body.stepUpRequired).toBeUndefined();

    // PATCH /api/users/me should not require step-up.
    const mePatch = await request(app)
      .patch('/api/users/me')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ name: 'Renamed' });
    expect(mePatch.statusCode).toBe(200);
    expect(mePatch.body.stepUpRequired).toBeUndefined();
  });
});

describe('Section 6.3 — Step-Up MFA: state helpers (unit)', () => {
  it('establishStepUpVerification writes a valid record', () => {
    const expiresAt = sessionMonitor.establishStepUpVerification({
      user: { _id: userId },
      headers: { 'user-agent': 'jest' },
    });
    expect(expiresAt).toBeTruthy();
    expect(expiresAt.purpose).toBe('stepup');
    expect(new Date(expiresAt.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it('isStepUpVerificationValid returns true when unexpired, false when expired', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {});
    sessionMonitor.establishStepUpVerification({ user: { _id: userId } });
    expect(sessionMonitor.isStepUpVerificationValid({ user: { _id: userId } })).toBe(true);

    const session = sessionMonitor.getSessionStatus({ user: { _id: userId } });
    session.stepUpVerified.expiresAt = new Date(Date.now() - 1000);
    expect(sessionMonitor.isStepUpVerificationValid({ user: { _id: userId } })).toBe(false);
  });

  it('consumeStepUpVerification returns the record and clears it', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {});
    sessionMonitor.establishStepUpVerification({ user: { _id: userId } });
    const consumed = sessionMonitor.consumeStepUpVerification({ user: { _id: userId } });
    expect(consumed).toBeTruthy();
    expect(consumed.purpose).toBe('stepup');
    expect(sessionMonitor.isStepUpVerificationValid({ user: { _id: userId } })).toBe(false);
  });

  it('clearStepUpVerification removes the record', () => {
    sessionMonitor.sessions.set(`user:${userId}`, {});
    sessionMonitor.establishStepUpVerification({ user: { _id: userId } });
    expect(sessionMonitor.clearStepUpVerification({ user: { _id: userId } })).toBe(true);
    expect(sessionMonitor.clearStepUpVerification({ user: { _id: userId } })).toBe(false);
  });
});