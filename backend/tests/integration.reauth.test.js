const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

let mongo;
let app;
let sessionMonitor;
let authToken;
let userId;

const EMAIL = `reauth_${Date.now()}@test.com`;
const PASSWORD = 'password123';

beforeAll(async () => {
  process.env.JWT_SECRET = 'test_secret_for_reauth_smoke';
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

async function signupAndLogin() {
  const reg = await request(app)
    .post('/api/auth/register')
    .send({ name: 'Reauth Tester', email: EMAIL, password: PASSWORD, role: 'student' });
  expect(reg.statusCode).toBe(201);
  expect(reg.body.devOtpCode).toBeDefined();

  const verify = await request(app)
    .post('/api/auth/register/verify')
    .send({ signupId: reg.body.signupId, code: reg.body.devOtpCode });
  expect(verify.statusCode).toBe(201);

  const login = await request(app)
    .post('/api/auth/login')
    .send({ email: EMAIL, password: PASSWORD });
  expect(login.statusCode).toBe(200);
  expect(login.body.devOtpCode).toBeDefined();

  const mfa = await request(app)
    .post('/api/auth/verify-mfa')
    .send({ loginId: login.body.loginId, code: login.body.devOtpCode });
  expect(mfa.statusCode).toBe(200);
  expect(mfa.body.token).toBeDefined();

  authToken = mfa.body.token;

  const me = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${authToken}`);
  userId = me.body.user.id;
}

describe('Session re-authentication enforcement (P1)', () => {
  beforeAll(signupAndLogin);

  it('allows normal protected access before a re-auth flag is set', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.statusCode).toBe(200);
  });

  it('returns 403 reauthenticationRequired once the session is flagged', async () => {
    sessionMonitor.sessions.set(`user:${userId}`, {
      requiresReauthentication: true,
      lastRiskResult: { risk_level: 'high', recommended_action: 'Require Additional Verification' },
    });

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.statusCode).toBe(403);
    expect(res.body.reauthenticationRequired).toBe(true);
  });

  it('re-authentication request issues an OTP and verify clears the flag', async () => {
    const req = await request(app)
      .post('/api/auth/reauth/request')
      .set('Authorization', `Bearer ${authToken}`);
    expect(req.statusCode).toBe(200);
    expect(req.body.reauthId).toBeDefined();
    expect(req.body.devOtpCode).toBeDefined();

    const verify = await request(app)
      .post('/api/auth/reauth/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ reauthId: req.body.reauthId, code: req.body.devOtpCode });
    expect(verify.statusCode).toBe(200);
    expect(verify.body.reauthenticationRequired).toBe(false);

    // Session flag must be cleared in the monitor.
    const status = sessionMonitor.getSessionStatus({
      user: { _id: userId },
    });
    expect(status?.requiresReauthentication).toBeFalsy();
  });

  it('restores normal protected access after re-authentication', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.statusCode).toBe(200);
  });
});
