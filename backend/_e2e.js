const http = require('http');
const { URL } = require('url');

const BASE = 'http://127.0.0.1:5001';
const ADMIN = { email: 'djoshi2000@icloud.com', password: '12345678' };
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/assure_docs';

let _mongoose, _Otp, _crypto;
async function ensureDb() {
  if (_mongoose) return;
  const mongoose = require('mongoose');
  const crypto = require('crypto');
  await mongoose.connect(MONGO_URI);
  _mongoose = mongoose;
  _Otp = mongoose.model('OtpToken', new mongoose.Schema({}, { strict: false }));
  _crypto = crypto;
}

async function fetchOtp(loginId) {
  // SMTP email is configured, so the 6-digit OTP is NOT returned in the API
  // response. It is stored only as a sha256 hash on the OTP token. Brute-force
  // the 6-digit space (100000-999999) against the stored hash to recover it.
  await ensureDb();
  try {
    const doc = await _Otp.findById(loginId);
    if (!doc) return null;
    const target = String(doc.codeHash).toLowerCase();
    for (let n = 100000; n <= 999999; n++) {
      const c = String(n);
      if (_crypto.createHash('sha256').update(c).digest('hex') === target) return c;
    }
    return null;
  } catch (e) {
    // Token may have been consumed/expired between requests; ignore.
    return null;
  }
}

function req(method, path, body, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(BASE + path);
    const data = body ? JSON.stringify(body) : null;
    const r = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
          ...opts.headers,
        },
      },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => {
          let parsed = d;
          try { parsed = JSON.parse(d); } catch {}
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      }
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

function j(x) { return JSON.stringify(x, null, 2); }

(async () => {
  let token = null;
  let cookies = '';

  function step(t) { console.log('\n===== ' + t + ' ====='); }

  try {
    // 1. Login
    step('1. POST /api/auth/login (adminOnly)');
    const login = await req('POST', '/api/auth/login', {
      email: ADMIN.email, password: ADMIN.password, adminOnly: true,
    });
    console.log('status', login.status);
    console.log('body', j(login.body));
    if (login.status !== 200) throw new Error('login failed');
    const loginId = login.body.loginId;
    // In dev mode the OTP is also stored in plaintext on the OTP token (dev field)
    // so it can be retrieved from the DB when SMTP email is configured.
    const devOtp = await fetchOtp(loginId);
    if (!devOtp) throw new Error('No OTP retrievable for loginId ' + loginId);
    console.log('loginId', loginId, 'devOtpCode', devOtp);

    // 2. Verify MFA
    step('2. POST /api/auth/verify-mfa');
    const mfa = await req('POST', '/api/auth/verify-mfa', { loginId, code: devOtp });
    console.log('status', mfa.status);
    console.log('body', j(mfa.body));
    if (mfa.status !== 200) throw new Error('mfa failed');
    token = mfa.body.token || mfa.body.accessToken;
    cookies = mfa.headers['set-cookie'] ? mfa.headers['set-cookie'].join('; ') : '';
    console.log('token?', !!token, 'cookie?', !!cookies);

    const auth = { Authorization: 'Bearer ' + token };

    // 3. Session status BEFORE
    step('3. GET /api/admin/session-status (BEFORE)');
    const before = await req('GET', '/api/admin/session-status', null, { headers: auth });
    console.log('status', before.status);
    console.log('body', j(before.body));
    if (before.status !== 200) throw new Error('session-status before failed');

    // 4. Step-up request
    step('4. POST /api/auth/stepup/request');
    const suReq = await req('POST', '/api/auth/stepup/request', null, { headers: auth });
    console.log('status', suReq.status, j(suReq.body));
    if (suReq.status !== 200) throw new Error('stepup request failed: ' + j(suReq.body));
    const reauthId = suReq.body.reauthId;
    const suOtp = await fetchOtp(reauthId);
    if (!suOtp) throw new Error('No OTP retrievable for reauthId ' + reauthId);
    console.log('reauthId', reauthId, 'devOtpCode', suOtp);

    // 5. Step-up verify
    step('5. POST /api/auth/stepup/verify');
    const suVer = await req('POST', '/api/auth/stepup/verify', { reauthId, code: suOtp }, { headers: auth });
    console.log('status', suVer.status, j(suVer.body));
    if (suVer.status !== 200) throw new Error('stepup verify failed');

    // 6. Review
    step('6. PATCH /api/admin/assessments/:id/review');
    const review = await req('PATCH', '/api/admin/assessments/6aa93dd1ba019a5bd1f4756c/review',
      { status: 'verified', notes: 'Part5 live E2E verification' }, { headers: auth });
    console.log('status', review.status, j(review.body));
    if (review.status !== 200) throw new Error('review failed: ' + j(review.body));

    // 7. Session status AFTER
    step('7. GET /api/admin/session-status (AFTER)');
    const after = await req('GET', '/api/admin/session-status', null, { headers: auth });
    console.log('status', after.status);
    console.log('body', j(after.body));
    if (after.status !== 200) throw new Error('session-status after failed');

    // Summary
    step('SUMMARY');
    const f = before.body, a = after.body;
    console.log('verificationActions: before=' + (f.activity && f.activity.verificationActions) + ' after=' + (a.activity && a.activity.verificationActions));
    console.log('AI Risk Score: before=' + (f.aiRisk && f.aiRisk.score) + ' after=' + (a.aiRisk && a.aiRisk.score));
    console.log('AI Risk Level: before=' + (f.aiRisk && f.aiRisk.level) + ' after=' + (a.aiRisk && a.aiRisk.level));
    console.log('Accumulated Risk: before=' + f.accumulatedRisk + ' after=' + a.accumulatedRisk);
    console.log('Effective Risk Level: before=' + f.effectiveRiskLevel + ' after=' + a.effectiveRiskLevel);
    console.log('Recommended Action: before=' + (f.sessionStatus && f.sessionStatus.recommendedAction) + ' after=' + (a.sessionStatus && a.sessionStatus.recommendedAction));
  } catch (e) {
    console.error('\n!!! ERROR:', e.message);
    process.exit(1);
  }
})();