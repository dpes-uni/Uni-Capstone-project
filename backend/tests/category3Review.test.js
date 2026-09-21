/**
 * Category 3 Review Verification Tests.
 *
 * Verifies 6 scenarios required by the Category 3 review:
 *  1. Normal action, score 35 → Monitor
 *  2. Sensitive action, score 35 → determine and report
 *  3. Repeated moderate normal events → accumulation to threshold
 *  4. Successful re-authentication → reset, cooldown, baseline
 *  5. Moderate anomaly during cooldown → Monitor, no MFA
 *  6. High/critical event during cooldown → strongest response
 *
 * Also inspects the action-specific threshold interaction:
 * does an individual medium-risk event become immediate re-auth
 * solely because an action-specific threshold classified it as high?
 */

process.env.RISK_MEDIUM_THRESHOLD = '30';
process.env.RISK_HIGH_THRESHOLD = '61';
process.env.RISK_CRITICAL_THRESHOLD = '81';
process.env.SESSION_RISK_CONTRIBUTION = '15';
process.env.SESSION_RISK_DECAY_PER_SECOND = '0.05';
process.env.REAUTH_COOLDOWN_MS = 5 * 60 * 1000;

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
const { getActionHighThreshold } = require('../src/utils/actionThresholds');

const mockReq = (overrides = {}) => ({
  user: { _id: 'review-u1', email: 'review@test.com', role: 'student' },
  headers: { 'user-agent': 'jest' },
  ip: '127.0.0.1',
  ...overrides,
});

const setRisk = (result) => aiService.assessSessionRisk.mockResolvedValueOnce(result);

const setRiskTimes = (n, riskFn) => {
  for (let i = 0; i < n; i++) setRisk(riskFn());
};

const medRisk35 = () => ({
  risk_score: 35,
  risk_level: 'medium',
  recommended_action: 'Require Email OTP',
  reason: 'medium',
});

const criticalRisk = () => ({
  risk_score: 95,
  risk_level: 'critical',
  recommended_action: 'Block Login',
  reason: 'critical',
});

const highRisk = () => ({
  risk_score: 70,
  risk_level: 'high',
  recommended_action: 'Require Additional Verification',
  reason: 'high',
});

describe('Category 3 Review — Scenario verification', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  // ── SCENARIO 1 — Normal action ──

  describe('Scenario 1 — Normal action, score 35', () => {
    test('individual classification = medium, session in Monitor', async () => {
      setRisk(medRisk35());
      const req = mockReq();
      const res = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

      const indClass = sessionMonitor.classifySessionRisk(medRisk35(), 'document_viewed');
      const threshold = getActionHighThreshold('document_viewed');

      console.log('--- SCENARIO 1 ---');
      console.log('Action: document_viewed (normal)');
      console.log('Score: 35');
      console.log('Individual classification:', indClass);
      console.log('Action high threshold:', threshold);
      console.log('accumulatedRisk:', res.accumulatedRisk);
      console.log('riskDecision:', res.riskDecision);
      console.log('requiresReauthentication:', res.requiresReauthentication);

      // Verify session state via getSessionStatus
      const status = sessionMonitor.getSessionStatus(req);

      expect(indClass).toBe('medium');
      expect(res.riskDecision).toBe('monitor');
      expect(res.requiresReauthentication).toBe(false);
      expect(status.riskLevel).toBe('medium');
    });
  });

  // ── SCENARIO 2 — Sensitive action ──

  describe('Scenario 2 — Sensitive action, score 35', () => {
    test('determine classification, accumulation, re-auth decision', async () => {
      setRisk(medRisk35());
      const req = mockReq();
      const res = await sessionMonitor.recordSessionEvent(req, 'document_uploaded');

      const indClass = sessionMonitor.classifySessionRisk(medRisk35(), 'document_uploaded');
      const threshold = getActionHighThreshold('document_uploaded');

      console.log('--- SCENARIO 2 ---');
      console.log('Action: document_uploaded (sensitive)');
      console.log('Score: 35');
      console.log('Individual classification:', indClass);
      console.log('Action high threshold:', threshold);
      console.log('accumulatedRisk:', res.accumulatedRisk);
      console.log('riskDecision:', res.riskDecision);
      console.log('requiresReauthentication:', res.requiresReauthentication);
      console.log('MFA triggered:', res.requiresReauthentication);

      console.log('\n=== SCENARIO 2 ANALYSIS ===');
      console.log(
        'Sensitive action uses RISK_MEDIUM_THRESHOLD (30) as its high threshold. ' +
        'Score 35 >= 30 → individual classification = HIGH. ' +
        'This is CATEGORY 2 BEHAVIOUR: sensitive actions use a stricter threshold. ' +
        'The individual HIGH classification flows to finalClass = max(high, accumulated) = high. ' +
        'Therefore re-auth is triggered by INDIVIDUAL classification, NOT by accumulated risk.'
      );

      expect(indClass).toBe('high');
      expect(res.accumulatedRisk).toBeCloseTo(15, 1);
      expect(res.riskDecision).toBe('reauth_required');
      expect(res.requiresReauthentication).toBe(true);
    });
  });

  // ── SCENARIO 3 — Repeated moderate normal events ──

  describe('Scenario 3 — 5 repeated moderate normal events (score 35 each)', () => {
    test('accumulated risk grows; events stay Monitor until threshold', async () => {
      for (let i = 0; i < 5; i++) setRisk(medRisk35());
      const req = mockReq();
      let last;
      const decisions = [];
      for (let i = 0; i < 5; i++) {
        last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
        decisions.push({
          event: i + 1,
          accumulatedRisk: last.accumulatedRisk,
          riskDecision: last.riskDecision,
          requiresReauthentication: last.requiresReauthentication,
        });
      }

      console.log('--- SCENARIO 3 ---');
      console.log('5 x normal action, score 35');
      decisions.forEach((d) => {
        console.log(
          `Event ${d.event}: accumulatedRisk=${d.accumulatedRisk.toFixed(1)}, ` +
          `riskDecision=${d.riskDecision}, reauth=${d.requiresReauthentication}`
        );
      });

      expect(decisions[0].riskDecision).toBe('monitor');
      expect(decisions[0].requiresReauthentication).toBe(false);
      expect(decisions[0].accumulatedRisk).toBeCloseTo(15, 1);

      expect(decisions[1].riskDecision).toBe('monitor');
      expect(decisions[1].requiresReauthentication).toBe(false);
      expect(decisions[1].accumulatedRisk).toBeCloseTo(30, 1);

      expect(decisions[2].riskDecision).toBe('monitor');
      expect(decisions[2].requiresReauthentication).toBe(false);
      expect(decisions[2].accumulatedRisk).toBeCloseTo(45, 1);

      expect(decisions[3].riskDecision).toBe('monitor');
      expect(decisions[3].requiresReauthentication).toBe(false);
      expect(decisions[3].accumulatedRisk).toBeCloseTo(60, 1);

      expect(decisions[4].riskDecision).toBe('reauth_required');
      expect(decisions[4].requiresReauthentication).toBe(true);
      expect(decisions[4].accumulatedRisk).toBeCloseTo(75, 1);

      // Verify re-auth was triggered by ACCUMULATED risk (75 >= 61), not individual
      const individualClass = sessionMonitor.classifySessionRisk(medRisk35(), 'document_viewed');
      expect(individualClass).toBe('medium'); // individually medium!

      const status = sessionMonitor.getSessionStatus(req);
      expect(status.riskLevel).toBe('high'); // effective risk is high (accumulated 75)
    });
  });

  // ── SCENARIO 4 — Successful re-authentication ──

  describe('Scenario 4 — Successful re-authentication', () => {
    test('accumulatedRisk reset, cooldown starts, baseline refreshed', async () => {
      setRiskTimes(5, medRisk35);
      const req = mockReq();
      for (let i = 0; i < 5; i++) {
        await sessionMonitor.recordSessionEvent(req, 'document_viewed');
      }

      const statusBefore = sessionMonitor.getSessionStatus(req);
      expect(statusBefore.requiresReauthentication).toBe(true);

      const result = await sessionMonitor.refreshSessionBaselineAfterReauth(req);
      expect(result).toBe(true);

      const statusAfter = sessionMonitor.getSessionStatus(req);

      console.log('--- SCENARIO 4 ---');
      console.log('After successful re-auth:');
      console.log('accumulatedRisk:', statusAfter.accumulatedRisk);
      console.log('riskDecision:', statusAfter.riskDecision);
      console.log('riskLevel:', statusAfter.riskLevel);
      console.log('requiresReauthentication:', statusAfter.requiresReauthentication);
      console.log('reauthCooldownUntil:', statusAfter.reauthCooldownUntil);
      console.log('isInReauthCooldown:', sessionMonitor.isInReauthCooldown(statusAfter));
      console.log('securityBaseline set:', statusAfter.securityBaseline !== null);

      expect(statusAfter.accumulatedRisk).toBe(0);
      expect(statusAfter.riskDecision).toBe('continue');
      expect(statusAfter.riskLevel).toBe('low');
      expect(statusAfter.requiresReauthentication).toBe(false);
      expect(statusAfter.reauthCooldownUntil).toBeGreaterThan(Date.now());
      expect(statusAfter.securityBaseline).not.toBeNull();
      expect(result).toBe(true);
    });
  });

  // ── SCENARIO 5 — Moderate anomaly during cooldown ──

  describe('Scenario 5 — Moderate anomaly during cooldown', () => {
    test('no immediate MFA, Monitor remains, accumulation operates', async () => {
      jest.useFakeTimers();

      // Build high risk and re-auth to start cooldown.
      setRiskTimes(5, medRisk35);
      const req = mockReq();
      for (let i = 0; i < 5; i++) {
        await sessionMonitor.recordSessionEvent(req, 'document_viewed');
      }
      await sessionMonitor.refreshSessionBaselineAfterReauth(req);

      // 3 moderate events during cooldown — should accumulate without MFA
      setRiskTimes(3, medRisk35);
      let last;
      for (let i = 0; i < 3; i++) {
        last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
      }

      console.log('--- SCENARIO 5 ---');
      console.log('During cooldown, 3 moderate events:');
      console.log('accumulatedRisk:', last.accumulatedRisk);
      console.log('riskDecision:', last.riskDecision);
      console.log('requiresReauthentication:', last.requiresReauthentication);

      expect(last.accumulatedRisk).toBeCloseTo(45, 1);
      expect(last.riskDecision).toBe('monitor');
      expect(last.requiresReauthentication).toBe(false);

      jest.useRealTimers();
    });
  });

  // ── SCENARIO 6 — High/critical event during cooldown ──

  describe('Scenario 6 — High/critical event during cooldown', () => {
    test('cooldown does NOT bypass security for high/critical', async () => {
      jest.useFakeTimers();

      // Build high risk and re-auth to start cooldown.
      setRiskTimes(5, medRisk35);
      const req = mockReq();
      for (let i = 0; i < 5; i++) {
        await sessionMonitor.recordSessionEvent(req, 'document_viewed');
      }
      await sessionMonitor.refreshSessionBaselineAfterReauth(req);

      // Critical event during cooldown
      setRisk(criticalRisk());
      const critRes = await sessionMonitor.recordSessionEvent(req, 'document_viewed');

      console.log('--- SCENARIO 6 ---');
      console.log('Critical event during cooldown:');
      console.log('riskDecision:', critRes.riskDecision);
      console.log('requiresReauthentication:', critRes.requiresReauthentication);
      console.log('accumulatedRisk:', critRes.accumulatedRisk);

      expect(critRes.requiresReauthentication).toBe(true);
      expect(critRes.riskDecision).toBe('reauth_required');

      // High event during cooldown (requiresReauthentication already true from critical)
      // Use a fresh session for the high event test
      setRiskTimes(5, medRisk35);
      const req2 = mockReq({ user: { _id: 'review-u2', email: 'review2@test.com', role: 'student' } });
      for (let i = 0; i < 5; i++) {
        await sessionMonitor.recordSessionEvent(req2, 'document_viewed');
      }
      await sessionMonitor.refreshSessionBaselineAfterReauth(req2);

      setRisk(highRisk());
      const highRes = await sessionMonitor.recordSessionEvent(req2, 'document_viewed');

      console.log('High event during cooldown (fresh session):');
      console.log('riskDecision:', highRes.riskDecision);
      console.log('requiresReauthentication:', highRes.requiresReauthentication);

      expect(highRes.requiresReauthentication).toBe(true);
      expect(highRes.riskDecision).toBe('reauth_required');

      console.log('\nCooldown does NOT suppress high/critical events — strongest response retained.');

      jest.useRealTimers();
    });
  });
});
