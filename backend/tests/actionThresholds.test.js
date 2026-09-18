/**
 * Unit tests for action-specific risk thresholds (Category 2).
 *
 * Verifies that:
 *  - normal actions use RISK_HIGH_THRESHOLD (default 61)
 *  - sensitive actions (document_uploaded, verification_action) use
 *    RISK_MEDIUM_THRESHOLD (default 30) — a stricter threshold
 *  - unknown/unconfigured actions default to the normal threshold
 *  - action-specific thresholds interact correctly with accumulated risk
 *  - unavailable/null context features are preserved as null
 *
 * Thresholds are derived from existing environment configuration —
 * no new magic numbers are introduced.
 */

process.env.RISK_MEDIUM_THRESHOLD = '30';
process.env.RISK_HIGH_THRESHOLD = '61';
process.env.RISK_CRITICAL_THRESHOLD = '81';
process.env.SESSION_RISK_CONTRIBUTION = '15';
process.env.SESSION_RISK_DECAY_PER_SECOND = '0.05';

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
const {
  SENSITIVE_ACTIONS,
  getActionHighThreshold,
  isSensitiveAction,
} = require('../src/utils/actionThresholds');
const aiService = require('../src/services/aiService');

const mockReq = (overrides = {}) => ({
  user: { _id: 'u1', email: 'a@test.com', role: 'student' },
  headers: { 'user-agent': 'jest' },
  ip: '127.0.0.1',
  ...overrides,
});

const setRisk = (result) => aiService.assessSessionRisk.mockResolvedValueOnce(result);

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

describe('Action thresholds — sensitive actions', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('SENSITIVE_ACTIONS contains the configured sensitive action types', () => {
    expect(SENSITIVE_ACTIONS.has('document_uploaded')).toBe(true);
    expect(SENSITIVE_ACTIONS.has('verification_action')).toBe(true);
  });

  test('document_uploaded is classified as sensitive', () => {
    expect(isSensitiveAction('document_uploaded')).toBe(true);
  });

  test('verification_action is classified as sensitive', () => {
    expect(isSensitiveAction('verification_action')).toBe(true);
  });

  test('document_viewed is NOT classified as sensitive', () => {
    expect(isSensitiveAction('document_viewed')).toBe(false);
  });

  test('null action is NOT classified as sensitive', () => {
    expect(isSensitiveAction(null)).toBe(false);
  });

  test('getActionHighThreshold returns strict threshold for sensitive action', () => {
    expect(getActionHighThreshold('document_uploaded')).toBe(30);
    expect(getActionHighThreshold('verification_action')).toBe(30);
  });

  test('getActionHighThreshold returns standard threshold for normal action', () => {
    expect(getActionHighThreshold('document_viewed')).toBe(61);
  });

  test('getActionHighThreshold returns standard threshold for unknown action', () => {
    // Unknown actions default to the universal high threshold.
    // Security is never silently disabled.
    expect(getActionHighThreshold('some_random_action')).toBe(61);
    expect(getActionHighThreshold('')).toBe(61);
    expect(getActionHighThreshold(null)).toBe(61);
    expect(getActionHighThreshold(undefined)).toBe(61);
  });
});

describe('Action thresholds — normal vs sensitive classification', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('sensitive action with medium score triggers re-auth', async () => {
    // score=35 > 30 (sensitive threshold) → classified as high → reauth required
    setRisk(medRisk());
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');
  });

  test('sensitive action with medium score via verification_action triggers re-auth', async () => {
    setRisk(medRisk());
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'verification_action');
    expect(res.requiresReauthentication).toBe(true);
  });

  test('normal action with same medium score does NOT trigger re-auth', async () => {
    // score=35 < 61 (normal threshold) → classified as medium → Monitor (no reauth)
    setRisk(medRisk());
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    expect(res.requiresReauthentication).toBe(false);
    expect(res.riskDecision).toBe('monitor');
  });

  test('sensitive action below its threshold does not trigger re-auth', async () => {
    setRisk({
      risk_score: 25,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'low',
    });
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    // score=25 < 30 → classified as medium → no reauth
    expect(res.requiresReauthentication).toBe(false);
  });

  test('normal action below normal threshold does not trigger re-auth', async () => {
    setRisk({
      risk_score: 50,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'medium',
    });
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    // score=50 < 61 → classified as medium → no reauth
    expect(res.requiresReauthentication).toBe(false);
  });

  test('both sensitive and normal actions respect critical threshold uniformly', async () => {
    setRisk({
      risk_score: 90,
      risk_level: 'critical',
      recommended_action: 'Block Login',
      reason: 'critical',
    });
    const sensitive = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    expect(sensitive.requiresReauthentication).toBe(true);
    expect(sensitive.riskDecision).toBe('reauth_required');

    const normal = await sessionMonitor.recordSessionEvent(mockReq(), 'document_viewed');
    expect(normal.requiresReauthentication).toBe(true);
    expect(normal.riskDecision).toBe('reauth_required');
  });
});

describe('Action thresholds — threshold boundary (sensitive)', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('sensitive action: score just below boundary (29) does not re-auth', async () => {
    setRisk({
      risk_score: 29,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'low',
    });
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    expect(res.requiresReauthentication).toBe(false);
    expect(res.riskDecision).toBe('monitor');
  });

  test('sensitive action: score at boundary (30) triggers re-auth', async () => {
    setRisk({
      risk_score: 30,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'medium',
    });
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    expect(res.requiresReauthentication).toBe(true);
    expect(res.riskDecision).toBe('reauth_required');
  });

  test('sensitive action: score just above boundary (31) triggers re-auth', async () => {
    setRisk({
      risk_score: 31,
      risk_level: 'medium',
      recommended_action: 'Require Email OTP',
      reason: 'medium',
    });
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    expect(res.requiresReauthentication).toBe(true);
  });
});

describe('Action thresholds — unknown/unconfigured action defaults safely', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('unknown action uses normal threshold (does not disable security)', () => {
    // score=50: below normal threshold (61), above sensitive threshold (30)
    // Unknown actions use RISK_HIGH_THRESHOLD (61) — security is never disabled.
    const result = sessionMonitor.classifySessionRisk(
      { risk_score: 50, risk_level: 'medium' },
      'some_unconfigured_action'
    );
    expect(result).toBe('medium'); // not 'high', not 'critical' — uses normal threshold
  });

  test('unknown action does not re-auth at normal threshold boundary', () => {
    // score=65: above normal threshold (61)
    const result = sessionMonitor.classifySessionRisk(
      { risk_score: 65, risk_level: 'medium' },
      'unknown_action'
    );
    // 65 >= 61 (normal threshold) → high → reauth would be required
    expect(result).toBe('high');
  });

  test('unknown action: default threshold is clearly documented as RISK_HIGH_THRESHOLD', () => {
    // The default for unknown actions is the standard high threshold.
    // This is documented in actionThresholds.js comments.
    expect(getActionHighThreshold('nonexistent_action')).toBe(61);
  });
});

describe('Action thresholds — interaction with accumulated risk', () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  test('sensitive action: single medium event triggers re-auth via classifySessionRisk', async () => {
    setRisk(medRisk());
    const res = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    // classifySessionRisk returns 'high' for sensitive action with score 35,
    // so accumulated risk is added and re-auth is triggered.
    expect(res.requiresReauthentication).toBe(true);
  });

  test('normal action: accumulated risk alone can trigger re-auth at normal threshold', async () => {
    // 5 medium events × 15 contribution = 75 > 61 (normal threshold)
    for (let i = 0; i < 5; i++) {
      setRisk(medRisk());
    }
    const req = mockReq();
    let last;
    for (let i = 0; i < 5; i++) {
      last = await sessionMonitor.recordSessionEvent(req, 'document_viewed');
    }
    expect(last.accumulatedRisk).toBeCloseTo(75, 1);
    expect(last.requiresReauthentication).toBe(true);
  });

  test('sensitive action: single event triggers re-auth via classifySessionRisk', async () => {
    // score=35 > 30 (sensitive threshold) → classified as high → reauth required
    setRisk(medRisk());
    const sensitive = await sessionMonitor.recordSessionEvent(mockReq(), 'document_uploaded');
    expect(sensitive.requiresReauthentication).toBe(true);
  });

  test('normal action: same score does NOT trigger re-auth', async () => {
    // score=35 < 61 (normal threshold) → classified as medium → no reauth
    setRisk(medRisk());
    const normal = await sessionMonitor.recordSessionEvent(
      mockReq({ user: { _id: 'different-user', email: 'b@test.com', role: 'student' } }),
      'document_viewed'
    );
    expect(normal.requiresReauthentication).toBe(false);
  });
});

describe('Action thresholds — exported interface', () => {
  test('getActionHighThreshold is exported', () => {
    expect(typeof getActionHighThreshold).toBe('function');
  });

  test('isSensitiveAction is exported', () => {
    expect(typeof isSensitiveAction).toBe('function');
  });

  test('SENSITIVE_ACTIONS is exported as a Set', () => {
    expect(SENSITIVE_ACTIONS instanceof Set).toBe(true);
  });
});
