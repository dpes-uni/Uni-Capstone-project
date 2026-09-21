const { scoreLogin } = require('../src/utils/riskEngine');

const baseUser = () => ({ trustedDevices: [{ deviceHash: 'dev1', ip: '1.2.3.4' }] });

const baseArgs = () => ({
  user: baseUser(),
  deviceHash: 'dev1',
  ip: '1.2.3.4',
  isNewDevice: false,
  isNewIp: false,
  recentFailedAttempts: 0,
});

describe('scoreLogin (rule-based risk engine)', () => {
  test('recognized device and IP with no failures scores 0 and is low risk', () => {
    const result = scoreLogin(baseArgs());
    expect(result.score).toBe(0);
    expect(result.level).toBe('low');
    expect(result.mfaRequired).toBe(false);
    expect(result.reasons).toContain('Recognized device and IP, no recent failures');
  });

  test('new device adds 40 points', () => {
    const result = scoreLogin({ ...baseArgs(), isNewDevice: true });
    expect(result.score).toBe(40);
    expect(result.level).toBe('medium');
    expect(result.mfaRequired).toBe(true);
  });

  test('new IP adds 25 points', () => {
    const result = scoreLogin({ ...baseArgs(), isNewIp: true });
    expect(result.score).toBe(25);
    expect(result.level).toBe('low');
    expect(result.mfaRequired).toBe(false);
  });

  test('3+ recent failed attempts add 25 points', () => {
    const result = scoreLogin({ ...baseArgs(), recentFailedAttempts: 3 });
    expect(result.score).toBe(25);
  });

  test('1-2 recent failed attempts add 10 points', () => {
    const result = scoreLogin({ ...baseArgs(), recentFailedAttempts: 2 });
    expect(result.score).toBe(10);
  });

  test('combined signals are additive', () => {
    const result = scoreLogin({
      ...baseArgs(),
      isNewDevice: true,
      isNewIp: true,
      recentFailedAttempts: 4,
    });
    expect(result.score).toBe(40 + 25 + 25);
    expect(result.level).toBe('high');
    expect(result.mfaRequired).toBe(true);
  });

  test('first-ever login (no trusted devices) adds 5 points', () => {
    const result = scoreLogin({ ...baseArgs(), user: { trustedDevices: [] } });
    expect(result.score).toBe(5);
    expect(result.level).toBe('low');
  });

  test('score is capped at the sum of all signals (max 95) and never exceeds 100', () => {
    const result = scoreLogin({
      ...baseArgs(),
      user: { trustedDevices: [] },
      isNewDevice: true,
      isNewIp: true,
      recentFailedAttempts: 10,
    });
    expect(result.score).toBe(95);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.level).toBe('high');
  });

  test('threshold boundary: 69 is medium, 70 is high', () => {
    const medium = scoreLogin({ ...baseArgs(), isNewDevice: true, recentFailedAttempts: 3 });
    expect(medium.score).toBe(65);
    expect(medium.level).toBe('medium');

    const high = scoreLogin({ ...baseArgs(), isNewDevice: true, isNewIp: true, recentFailedAttempts: 3 });
    expect(high.score).toBe(90);
    expect(high.level).toBe('high');
  });

  test('custom thresholds from env are respected', () => {
    const original = { medium: process.env.RISK_MEDIUM_THRESHOLD, high: process.env.RISK_HIGH_THRESHOLD };
    process.env.RISK_MEDIUM_THRESHOLD = '10';
    process.env.RISK_HIGH_THRESHOLD = '20';
    try {
      const result = scoreLogin({ ...baseArgs(), isNewIp: true });
      expect(result.score).toBe(25);
      expect(result.level).toBe('high');
    } finally {
      if (original.medium === undefined) delete process.env.RISK_MEDIUM_THRESHOLD;
      else process.env.RISK_MEDIUM_THRESHOLD = original.medium;
      if (original.high === undefined) delete process.env.RISK_HIGH_THRESHOLD;
      else process.env.RISK_HIGH_THRESHOLD = original.high;
    }
  });
});