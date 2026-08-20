const { generateOtp, hashOtp } = require('../src/utils/otp');
const crypto = require('crypto');

describe('OTP utilities', () => {
  test('generateOtp returns a 6-digit numeric string', () => {
    const code = generateOtp();
    expect(code).toMatch(/^\d{6}$/);
  });

  test('generateOtp produces varied values', () => {
    const codes = new Set(Array.from({ length: 50 }, () => generateOtp()));
    expect(codes.size).toBeGreaterThan(1);
  });

  test('hashOtp returns a sha256 hex digest', () => {
    const hash = hashOtp('123456');
    const expected = crypto.createHash('sha256').update('123456').digest('hex');
    expect(hash).toBe(expected);
    expect(hash).toHaveLength(64);
  });

  test('hashOtp is deterministic and one-way', () => {
    expect(hashOtp('123456')).toBe(hashOtp('123456'));
    expect(hashOtp('123456')).not.toBe(hashOtp('654321'));
    expect(hashOtp('123456')).not.toContain('123456');
  });
});