const jwt = require('jsonwebtoken');
const {
  generateAuthToken,
  generateRandomToken,
  hashToken,
  deviceFingerprint,
  getClientIp,
} = require('../src/utils/generateToken');

process.env.JWT_SECRET = 'test-jwt-secret';

describe('token utilities', () => {
  test('generateAuthToken returns a JWT with the user id as sub', () => {
    const token = generateAuthToken('507f1f77bcf86cd799439011');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    expect(decoded.sub).toBe('507f1f77bcf86cd799439011');
    expect(typeof decoded.exp).toBe('number');
  });

  test('generateRandomToken produces a hex string of the requested length', () => {
    const token = generateRandomToken(16);
    expect(token).toMatch(/^[0-9a-f]{32}$/);
  });

  test('hashToken is deterministic and matches sha256', () => {
    const crypto = require('crypto');
    const expected = crypto.createHash('sha256').update('abc').digest('hex');
    expect(hashToken('abc')).toBe(expected);
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc')).not.toBe(hashToken('abd'));
  });

  test('deviceFingerprint hashes user agent + accept-language', () => {
    const req = {
      headers: { 'user-agent': 'Mozilla/5.0', 'accept-language': 'en-US,en;q=0.9' },
    };
    const fp = deviceFingerprint(req);
    expect(fp).toBe(hashToken('Mozilla/5.0::en-US,en;q=0.9'));
    expect(deviceFingerprint(req)).toBe(fp);
  });

  test('deviceFingerprint differs when user agent differs', () => {
    const a = deviceFingerprint({ headers: { 'user-agent': 'UA-A', 'accept-language': 'en' } });
    const b = deviceFingerprint({ headers: { 'user-agent': 'UA-B', 'accept-language': 'en' } });
    expect(a).not.toBe(b);
  });

  test('getClientIp prefers the first x-forwarded-for entry', () => {
    const req = { headers: { 'x-forwarded-for': '203.0.113.9, 10.0.0.1' }, ip: '127.0.0.1' };
    expect(getClientIp(req)).toBe('203.0.113.9');
  });

  test('getClientIp falls back to req.ip', () => {
    expect(getClientIp({ headers: {}, ip: '1.2.3.4' })).toBe('1.2.3.4');
  });
});