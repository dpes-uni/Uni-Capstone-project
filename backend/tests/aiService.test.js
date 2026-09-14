const axios = require('axios');

jest.mock('axios');
jest.mock('../src/services/ipService', () => ({
  getIpGeolocation: jest.fn(async (ip) =>
    ip === '203.0.113.9'
      ? { country: 'United States', city: 'Austin', org: '', asn: null }
      : { country: 'Unknown', city: 'Unknown', org: '', asn: null }
  ),
  detectVpn: jest.fn(() => false),
}));
jest.mock('../src/models/LoginActivity', () => ({
  distinct: jest.fn(async () => []),
}));

const aiService = require('../src/services/aiService');

describe('AiService', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('extractDeviceInfo', () => {
    const run = (userAgent) =>
      aiService.extractDeviceInfo({ headers: { 'user-agent': userAgent } });

    test('detects Windows + Chrome + Desktop', () => {
      const info = run(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'
      );
      expect(info).toEqual({ device: 'Desktop', browser: 'Chrome', operatingSystem: 'Windows' });
    });

    test('detects MacOS + Safari', () => {
      const info = run('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15');
      expect(info.operatingSystem).toBe('MacOS');
      expect(info.browser).toBe('Safari');
      expect(info.device).toBe('Desktop');
    });

    test('detects Android + Firefox + Mobile', () => {
      const info = run('Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0');
      expect(info.operatingSystem).toBe('Android');
      expect(info.browser).toBe('Firefox');
      expect(info.device).toBe('Mobile');
    });

    test('falls back to Unknown', () => {
      const info = aiService.extractDeviceInfo({ headers: {} });
      expect(info).toEqual({ device: 'Desktop', browser: 'Unknown', operatingSystem: 'Unknown' });
    });
  });

  describe('buildLoginAttempt', () => {
    test('maps user, device and geolocation into the AI LoginAttempt format', async () => {
      const user = { email: 'demo@assuredocs.test', trustedDevices: [{ deviceHash: 'dev-1' }] };
      const req = {
        headers: {
          'user-agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
        },
      };
      const attempt = await aiService.buildLoginAttempt(user, 'dev-1', '203.0.113.9', 'UA', req, 2);

      expect(attempt.username).toBe('demo@assuredocs.test');
      expect(attempt.ip_address).toBe('203.0.113.9');
      expect(attempt.country).toBe('United States');
      expect(attempt.city).toBe('Austin');
      expect(attempt.operating_system).toBe('Windows');
      expect(attempt.browser).toBe('Chrome');
      expect(attempt.new_device).toBe(false);
      expect(attempt.trusted_device).toBe(true);
      expect(attempt.failed_login_attempts).toBe(2);
      expect(attempt.login_hour).toBeGreaterThanOrEqual(0);
      expect(attempt.login_hour).toBeLessThanOrEqual(23);
    });

    test('flags a device never seen before as new', async () => {
      const user = { email: 'demo@assuredocs.test', trustedDevices: [{ deviceHash: 'dev-1' }] };
      const req = { headers: {} };
      const attempt = await aiService.buildLoginAttempt(user, 'brand-new-hash', '10.0.0.5', 'UA', req, 0);
      expect(attempt.new_device).toBe(true);
      expect(attempt.trusted_device).toBe(false);
    });
  });

  describe('assessRisk', () => {
    test('POSTs the login attempt to /predict and returns the result', async () => {
      const payload = { username: 'demo@assuredocs.test', new_device: true };
      axios.post.mockResolvedValue({ data: { risk_score: 55, risk_level: 'medium', recommended_action: 'Require Email OTP', reason: 'x' } });

      const result = await aiService.assessRisk(payload);
      expect(axios.post).toHaveBeenCalledWith(
        expect.stringMatching(/\/predict$/),
        payload,
        expect.objectContaining({ timeout: 5000 })
      );
      expect(result.risk_score).toBe(55);
    });

    test('throws a descriptive error when the AI service is unreachable', async () => {
      axios.post.mockRejectedValue(new Error('ECONNREFUSED'));
      await expect(aiService.assessRisk({})).rejects.toThrow(/AI service unavailable/);
    });
  });

  describe('isHealthy', () => {
    test('returns true when the service reports healthy', async () => {
      axios.get.mockResolvedValue({ data: { status: 'healthy' } });
      await expect(aiService.isHealthy()).resolves.toBe(true);
    });

    test('returns false when the service is down', async () => {
      axios.get.mockRejectedValue(new Error('timeout'));
      await expect(aiService.isHealthy()).resolves.toBe(false);
    });
  });
});