/**
 * Unit tests for session context comparison logic.
 *
 * Tests compareSessionContext() and session baseline establishment
 * for the Enhanced Session Context Monitoring feature.
 */

jest.mock('../src/services/ipService', () => ({
  getIpGeolocation: jest.fn(),
  detectVpn: jest.fn(),
}));

jest.mock('../src/services/aiService', () => ({
  extractDeviceInfo: jest.fn(),
}));

const { compareSessionContext } = require('../src/services/sessionMonitor');

describe('compareSessionContext', () => {
  const baseline = {
    device: 'Desktop',
    browser: 'Chrome',
    operatingSystem: 'Windows',
    ip: '203.0.113.1',
    country: 'Australia',
    city: 'Sydney',
    vpnDetected: false,
  };

  test('no changes — all flags false', () => {
    const current = { ...baseline };
    const result = compareSessionContext(baseline, current);
    expect(result.deviceChanged).toBe(false);
    expect(result.browserChanged).toBe(false);
    expect(result.osChanged).toBe(false);
    expect(result.ipChanged).toBe(false);
    expect(result.locationChanged).toBe(false);
    expect(result.vpnChanged).toBe(false);
  });

  test('device changed', () => {
    const current = { ...baseline, device: 'Mobile' };
    const result = compareSessionContext(baseline, current);
    expect(result.deviceChanged).toBe(true);
    expect(result.browserChanged).toBe(false);
    expect(result.osChanged).toBe(false);
    expect(result.ipChanged).toBe(false);
    expect(result.locationChanged).toBe(false);
    expect(result.vpnChanged).toBe(false);
  });

  test('browser changed', () => {
    const current = { ...baseline, browser: 'Firefox' };
    const result = compareSessionContext(baseline, current);
    expect(result.browserChanged).toBe(true);
    expect(result.deviceChanged).toBe(false);
  });

  test('operating system changed', () => {
    const current = { ...baseline, operatingSystem: 'MacOS' };
    const result = compareSessionContext(baseline, current);
    expect(result.osChanged).toBe(true);
  });

  test('IP changed but country unchanged — ipChanged is false', () => {
    const current = { ...baseline, ip: '203.0.113.42' };
    const result = compareSessionContext(baseline, current);
    // IP changed but country didn't, so no suspicious IP change.
    expect(result.ipChanged).toBe(false);
    expect(result.locationChanged).toBe(false);
  });

  test('IP changed AND country changed — ipChanged is true', () => {
    const current = { ...baseline, ip: '198.51.100.5', country: 'Germany' };
    const result = compareSessionContext(baseline, current);
    expect(result.ipChanged).toBe(true);
    expect(result.locationChanged).toBe(true);
  });

  test('country changed without IP change — locationChanged true', () => {
    // Rare but possible: IP block reassignment.
    const current = { ...baseline, country: 'Canada' };
    const result = compareSessionContext(baseline, current);
    expect(result.locationChanged).toBe(true);
    expect(result.ipChanged).toBe(false);
  });

  test('VPN status changed', () => {
    const current = { ...baseline, vpnDetected: true };
    const result = compareSessionContext(baseline, current);
    expect(result.vpnChanged).toBe(true);
    expect(result.locationChanged).toBe(false);
  });

  test('VPN turned on in different location — multiple flags', () => {
    const current = {
      ...baseline,
      vpnDetected: true,
      country: 'Netherlands',
      ip: '185.220.101.1',
    };
    const result = compareSessionContext(baseline, current);
    expect(result.vpnChanged).toBe(true);
    expect(result.locationChanged).toBe(true);
    expect(result.ipChanged).toBe(true);
  });

  test('multiple changes simultaneously', () => {
    const current = {
      ...baseline,
      device: 'Mobile',
      browser: 'Safari',
      operatingSystem: 'iOS',
      country: 'Japan',
      vpnDetected: true,
    };
    const result = compareSessionContext(baseline, current);
    expect(result.deviceChanged).toBe(true);
    expect(result.browserChanged).toBe(true);
    expect(result.osChanged).toBe(true);
    expect(result.locationChanged).toBe(true);
    expect(result.vpnChanged).toBe(true);
  });

  test('no baseline — all flags false', () => {
    const result = compareSessionContext(null, baseline);
    expect(result.deviceChanged).toBe(false);
    expect(result.browserChanged).toBe(false);
    expect(result.osChanged).toBe(false);
    expect(result.ipChanged).toBe(false);
    expect(result.locationChanged).toBe(false);
    expect(result.vpnChanged).toBe(false);
  });

  test('no current context — all flags false', () => {
    const result = compareSessionContext(baseline, null);
    expect(result.deviceChanged).toBe(false);
    expect(result.browserChanged).toBe(false);
    expect(result.osChanged).toBe(false);
    expect(result.ipChanged).toBe(false);
    expect(result.locationChanged).toBe(false);
    expect(result.vpnChanged).toBe(false);
  });

  test('missing fields in baseline — safe defaults', () => {
    const partialBaseline = { device: 'Desktop' };
    const result = compareSessionContext(partialBaseline, baseline);
    expect(result.deviceChanged).toBe(false);
    // Other fields compare undefined !== actual value, so true.
    expect(result.browserChanged).toBe(true);
    expect(result.osChanged).toBe(true);
  });
});
