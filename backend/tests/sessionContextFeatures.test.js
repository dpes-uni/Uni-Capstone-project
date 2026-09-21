/**
 * Unit tests for sessionContextFeatures.js
 *
 * Tests every feature computation path, including the NOT
 * AVAILABLE features (which must return null, never 0 or a fake value).
 */

jest.mock('../src/models/LoginActivity', () => {
  const sortFn = jest.fn();
  const findOne = jest.fn(() => ({ sort: sortFn }));
  // Make mockResolvedValue configure the sort() chain so
  // LoginActivity.findOne({...}).sort({...}) resolves to the expected value.
  const orig = findOne;
  findOne.mockResolvedValue = function (val) {
    sortFn.mockReturnValue(Promise.resolve(val));
    return orig;
  };
  return {
    countDocuments: jest.fn(),
    findOne,
  };
});

jest.mock('../src/utils/geolocation', () => ({
  haversineDistance: jest.fn(() => 1234.5),
}));

const {
  deviceSeenBefore,
  timeSinceLastLogin,
  userTypicalLoginHour,
  timeSincePreviousSession,
  distanceFromLastLocation,
  numberOfRecentFailedLogins,
  successfulMfaHistory,
  computeSessionContextFeatures,
  RECENT_FAILED_LOGIN_WINDOW_MS,
} = require('../src/utils/sessionContextFeatures');

const LoginActivity = require('../src/models/LoginActivity');
const { haversineDistance } = require('../src/utils/geolocation');

const PAST_NOW = Date.now() - 3 * 60 * 60 * 1000; // 3 hours ago

function makeUser({ lastLoginAt = null, failedLoginAttempts = 0, trustedDevices = [], _id = 'u1' } = {}) {
  return { _id, lastLoginAt, failedLoginAttempts, trustedDevices };
}

describe('device_seen_before', () => {
  test('true when deviceHash matches a trusted device', () => {
    const user = makeUser({
      trustedDevices: [{ deviceHash: 'abc123' }, { deviceHash: 'def456' }],
    });
    expect(deviceSeenBefore(user, 'abc123')).toBe(true);
  });

  test('false when deviceHash is not trusted', () => {
    const user = makeUser({ trustedDevices: [{ deviceHash: 'abc123' }] });
    expect(deviceSeenBefore(user, 'zzz999')).toBe(false);
  });

  test('false when no trusted devices', () => {
    expect(deviceSeenBefore(makeUser(), 'abc123')).toBe(false);
  });

  test('false when user is null/undefined', () => {
    expect(deviceSeenBefore(null, 'abc123')).toBe(false);
    expect(deviceSeenBefore(undefined, 'abc123')).toBe(false);
  });
});

describe('time_since_last_login', () => {
  test('null when user has never logged in', () => {
    expect(timeSinceLastLogin(makeUser())).toBeNull();
  });

  test('null when lastLoginAt is invalid', () => {
    expect(timeSinceLastLogin(makeUser({ lastLoginAt: 'not-a-date' }))).toBeNull();
    expect(timeSinceLastLogin(makeUser({ lastLoginAt: null }))).toBeNull();
  });

  test('returns positive ms when lastLoginAt is set', () => {
    const user = makeUser({ lastLoginAt: new Date(PAST_NOW) });
    const ms = timeSinceLastLogin(user);
    expect(ms).not.toBeNull();
    expect(ms).toBeGreaterThanOrEqual(0);
    expect(ms).toBeGreaterThanOrEqual(3 * 60 * 60 * 1000 - 100); // ~3h with tolerance
  });
});

describe('user_typical_login_hour (NOT AVAILABLE)', () => {
  test('returns null (not a number, not a placeholder)', () => {
    expect(userTypicalLoginHour()).toBeNull();
  });

  test('computeSessionContextFeatures returns null for the field', async () => {
    const user = makeUser();
    LoginActivity.findOne.mockResolvedValue(null);
    LoginActivity.countDocuments.mockResolvedValue(0);
    const features = await computeSessionContextFeatures({ user, deviceHash: 'x' });
    expect(features.user_typical_login_hour).toBeNull();
  });
});

describe('time_since_previous_session (NOT AVAILABLE)', () => {
  test('returns null (not a number, not a placeholder)', () => {
    expect(timeSincePreviousSession()).toBeNull();
  });

  test('computeSessionContextFeatures returns null for the field', async () => {
    const user = makeUser();
    LoginActivity.findOne.mockResolvedValue(null);
    LoginActivity.countDocuments.mockResolvedValue(0);
    const features = await computeSessionContextFeatures({ user, deviceHash: 'x' });
    expect(features.time_since_previous_session).toBeNull();
  });
});

describe('distance_from_last_location', () => {
  test('returns distance in km when both positions have coordinates', () => {
    haversineDistance.mockReturnValue(42.7);
    const previous = { latitude: -33.8688, longitude: 151.2093 };
    const current = { latitude: -37.8136, longitude: 144.9631 };
    expect(distanceFromLastLocation(previous, current)).toBe(42.7);
    expect(haversineDistance).toHaveBeenCalledWith(-33.8688, 151.2093, -37.8136, 144.9631);
  });

  test('returns null when no previous login', () => {
    expect(distanceFromLastLocation(null, { latitude: 1, longitude: 2 })).toBeNull();
  });

  test('returns null when currentGeo is missing', () => {
    const previous = { latitude: 1, longitude: 2 };
    expect(distanceFromLastLocation(previous, null)).toBeNull();
    expect(distanceFromLastLocation(previous, undefined)).toBeNull();
  });

  test('returns null when either coordinate is null', () => {
    expect(distanceFromLastLocation({ latitude: null, longitude: 2 }, { latitude: 1, longitude: 2 })).toBeNull();
    expect(distanceFromLastLocation({ latitude: 1, longitude: 2 }, { latitude: null, longitude: 2 })).toBeNull();
    expect(distanceFromLastLocation({ latitude: 1, longitude: null }, { latitude: 1, longitude: 2 })).toBeNull();
    expect(distanceFromLastLocation({ latitude: 1, longitude: 2 }, { latitude: 1, longitude: null })).toBeNull();
  });
});

describe('number_of_recent_failed_logins', () => {
  afterEach(() => {
    LoginActivity.countDocuments.mockClear();
  });

  test('uses counter when counter is higher than DB count', async () => {
    LoginActivity.countDocuments.mockResolvedValue(2);
    const user = makeUser({ failedLoginAttempts: 5 });
    expect(await numberOfRecentFailedLogins(user)).toBe(5);
  });

  test('uses DB count when it is higher than counter', async () => {
    LoginActivity.countDocuments.mockResolvedValue(7);
    const user = makeUser({ failedLoginAttempts: 2 });
    expect(await numberOfRecentFailedLogins(user)).toBe(7);
  });

  test('returns 0 when user is null/undefined', async () => {
    expect(await numberOfRecentFailedLogins(null)).toBe(0);
    expect(await numberOfRecentFailedLogins(undefined)).toBe(0);
  });

  test('queries LoginActivity with 24h cutoff', async () => {
    LoginActivity.countDocuments.mockResolvedValue(0);
    const user = makeUser();
    await numberOfRecentFailedLogins(user);
    const [filter] = LoginActivity.countDocuments.mock.calls[0];
    expect(filter.user).toBe(user._id);
    expect(filter.success).toBe(false);
    expect(filter.createdAt.$gte).not.toBeUndefined();
  });
});

describe('successful_mfa_history', () => {
  test('counts MFA-verified successful logins', async () => {
    LoginActivity.countDocuments.mockResolvedValue(42);
    const user = makeUser();
    expect(await successfulMfaHistory(user)).toBe(42);
    expect(LoginActivity.countDocuments).toHaveBeenCalledWith({
      user: user._id,
      mfaVerified: true,
      success: true,
    });
  });

  test('returns 0 when user is null/undefined', async () => {
    expect(await successfulMfaHistory(null)).toBe(0);
    expect(await successfulMfaHistory(undefined)).toBe(0);
  });
});

describe('computeSessionContextFeatures (all seven fields)', () => {
  afterEach(() => {
    LoginActivity.countDocuments.mockClear();
    LoginActivity.findOne.mockClear();
  });

  test('returns exactly seven keys', async () => {
    LoginActivity.countDocuments.mockResolvedValue(0);
    LoginActivity.findOne.mockResolvedValue(null);
    const user = makeUser({ lastLoginAt: new Date(PAST_NOW), failedLoginAttempts: 0 });
    const result = await computeSessionContextFeatures({ user, deviceHash: 'abc' });
    expect(Object.keys(result)).toEqual([
      'device_seen_before',
      'time_since_last_login',
      'user_typical_login_hour',
      'time_since_previous_session',
      'distance_from_last_location',
      'number_of_recent_failed_logins',
      'successful_mfa_history',
    ]);
  });

  test('device_seen_before reflects trustedDevices', async () => {
    LoginActivity.countDocuments.mockResolvedValue(0);
    LoginActivity.findOne.mockResolvedValue(null);
    const user = makeUser({ trustedDevices: [{ deviceHash: 'abc' }], failedLoginAttempts: 0 });
    const result = await computeSessionContextFeatures({ user, deviceHash: 'abc' });
    expect(result.device_seen_before).toBe(true);
  });

  test('unavailable features are null NOT zero', async () => {
    LoginActivity.countDocuments.mockResolvedValue(0);
    LoginActivity.findOne.mockResolvedValue(null);
    const user = makeUser({ lastLoginAt: new Date(PAST_NOW), failedLoginAttempts: 0 });
    const result = await computeSessionContextFeatures({ user, deviceHash: 'abc' });
    expect(result.user_typical_login_hour).toBeNull();
    expect(result.time_since_previous_session).toBeNull();
    // Never a fake-looking number like 0 or 12 for unavailable features.
    expect(result.user_typical_login_hour).not.toBe(0);
    expect(result.time_since_previous_session).not.toBe(0);
  });
});

describe('RECENT_FAILED_LOGIN_WINDOW_MS', () => {
  test('is a positive duration', () => {
    expect(RECENT_FAILED_LOGIN_WINDOW_MS).toBe(24 * 60 * 60 * 1000);
    expect(typeof RECENT_FAILED_LOGIN_WINDOW_MS).toBe('number');
    expect(RECENT_FAILED_LOGIN_WINDOW_MS).toBeGreaterThan(0);
  });
});
