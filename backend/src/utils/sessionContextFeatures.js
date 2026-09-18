/**
 * sessionContextFeatures.js
 *
 * Session / login context feature engineering.
 *
 * Computes the seven requested session-login context features from data
 * that ALREADY exists in the application:
 *
 *   1. device_seen_before         -> User.trustedDevices[].deviceHash
 *   2. time_since_last_login      -> User.lastLoginAt (set on every successful MFA)
 *   3. distance_from_last_location -> last successful LoginActivity lat/lon vs
 *                                    current geolocation (haversine)
 *   4. number_of_recent_failed_logins -> User.failedLoginAttempts + recent
 *                                    LoginActivity(success=false) records
 *   5. successful_mfa_history     -> count of LoginActivity records with
 *                                    mfaVerified=true && success=true
 *
 * Two features are NOT available in the current system and are returned as
 * `null` (NOT zero, NOT a fabricated value) so the risk engine can treat
 * them as genuinely unknown:
 *
 *   6. user_typical_login_hour    -> no per-user "typical hour" is stored or
 *                                    computed anywhere; login_hour only exists
 *                                    transiently inside the Python AI payload.
 *   7. time_since_previous_session -> sessions are held in-memory only and
 *                                    have no persisted start/end timestamps, so
 *                                    the gap between sessions cannot be derived.
 *
 * Every feature here is derived from real application state. No random or
 * placeholder values are ever generated.
 */

const LoginActivity = require('../models/LoginActivity');
const { haversineDistance } = require('./geolocation');

// Window used for "recent" failed-login counting. Keep it short and explicit.
const RECENT_FAILED_LOGIN_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Whether the device fingerprint is already known for this user.
 *
 * Source: User.trustedDevices[].deviceHash, which is populated in
 * authController.verifyMfa() after a successful OTP verification.
 *
 * @param {import('mongoose').Document} user
 * @param {string} deviceHash
 * @returns {boolean}
 */
function deviceSeenBefore(user, deviceHash) {
  const trustedDevices = Array.isArray(user?.trustedDevices) ? user.trustedDevices : [];
  return trustedDevices.some((entry) => entry && entry.deviceHash === deviceHash);
}

/**
 * Milliseconds elapsed since the user's most recent successful login.
 *
 * Source: User.lastLoginAt, which is written in authController.verifyMfa()
 * at the moment a new authenticated session is issued. Returns null when the
 * user has never completed a successful login.
 *
 * @param {import('mongoose').Document} user
 * @returns {number|null}
 */
function timeSinceLastLogin(user) {
  if (!user?.lastLoginAt) {
    return null;
  }
  const lastLoginAt = new Date(user.lastLoginAt).getTime();
  if (Number.isNaN(lastLoginAt)) {
    return null;
  }
  return Math.max(0, Date.now() - lastLoginAt);
}

/**
 * Distance in kilometres between the user's last known login location and
 * the current location.
 *
 * Source: LoginActivity.latitude/longitude from the most recent successful,
 * MFA-verified login, compared with the current geolocation via the existing
 * haversine helper in geolocation.js.
 *
 * Returns null when either side has no usable coordinates (no history,
 * geolocation unavailable, or coordinates missing).
 *
 * @param {import('mongoose').Document|null} previousLogin
 * @param {{latitude?:number|null, longitude?:number|null}} currentGeo
 * @returns {number|null}
 */
function distanceFromLastLocation(previousLogin, currentGeo = {}) {
  if (!previousLogin || !currentGeo) {
    return null;
  }
  const prevLat = previousLogin.latitude;
  const prevLon = previousLogin.longitude;
  const currLat = currentGeo.latitude;
  const currLon = currentGeo.longitude;
  if (
    prevLat === null ||
    prevLat === undefined ||
    prevLon === null ||
    prevLon === undefined ||
    currLat === null ||
    currLat === undefined ||
    currLon === null ||
    currLon === undefined
  ) {
    return null;
  }
  return haversineDistance(prevLat, prevLon, currLat, currLon);
}

/**
 * Count of failed login attempts in the recent window.
 *
 * Source: User.failedLoginAttempts (live counter, reset to 0 on every
 * successful login) AND LoginActivity records with success=false in the last
 * 24 hours. The higher of the two is returned so the value stays useful even
 * if one source is stale or incomplete.
 *
 * @param {import('mongoose').Document} user
 * @returns {Promise<number>}
 */
async function numberOfRecentFailedLogins(user) {
  if (!user?._id) {
    return 0;
  }
  const cutoff = Date.now() - RECENT_FAILED_LOGIN_WINDOW_MS;
  const recentFailures = await LoginActivity.countDocuments({
    user: user._id,
    success: false,
    createdAt: { $gte: cutoff },
  });
  const counter = Number(user.failedLoginAttempts) || 0;
  return Math.max(counter, recentFailures);
}

/**
 * Count of successful MFA verifications for the user.
 *
 * Source: LoginActivity records where mfaVerified=true AND success=true.
 * Both flags are written in authController.verifyMfa() only after the OTP is
 * correct and a session has been issued.
 *
 * @param {import('mongoose').Document} user
 * @returns {Promise<number>}
 */
async function successfulMfaHistory(user) {
  if (!user?._id) {
    return 0;
  }
  return LoginActivity.countDocuments({
    user: user._id,
    mfaVerified: true,
    success: true,
  });
}

/**
 * The user's typical login hour.
 *
 * NOT AVAILABLE in the current system. The application never stores a
 * per-user "typical hour": login_hour is computed transiently inside
 * aiService.buildLoginAttempt() from Date.now() and is never persisted, so a
 * historical typical value cannot be derived from real application data.
 *
 * @returns {null}
 */
function userTypicalLoginHour() {
  return null;
}

/**
 * Time since the previous session.
 *
 * NOT AVAILABLE in the current system. Sessions live only in the in-memory
 * sessionMonitor Map and are never persisted with start/end timestamps, so the
 * gap between consecutive sessions cannot be computed from real data.
 *
 * @returns {null}
 */
function timeSincePreviousSession() {
  return null;
}

/**
 * Fetch the user's most recent successful, MFA-verified login record.
 *
 * Used as the "previous location" for distance_from_last_location.
 *
 * @param {import('mongoose').Document} user
 * @returns {Promise<import('mongoose').Document|null>}
 */
async function getPreviousSuccessfulLogin(user) {
  if (!user?._id) {
    return null;
  }
  return LoginActivity.findOne({
    user: user._id,
    success: true,
    mfaVerified: true,
  }).sort({ createdAt: -1 });
}

/**
 * Compute all seven session-login context features for a login attempt.
 *
 * @param {object} opts
 * @param {import('mongoose').Document} opts.user
 * @param {string} opts.deviceHash
 * @param {{latitude?:number|null, longitude?:number|null}} opts.currentGeo
 * @returns {Promise<object>}
 */
async function computeSessionContextFeatures({
  user,
  deviceHash,
  currentGeo = {},
}) {
  const previousLogin = await getPreviousSuccessfulLogin(user);
  return {
    device_seen_before: deviceSeenBefore(user, deviceHash),
    time_since_last_login: timeSinceLastLogin(user),
    user_typical_login_hour: userTypicalLoginHour(),
    time_since_previous_session: timeSincePreviousSession(),
    distance_from_last_location: distanceFromLastLocation(previousLogin, currentGeo),
    number_of_recent_failed_logins: await numberOfRecentFailedLogins(user),
    successful_mfa_history: await successfulMfaHistory(user),
  };
}

module.exports = {
  deviceSeenBefore,
  timeSinceLastLogin,
  userTypicalLoginHour,
  timeSincePreviousSession,
  distanceFromLastLocation,
  numberOfRecentFailedLogins,
  successfulMfaHistory,
  getPreviousSuccessfulLogin,
  computeSessionContextFeatures,
  RECENT_FAILED_LOGIN_WINDOW_MS,
};
