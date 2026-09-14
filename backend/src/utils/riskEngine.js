/**
 * Rule-based login risk engine.
 *
 * Mirrors the "RiskCalculator" component described in /ai/docs/AI_ARCHITECTURE.md:
 * it inspects a login attempt against what is already known about the user
 * (trusted devices, recent failures) and produces a 0-100 risk score plus a
 * human-readable list of reasons. The Node backend uses this score to decide
 * whether a login can proceed immediately (low risk), needs a one-time
 * passcode (medium risk), or should be treated as high risk.
 *
 * The AI module in /ai (Python + scikit-learn) implements the same idea with
 * a trained ML model. This JS engine keeps the MERN backend fully
 * self-contained so it runs without a Python runtime; swapping in the ML
 * service later just means calling it instead of / alongside this function.
 */

function scoreLogin({ user, deviceHash, ip, isNewDevice, isNewIp, recentFailedAttempts }) {
  let score = 0;
  const reasons = [];

  if (isNewDevice) {
    score += 40;
    reasons.push('Login from a device that has not been seen before');
  }

  if (isNewIp) {
    score += 25;
    reasons.push('Login from a new or unrecognized IP address');
  }

  if (recentFailedAttempts >= 3) {
    score += 25;
    reasons.push(`${recentFailedAttempts} failed login attempts recently`);
  } else if (recentFailedAttempts > 0) {
    score += 10;
    reasons.push(`${recentFailedAttempts} recent failed login attempt(s)`);
  }

  if (user.trustedDevices.length === 0) {
    // First ever login is inherently a bit riskier to fingerprint, but we
    // don't want to punish brand-new accounts too harshly.
    score += 5;
  }

  score = Math.max(0, Math.min(100, score));

  const mediumThreshold = Number(process.env.RISK_MEDIUM_THRESHOLD || 30);
  const highThreshold = Number(process.env.RISK_HIGH_THRESHOLD || 70);

  let level = 'low';
  if (score >= highThreshold) level = 'high';
  else if (score >= mediumThreshold) level = 'medium';

  if (reasons.length === 0) {
    reasons.push('Recognized device and IP, no recent failures');
  }

  return { score, level, reasons, mfaRequired: level !== 'low' };
}

module.exports = { scoreLogin };
