const jwt = require('jsonwebtoken');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const {
  getSessionStatus,
  consumeStepUpVerification,
  clearStepUpVerification,
  isSessionReauthenticationRequired,
  getSessionTimeoutInfo,
  clearSessionByUserId,
} = require('../services/sessionMonitor');
const logger = require('../utils/logger');

function getRequestToken(req) {
  const authHeader = req?.headers?.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  if (req?.cookies?.token) {
    return req.cookies.token;
  }

  return null;
}

async function authenticateUser(req) {
  const token = getRequestToken(req);

  if (!token) {
    const error = new Error('Not authorized, no token provided');
    error.statusCode = 401;
    throw error;
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await User.findById(decoded.sub);

  if (!user) {
    const error = new Error('Not authorized, user no longer exists');
    error.statusCode = 401;
    throw error;
  }

  return user;
}

async function authenticateSession(req, res, next) {
  try {
    req.user = await authenticateUser(req);
    next();
  } catch (err) {
    return res.status(err.statusCode || 401).json({
      message: err.message || 'Not authorized, invalid or expired token',
    });
  }
}

async function protect(req, res, next) {
  try {
    req.user = await authenticateUser(req);

    const sessionStatus = getSessionStatus(req);

    if (sessionStatus?.requiresReauthentication) {
      const sessionTimeout = getSessionTimeoutInfo(req);

      // 10-minute re-authentication window expired without successful
      // re-authentication — enforce the existing session security consequence.
      // Revoke the refresh token server-side so even the /auth/refresh
      // endpoint cannot extend the session.
      if (sessionTimeout?.highRiskTerminate) {
        logger.warn('Session force-terminated: 10-minute re-authentication window expired', {
          user: req.user.email,
        });

        await RefreshToken.updateMany(
          { user: req.user._id, revoked: false },
          { $set: { revoked: true, revokedAt: new Date() } }
        );

        clearSessionByUserId(req.user._id);

        return res.status(401).json({
          message: 'Session terminated due to suspicious activity',
          sessionTerminated: true,
        });
      }

      return res.status(403).json({
        message: 'Session requires re-authentication',
        reauthenticationRequired: true,
        risk: sessionStatus.lastRiskResult
          ? {
              risk_score: sessionStatus.lastRiskResult.risk_score,
              risk_level: sessionStatus.lastRiskResult.risk_level,
              recommended_action: sessionStatus.lastRiskResult.recommended_action,
              reason: sessionStatus.lastRiskResult.reason,
            }
          : null,
      });
    }

    next();
  } catch (err) {
    return res.status(err.statusCode || 401).json({
      message: err.message || 'Not authorized, invalid or expired token',
    });
  }
}

// Middleware for sensitive actions that require step-up OTP verification.
//
// Runs AFTER `protect` (or any middleware that attaches req.user).
// Enforces that a valid step-up OTP has been verified for this session,
// regardless of whether the session risk is elevated.
//
// Returns 403 with:
//   { reauthenticationRequired: true }  — risk-based reauth is pending; use that flow
//   { stepUpRequired: true }          — step-up OTP needed
//   { stepUpRequired: true, expired: true } — step-up existed but expired
//
// On success, consumes the step-up verification immediately so the same
// verification cannot be replayed.
function stepUpProtect(req, res, next) {
  // Risk-based re-authentication takes precedence.
  if (isSessionReauthenticationRequired(req)) {
    return res.status(403).json({
      message: 'Session requires re-authentication.',
      reauthenticationRequired: true,
      stepUpRequired: false,
    });
  }

  const sessionStatus = getSessionStatus(req);

  if (!sessionStatus?.stepUpVerified) {
    return res.status(403).json({
      message: 'Additional verification required for this action.',
      stepUpRequired: true,
      reauthenticationRequired: false,
    });
  }

  const expiresAt = new Date(sessionStatus.stepUpVerified.expiresAt).getTime();
  if (expiresAt <= Date.now()) {
    // Expired — clear it so the next request triggers a fresh OTP challenge.
    clearStepUpVerification(req);
    return res.status(403).json({
      message: 'Step-up verification has expired. Please verify again.',
      stepUpRequired: true,
      reauthenticationRequired: false,
      expired: true,
    });
  }

  // Valid, unexpired step-up verification. Consume it before allowing the action
  // so that each sensitive operation requires its own fresh OTP.
  consumeStepUpVerification(req);
  return next();
}

module.exports = { protect, authenticateSession, stepUpProtect };
