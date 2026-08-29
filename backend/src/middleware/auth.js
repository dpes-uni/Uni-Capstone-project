const jwt = require('jsonwebtoken');
const User = require('../models/User');
const {
  getSessionStatus,
} = require('../services/sessionMonitor');

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

module.exports = { protect, authenticateSession };
