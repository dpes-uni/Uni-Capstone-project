const express = require('express');
const { protect } = require('../middleware/auth');
const {
  getSessionStatus,
  sessions,
} = require('../services/sessionMonitor');
const logger = require('../utils/logger');

const router = express.Router();

// POST /api/debug/trigger-session-risk
// Manually flags the current user's session as high-risk for demo/testing.
// Only available in development mode.
router.post('/trigger-session-risk', protect, (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: 'Debug endpoints are disabled in production' });
  }

  const key = req.user._id ? `user:${req.user._id}` : null;

  if (!key) {
    return res.status(400).json({ message: 'Could not identify session' });
  }

  let session = sessions.get(key);

  if (!session) {
    // Create a minimal session entry so the flag exists even if the monitor
    // hasn't tracked any events yet.
    session = {
      userId: key,
      username: req.user.email,
      userRole: req.user.role,
      startedAt: Date.now(),
      lastActivity: Date.now(),
      documentsViewed: 0,
      documentsDownloaded: 0,
      documentsUploaded: 0,
      verificationActions: 0,
      failedActions: 0,
      actionTimestamps: [],
      requiresReauthentication: false,
      lastRiskResult: null,
      lastRiskCheckedAt: null,
      riskDecision: 'unknown',
      riskLevel: 'low',
    };
    sessions.set(key, session);
  }

  // Flag the session as high-risk — same as what the AI does when it returns
  // risk_level: HIGH with recommended_action: "Require Additional Verification".
  session.requiresReauthentication = true;
  session.lastRiskCheckedAt = Date.now();
  session.riskLevel = 'high';
  session.recommendedAction = 'Require Additional Verification';
  session.riskDecision = 'reauth_required';
  session.lastRiskResult = {
    risk_score: 85,
    risk_level: 'high',
    recommended_action: 'Require Additional Verification',
    reason: '[DEBUG] Manual risk trigger for testing/demonstration',
  };

  logger.warn('Debug: Session manually flagged as high-risk', {
    user: req.user.email,
  });

  return res.json({
    message: 'Session flagged as high-risk. The termination popup will appear on the next API call.',
  });
});

module.exports = router;
