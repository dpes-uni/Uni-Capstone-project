const LoginActivity = require('../models/LoginActivity');
const Assessment = require('../models/Assessment');
const User = require('../models/User');
const { getSessionTimeoutInfo, getSessionStatus } = require('../services/sessionMonitor');

// @route GET /api/users/login-activity
async function getLoginActivity(req, res, next) {
  try {
    const activity = await LoginActivity.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    res.json({ activity });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/users/dashboard-summary
async function getDashboardSummary(req, res, next) {
  try {
    const userId = req.user._id;

    const [loginCount, highRiskCount, assessmentCounts, lastLogins] = await Promise.all([
      LoginActivity.countDocuments({ user: userId, success: true }),
      LoginActivity.countDocuments({ user: userId, riskLevel: 'high' }),
      Assessment.aggregate([
        { $match: { owner: userId } },
        { $group: { _id: '$status', count: { $sum: 1 } } },
      ]),
      LoginActivity.find({ user: userId }).sort({ createdAt: -1 }).limit(5),
    ]);

    const assessmentsByStatus = assessmentCounts.reduce((acc, row) => {
      acc[row._id] = row.count;
      return acc;
    }, { pending: 0, in_review: 0, verified: 0, rejected: 0 });

    res.json({
      user: req.user.toSafeObject(),
      stats: {
        totalSuccessfulLogins: loginCount,
        highRiskLogins: highRiskCount,
        trustedDevices: req.user.trustedDevices.length,
        assessmentsByStatus,
      },
      recentActivity: lastLogins,
    });
  } catch (err) {
    next(err);
  }
}

// @route PATCH /api/users/me
async function updateProfile(req, res, next) {
  try {
    const { name, role } = req.body;
    const user = await User.findById(req.user._id);

    if (name) user.name = name;
    if (role && ['student', 'agent', 'institution'].includes(role)) user.role = role;

    await user.save();
    res.json({ message: 'Profile updated', user: user.toSafeObject() });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/users/session-timeout
// Returns the current session timeout/risk status so the frontend can enforce
// high-risk termination and idle timeout warnings.
async function getSessionTimeout(req, res, next) {
  try {
    const timeoutInfo = getSessionTimeoutInfo(req);
    const sessionStatus = getSessionStatus(req);

    res.json({
      idleTimeout: timeoutInfo.idleTimeout,
      highRiskTerminate: timeoutInfo.highRiskTerminate,
      timeUntilExpire: timeoutInfo.timeUntilExpire,
      riskLevel: sessionStatus?.riskLevel || 'low',
      requiresReauthentication: sessionStatus?.requiresReauthentication || false,
    });
  } catch (err) {
    next(err);
  }
}

module.exports = { getLoginActivity, getDashboardSummary, updateProfile, getSessionTimeout };
