const path = require('path');
const fs = require('fs');
const User = require('../models/User');
const LoginActivity = require('../models/LoginActivity');
const Assessment = require('../models/Assessment');
const { UPLOAD_DIR } = require('../middleware/upload');
const { getSessionTimeoutInfo } = require('../services/sessionMonitor');

async function getSessionStatus(req, res, next) {
  try {
    const sessionMonitor = require('../services/sessionMonitor');

    // The admin dashboard monitors the latest active non-admin session.
    // The administrator's own session is not the session being evaluated.
    const monitoredSessions = Array.from(sessionMonitor.sessions.values())
      .filter((candidate) => candidate.userRole !== 'admin')
      .sort((a, b) => new Date(b.startedAt || 0).getTime() - new Date(a.startedAt || 0).getTime());

    const session = monitoredSessions[0] || null;

    if (!session) {
      return res.json({ active: false });
    }

    // Reuse the existing timeout calculation against the monitored user's
    // session rather than the administrator's request session.
    const monitoredRequest = {
      ...req,
      user: { _id: session.userId },
    };
    const timeoutInfo = getSessionTimeoutInfo(monitoredRequest);

    res.json({
      active: true,
      user: {
        username: session.username || null,
        role: session.userRole || null,
      },
      startedAt: session.startedAt || null,
      sessionStatus: {
        active: true,
        requiresReauthentication: session.requiresReauthentication || false,
        riskDecision: session.riskDecision || 'unknown',
        recommendedAction: session.recommendedAction || null,
      },
      aiRisk: {
        score: session.lastRiskResult?.risk_score ?? null,
        level: session.lastRiskResult?.risk_level || session.riskLevel || null,
      },
      accumulatedRisk: session.accumulatedRisk ?? 0,
      effectiveRiskLevel: session.riskLevel || 'low',
      timeout: {
        idleTimeout: timeoutInfo.idleTimeout,
        highRiskTerminate: timeoutInfo.highRiskTerminate,
        timeUntilExpire: timeoutInfo.timeUntilExpire,
      },
      baseline: session.securityBaseline || null,
      sessionContext: null,
      contextChanges: null,
      activity: {
        documentsViewed: session.documentsViewed || 0,
        documentsDownloaded: session.documentsDownloaded || 0,
        documentsUploaded: session.documentsUploaded || 0,
        verificationActions: session.verificationActions || 0,
        failedActions: session.failedActions || 0,
        rapidActions: session.actionTimestamps?.length >= 5 || false,
      },
    });
  } catch (err) {
    next(err);
  }
}

async function getOverview(req, res, next) {
  try {
    const [users, recentActivity, counts] = await Promise.all([
      User.find({}).select('name email role isVerified lastLoginAt createdAt').sort({ createdAt: -1 }).limit(100),
      LoginActivity.find({}).populate('user', 'name email role').sort({ createdAt: -1 }).limit(25),
      User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]),
    ]);

    const byRole = counts.reduce((acc, row) => {
      acc[row._id] = row.count;
      return acc;
    }, {});

    res.json({
      stats: {
        totalUsers: users.length,
        admins: byRole.admin || 0,
        clients: (byRole.student || 0) + (byRole.agent || 0) + (byRole.institution || 0),
        verified: users.filter((u) => u.isVerified).length,
      },
      users,
      recentActivity,
    });
  } catch (err) {
    next(err);
  }
}

async function updateUserRole(req, res, next) {
  try {
    const { role } = req.body;
    if (!['admin', 'student', 'agent', 'institution'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role.' });
    }
    if (String(req.user._id) === String(req.params.id) && role !== 'admin') {
      return res.status(400).json({ message: 'You cannot remove your own admin role.' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true, runValidators: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'User role updated.', user: user.toSafeObject() });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/admin/assessments
// Admin-only: list assessments from every user (not owner-scoped), with the
// submitting user's name/email/role attached, so admins can see who each
// document belongs to.
async function listAssessments(req, res, next) {
  try {
    const { status } = req.query;
    const filter = {};
    if (status) filter.status = status;

    const assessments = await Assessment.find(filter)
      .populate('owner', 'name email role')
      .sort({ createdAt: -1 });

    res.json({ assessments });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/admin/assessments/:id/document
// Admin-only: view/download any user's uploaded document for verification.
async function getAssessmentDocument(req, res, next) {
  try {
    const assessment = await Assessment.findById(req.params.id);
    if (!assessment || !assessment.documentFile || !assessment.documentFile.storedName) {
      return res.status(404).json({ message: 'Document not found' });
    }

    const filePath = path.join(UPLOAD_DIR, assessment.documentFile.storedName);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'Document file missing on server' });
    }

    res.setHeader('Content-Type', assessment.documentFile.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${assessment.documentFile.originalName}"`);
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    next(err);
  }
}

// @route PATCH /api/admin/assessments/:id/review
// Admin-only: verify or reject a submitted document.
async function reviewAssessment(req, res, next) {
  try {
    const { status, notes } = req.body;
    const assessment = await Assessment.findById(req.params.id);
    if (!assessment) return res.status(404).json({ message: 'Assessment not found' });

    if (!assessment.documentFile || !assessment.documentFile.storedName) {
      return res.status(400).json({ message: 'This assessment has no uploaded document to review yet.' });
    }

    assessment.status = status;
    if (notes !== undefined) assessment.notes = notes;
    assessment.reviewedBy = req.user._id;
    assessment.reviewedAt = new Date();

    await assessment.save();
    res.json({ message: 'Assessment reviewed', assessment });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getOverview,
  getSessionStatus,
  updateUserRole,
  listAssessments,
  getAssessmentDocument,
  reviewAssessment,
};
