const mongoose = require('mongoose');

const loginActivitySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    ip: { type: String },
    userAgent: { type: String },
    deviceHash: { type: String },
    isNewDevice: { type: Boolean, default: false },
    isNewIp: { type: Boolean, default: false },

    // ---------------------------------------------------------------
    // Session context features — login-decision snapshot.
    // Persisted at initial login (pre-MFA) and NOT recomputed after
    // successful MFA, so this record retains the state that drove the
    // login-decision snapshot. See authController.login().
    // deviceSeenBefore, timeSinceLastLoginMs, distanceFromLastKm,
    // recentFailedLoginsCount, successfulMfaHistoryCount — all null
    // unless explicitly populated by authController before save.
    // ---------------------------------------------------------------
    deviceSeenBefore: { type: Boolean, default: null },
    timeSinceLastLoginMs: { type: Number, default: null },
    distanceFromLastKm: { type: Number, default: null },
    recentFailedLoginsCount: { type: Number, default: null },
    successfulMfaHistoryCount: { type: Number, default: null },

    // Geolocation of the attempt, used for impossible-travel detection.
    country: { type: String, default: 'Unknown' },
    city: { type: String, default: 'Unknown' },
    latitude: { type: Number, default: null },
    longitude: { type: Number, default: null },

    riskScore: { type: Number, default: 0 },
    riskLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'low' },
    riskReasons: { type: [String], default: [] },

    // ---------------------------------------------------------------
    // Individual risk components that drove the combined final risk.
    // ruleRisk* is always populated from scoreLogin().
    // aiRisk* is populated only when the Python AI service responded;
    // null when the AI was genuinely unavailable.
    // riskScore/riskLevel above remain the combined final values.
    // ---------------------------------------------------------------
    ruleRiskScore: { type: Number, default: null },
    ruleRiskLevel: { type: String, enum: ['low', 'medium', 'high', null], default: null },
    aiRiskScore: { type: Number, default: null },
    aiRiskLevel: { type: String, enum: ['low', 'medium', 'high', null], default: null },

    mfaRequired: { type: Boolean, default: false },
    mfaVerified: { type: Boolean, default: false },

    success: { type: Boolean, default: false },
    failureReason: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model('LoginActivity', loginActivitySchema);
