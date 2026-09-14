/**
 * SecurityEvent model — structured audit trail for security-relevant session events.
 *
 * Purpose: security auditing, explainability, troubleshooting, capstone evidence.
 *
 * NEVER store: passwords, OTP values, JWT tokens, refresh tokens, secrets.
 */

const mongoose = require('mongoose');

const EVENT_TYPES = [
  'CONTEXT_CHANGE',
  'RISK_THRESHOLD_REACHED',
  'REAUTH_REQUIRED',
  'REAUTH_SUCCESS',
];

const securityEventSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },

    eventType: {
      type: String,
      enum: EVENT_TYPES,
      required: true,
      index: true,
    },

    riskScore: { type: Number, default: null },
    riskLevel: { type: String, default: null },

    recommendedAction: { type: String, default: null },

    reason: { type: String, default: null },

    accumulatedRisk: { type: Number, default: null },

    contextChanges: {
      deviceChanged: { type: Boolean, default: false },
      browserChanged: { type: Boolean, default: false },
      osChanged: { type: Boolean, default: false },
      ipChanged: { type: Boolean, default: false },
      locationChanged: { type: Boolean, default: false },
      vpnChanged: { type: Boolean, default: false },
    },

    ip: { type: String, default: null },
    userAgent: { type: String, default: null },
  },
  { timestamps: true }
);

securityEventSchema.index({ createdAt: -1 });
securityEventSchema.index({ user: 1, eventType: 1 });

module.exports = mongoose.model('SecurityEvent', securityEventSchema);
