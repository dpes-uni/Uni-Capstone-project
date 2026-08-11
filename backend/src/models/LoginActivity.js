const mongoose = require('mongoose');

const loginActivitySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    ip: { type: String },
    userAgent: { type: String },
    deviceHash: { type: String },
    isNewDevice: { type: Boolean, default: false },
    isNewIp: { type: Boolean, default: false },

    riskScore: { type: Number, default: 0 },
    riskLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'low' },
    riskReasons: { type: [String], default: [] },

    mfaRequired: { type: Boolean, default: false },
    mfaVerified: { type: Boolean, default: false },

    success: { type: Boolean, default: false },
    failureReason: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model('LoginActivity', loginActivitySchema);
