const mongoose = require('mongoose');

const otpTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    loginActivity: { type: mongoose.Schema.Types.ObjectId, ref: 'LoginActivity', required: true },
    codeHash: { type: String, required: true },
    purpose: { type: String, enum: ['login_mfa'], default: 'login_mfa' },
    attempts: { type: Number, default: 0 },
    maxAttempts: { type: Number, default: 5 },
    consumed: { type: Boolean, default: false },
    expiresAt: { type: Date, required: true },
    deviceHash: { type: String },
    ip: { type: String },
    userAgent: { type: String },
  },
  { timestamps: true }
);

otpTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('OtpToken', otpTokenSchema);
