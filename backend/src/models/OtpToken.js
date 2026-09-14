const mongoose = require('mongoose');

const otpTokenSchema = new mongoose.Schema(
  {
    // Login MFA uses an existing user; admin signup creates the user only
    // after the email OTP has been successfully verified.
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, default: null },
    loginActivity: { type: mongoose.Schema.Types.ObjectId, ref: 'LoginActivity', default: null },
    email: { type: String, lowercase: true, trim: true, index: true },
    name: { type: String, trim: true, maxlength: 100 },
    role: { type: String, enum: ['student', 'agent', 'institution'], default: 'student' },
    passwordHash: { type: String, select: false },
    codeHash: { type: String, required: true },
    purpose: { type: String, enum: ['login_mfa', 'reauth', 'signup', 'admin_signup', 'stepup'], default: 'login_mfa' },
    adminOnly: { type: Boolean, default: false },
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
