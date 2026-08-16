const bcrypt = require('bcryptjs');
const User = require('../models/User');
const LoginActivity = require('../models/LoginActivity');
const OtpToken = require('../models/OtpToken');
const { scoreLogin } = require('../utils/riskEngine');
const { sendEmail } = require('../utils/sendEmail');
const { generateOtp, hashOtp } = require('../utils/otp');
const {
  generateAuthToken,
  generateRandomToken,
  hashToken,
  deviceFingerprint,
  getClientIp,
} = require('../utils/generateToken');

const COOKIE_NAME = 'token';

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

// @route POST /api/auth/register
// Creates a pending signup and ALWAYS sends a 6-digit OTP to the signup email.
// The User document is created only after the OTP is verified.
async function register(req, res, next) {
  try {
    const { name, email, password, role } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();

    if (!name || !normalizedEmail || !password) {
      return res.status(400).json({ message: 'Name, email and password are required.' });
    }

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({ message: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const code = generateOtp();

    // Invalidate any previous unfinished signup OTPs for this email.
    await OtpToken.updateMany(
      { email: normalizedEmail, purpose: 'signup', consumed: false },
      { $set: { consumed: true } }
    );

    const otpDoc = await OtpToken.create({
      email: normalizedEmail,
      name,
      role: ['student', 'agent', 'institution'].includes(role) ? role : 'student',
      passwordHash,
      purpose: 'signup',
      codeHash: hashOtp(code),
      expiresAt: new Date(Date.now() + Number(process.env.OTP_EXPIRES_MINUTES || 10) * 60000),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || 'unknown',
    });

    const { delivered } = await sendEmail({
      to: normalizedEmail,
      subject: 'Your Assure Docs signup verification code',
      text: `Your Assure Docs signup OTP is ${code}. It expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes.`,
      html: `<div style="font-family:Arial,sans-serif"><h2>Assure Docs Signup</h2><p>Your verification code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes.</p><p>If you did not request this account, ignore this email.</p></div>`,
    });

    return res.status(201).json({
      message: delivered
        ? 'A verification code has been sent to your email. Enter it to finish creating your account.'
        : 'SMTP is not configured. In development, the OTP is available below.',
      signupId: otpDoc._id,
      email: normalizedEmail,

    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/register/verify
// Creates the normal user account only after the email OTP is correct.
async function verifySignup(req, res, next) {
  try {
    const { signupId, code } = req.body;
    const otpDoc = await OtpToken.findOne({
      _id: signupId,
      purpose: 'signup',
      consumed: false,
    }).select('+passwordHash');

    if (!otpDoc || otpDoc.expiresAt < new Date()) {
      return res.status(400).json({ message: 'This OTP is invalid or has expired. Please sign up again.' });
    }

    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      return res.status(429).json({ message: 'Too many incorrect attempts. Please sign up again.' });
    }

    if (hashOtp(String(code || '')) !== otpDoc.codeHash) {
      otpDoc.attempts += 1;
      await otpDoc.save();
      return res.status(400).json({ message: 'Incorrect OTP. Please try again.' });
    }

    const existing = await User.findOne({ email: otpDoc.email });
    if (existing) {
      otpDoc.consumed = true;
      await otpDoc.save();
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const user = await User.create({
      name: otpDoc.name,
      email: otpDoc.email,
      passwordHash: otpDoc.passwordHash,
      role: otpDoc.role || 'student',
      isVerified: true,
    });

    otpDoc.user = user._id;
    otpDoc.consumed = true;
    await otpDoc.save();

    return res.status(201).json({
      message: 'Account created and email verified successfully. You can now sign in.',
      user: user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/auth/verify-email/:token
async function verifyEmail(req, res, next) {
  try {
    const { token } = req.params;
    const hashed = hashToken(token);

    const user = await User.findOne({
      verificationToken: hashed,
      verificationTokenExpires: { $gt: Date.now() },
    }).select('+verificationToken +verificationTokenExpires');

    if (!user) {
      return res.status(400).json({ message: 'Verification link is invalid or has expired' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    return res.json({ message: 'Email verified successfully. You can now sign in.' });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/resend-verification
async function resendVerification(req, res, next) {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: (email || '').toLowerCase() });

    // Avoid leaking whether an account exists
    const genericMessage = { message: 'If that account exists and is unverified, a new link has been sent.' };

    if (!user || user.isVerified) {
      return res.json(genericMessage);
    }

    const verificationToken = generateRandomToken(24);
    user.verificationToken = hashToken(verificationToken);
    user.verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    const verifyLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
    const { delivered } = await sendEmail({
      to: user.email,
      subject: 'Verify your Assure Docs account',
      text: `Verify your email using this link (valid 24 hours): ${verifyLink}`,
      html: `<p>Verify your email using the link below (valid 24 hours):</p><p><a href="${verifyLink}">${verifyLink}</a></p>`,
    });

    return res.json({
      ...genericMessage,

    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/login
// Step 1 of login. Verifies credentials, runs the risk engine, and either
// issues a session token directly (low risk) or requires a one-time
// passcode (medium/high risk - adaptive MFA).
async function login(req, res, next) {
  try {
    const { email, password, adminOnly = false } = req.body;

    const user = await User.findOne({ email: (email || '').toLowerCase() }).select(
      '+passwordHash'
    );

    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'unknown';
    const deviceHash = deviceFingerprint(req);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (user.isLocked()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        message: `Account temporarily locked due to repeated failed attempts. Try again in ${minutesLeft} minute(s).`,
      });
    }

    const passwordOk = await user.comparePassword(password);

    if (!passwordOk) {
      user.failedLoginAttempts += 1;
      const maxAttempts = Number(process.env.MAX_FAILED_ATTEMPTS || 5);
      if (user.failedLoginAttempts >= maxAttempts) {
        user.lockUntil = new Date(Date.now() + Number(process.env.LOCK_MINUTES || 15) * 60000);
        user.failedLoginAttempts = 0;
      }
      await user.save();

      await LoginActivity.create({
        user: user._id,
        ip,
        userAgent,
        deviceHash,
        success: false,
        failureReason: 'invalid_password',
      });

      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Please verify your email before signing in' });
    }

    if (adminOnly && user.role !== 'admin') {
      return res.status(403).json({ message: 'This login is for administrators only.' });
    }

    // --- Adaptive risk assessment ---
    const isNewDevice = !user.trustedDevices.some((d) => d.deviceHash === deviceHash);
    const isNewIp = !user.trustedDevices.some((d) => d.ip === ip);

    const risk = scoreLogin({
      user,
      deviceHash,
      ip,
      isNewDevice,
      isNewIp,
      recentFailedAttempts: user.failedLoginAttempts,
    });

    const activity = await LoginActivity.create({
      user: user._id,
      ip,
      userAgent,
      deviceHash,
      isNewDevice,
      isNewIp,
      riskScore: risk.score,
      riskLevel: risk.level,
      riskReasons: risk.reasons,
      mfaRequired: true,
      mfaVerified: false,
      success: false, // becomes true once the session is actually issued
    });

    // OTP is mandatory for EVERY successful sign-in, regardless of risk level.
    // Do not issue a session token until the email OTP is verified.
    user.failedLoginAttempts = 0;
    await user.save();

    const code = generateOtp();
    const otpDoc = await OtpToken.create({
      user: user._id,
      loginActivity: activity._id,
      adminOnly,
      codeHash: hashOtp(code),
      expiresAt: new Date(Date.now() + Number(process.env.OTP_EXPIRES_MINUTES || 10) * 60000),
      deviceHash,
      ip,
      userAgent,
    });

    const { delivered } = await sendEmail({
      to: user.email,
      subject: 'Your Assure Docs verification code',
      text: `Your one-time passcode is ${code}. It expires in ${
        process.env.OTP_EXPIRES_MINUTES || 10
      } minutes. Reason for extra verification: ${risk.reasons.join('; ')}`,
      html: `<p>Your one-time passcode is <strong>${code}</strong>.</p><p>It expires in ${
        process.env.OTP_EXPIRES_MINUTES || 10
      } minutes.</p><p>Reason for extra verification: ${risk.reasons.join('; ')}</p>`,
    });

    return res.status(200).json({
      message: 'A verification code has been sent to your email. Enter it to complete sign-in.',
      mfaRequired: true,
      loginId: otpDoc._id,
      risk: { level: risk.level, score: risk.score, reasons: risk.reasons },

    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/verify-mfa
// Step 2 of login for medium/high risk attempts.
async function verifyMfa(req, res, next) {
  try {
    const { loginId, code } = req.body;

    const otpDoc = await OtpToken.findById(loginId).populate('loginActivity');
    if (!otpDoc || otpDoc.consumed || otpDoc.expiresAt < new Date()) {
      return res.status(400).json({ message: 'This code is invalid or has expired. Please sign in again.' });
    }

    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      return res.status(429).json({ message: 'Too many incorrect attempts. Please sign in again.' });
    }

    if (hashOtp(code) !== otpDoc.codeHash) {
      otpDoc.attempts += 1;
      await otpDoc.save();
      return res.status(400).json({ message: 'Incorrect code, please try again.' });
    }

    otpDoc.consumed = true;
    await otpDoc.save();

    const user = await User.findById(otpDoc.user);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.trustedDevices.push({ deviceHash: otpDoc.deviceHash, userAgent: otpDoc.userAgent, ip: otpDoc.ip });
    user.lastLoginAt = new Date();
    await user.save();

    if (otpDoc.loginActivity) {
      otpDoc.loginActivity.mfaVerified = true;
      otpDoc.loginActivity.success = true;
      await otpDoc.loginActivity.save();
    }

    const token = generateAuthToken(user._id);
    setAuthCookie(res, token);

    return res.json({
      message: 'Verification successful, login complete.',
      token,
      user: user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}


// @route POST /api/auth/admin-signup
// Creates a pending admin signup and emails a 6-digit OTP.
// A server-side ADMIN_SIGNUP_KEY prevents arbitrary public admin creation.
async function adminSignup(req, res, next) {
  try {
    const { name, email, password, signupKey } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();

    if (!process.env.ADMIN_SIGNUP_KEY || signupKey !== process.env.ADMIN_SIGNUP_KEY) {
      return res.status(403).json({ message: 'Invalid administrator signup key.' });
    }

    if (!name || !normalizedEmail || !password) {
      return res.status(400).json({ message: 'Name, email and password are required.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const code = generateOtp();

    // Invalidate older pending admin signup codes for this email.
    await OtpToken.updateMany(
      { email: normalizedEmail, purpose: 'admin_signup', consumed: false },
      { $set: { consumed: true } }
    );

    const otpDoc = await OtpToken.create({
      email: normalizedEmail,
      name,
      passwordHash,
      purpose: 'admin_signup',
      codeHash: hashOtp(code),
      expiresAt: new Date(Date.now() + Number(process.env.ADMIN_OTP_EXPIRES_MINUTES || 10) * 60000),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || 'unknown',
    });

    const { delivered } = await sendEmail({
      to: normalizedEmail,
      subject: 'Assure Docs admin signup verification code',
      text: `Your Assure Docs administrator signup OTP is ${code}. It expires in ${process.env.ADMIN_OTP_EXPIRES_MINUTES || 10} minutes.`,
      html: `<div style="font-family:Arial,sans-serif"><h2>Assure Docs Admin Signup</h2><p>Your verification code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in ${process.env.ADMIN_OTP_EXPIRES_MINUTES || 10} minutes.</p><p>If you did not request administrator access, ignore this email.</p></div>`,
    });

    return res.status(201).json({
      message: delivered
        ? 'Verification code sent to your Gmail/email address.'
        : 'SMTP is not configured. In development, the OTP is available below.',
      signupId: otpDoc._id,
      email: normalizedEmail,

    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/admin-signup/verify
// Verifies the OTP and creates the administrator in MongoDB.
async function verifyAdminSignup(req, res, next) {
  try {
    const { signupId, code } = req.body;

    const otpDoc = await OtpToken.findOne({
      _id: signupId,
      purpose: 'admin_signup',
      consumed: false,
    }).select('+passwordHash');

    if (!otpDoc || otpDoc.expiresAt < new Date()) {
      return res.status(400).json({ message: 'This OTP is invalid or has expired. Please start signup again.' });
    }

    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      return res.status(429).json({ message: 'Too many incorrect attempts. Please start signup again.' });
    }

    if (hashOtp(String(code || '')) !== otpDoc.codeHash) {
      otpDoc.attempts += 1;
      await otpDoc.save();
      return res.status(400).json({ message: 'Incorrect OTP. Please try again.' });
    }

    const existing = await User.findOne({ email: otpDoc.email });
    if (existing) {
      otpDoc.consumed = true;
      await otpDoc.save();
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const user = await User.create({
      name: otpDoc.name,
      email: otpDoc.email,
      passwordHash: otpDoc.passwordHash,
      role: 'admin',
      isVerified: true,
    });

    otpDoc.user = user._id;
    otpDoc.consumed = true;
    await otpDoc.save();

    return res.status(201).json({
      message: 'Administrator account created and email verified successfully.',
      user: user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/logout
async function logout(req, res) {
  res.clearCookie(COOKIE_NAME);
  res.json({ message: 'Logged out' });
}

// @route GET /api/auth/me
async function me(req, res) {
  res.json({ user: req.user.toSafeObject() });
}

module.exports = { register, verifySignup, verifyEmail, resendVerification, login, verifyMfa, adminSignup, verifyAdminSignup, logout, me };
