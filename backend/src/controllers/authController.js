const bcrypt = require('bcryptjs');
const User = require('../models/User');
const LoginActivity = require('../models/LoginActivity');
const OtpToken = require('../models/OtpToken');
const RefreshToken = require('../models/RefreshToken');
const { scoreLogin } = require('../utils/riskEngine');
const { sendEmail } = require('../utils/sendEmail');
const { generateOtp, hashOtp } = require('../utils/otp');
const logger = require('../utils/logger');
const { loginAttemptsTotal, loginRiskScore, loginVerificationTotal } = require('../utils/metrics');
const {
  getSessionStatus,
  clearSessionByUserId,
  establishSessionBaseline,
  initializeSession,
  refreshSessionBaselineAfterReauth,
  establishStepUpVerification,
  STEP_UP_VERIFY_WINDOW_MS,
} = require('../services/sessionMonitor');
const {
  computeSessionContextFeatures,
} = require('../utils/sessionContextFeatures');
const {
  generateAuthToken,
  generateRandomToken,
  hashToken,
  deviceFingerprint,
  getClientIp,
  setAuthCookie,
  issueRefreshToken,
  clearAuthCookies,
  getRefreshToken,
} = require('../utils/generateToken');

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
      ...(delivered ? {} : { devOtpCode: code }),
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
      loginAttemptsTotal.inc({ outcome: 'failed', risk_level: 'unknown' });
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (user.isLocked()) {
      loginAttemptsTotal.inc({ outcome: 'locked', risk_level: 'unknown' });
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

      loginAttemptsTotal.inc({ outcome: 'failed', risk_level: 'unknown' });
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (!user.isVerified) {
      loginAttemptsTotal.inc({ outcome: 'pending', risk_level: 'unknown' });
      return res.status(403).json({ message: 'Please verify your email before signing in' });
    }

    if (adminOnly && user.role !== 'admin' && user.role !== 'institution') {
      loginAttemptsTotal.inc({ outcome: 'forbidden', risk_level: 'unknown' });
      return res.status(403).json({ message: 'This login is for administrators only.' });
    }

    // --- Adaptive risk assessment ---
    const isNewDevice = !user.trustedDevices.some((d) => d.deviceHash === deviceHash);
    const isNewIp = !user.trustedDevices.some((d) => d.ip === ip);

    // Rule-based risk assessment
    const ruleRisk = scoreLogin({
      user,
      deviceHash,
      ip,
      isNewDevice,
      isNewIp,
      recentFailedAttempts: user.failedLoginAttempts,
    });

    // AI-based risk assessment (Python anomaly-detection service).
    // Falls back to the rule-based result if the AI service is unreachable.
    let aiRisk = { score: 0, level: 'low', reasons: [], mfaRequired: false };
    let finalRisk = ruleRisk;

    try {
      const aiService = require('../services/aiService');
      const loginAttemptData = await aiService.buildLoginAttempt(
        user,
        deviceHash,
        ip,
        userAgent,
        req,
        user.failedLoginAttempts
      );

      const aiResult = await aiService.assessRisk(loginAttemptData);

      aiRisk = {
        score: aiResult.risk_score,
        level: aiResult.risk_level.toLowerCase(),
        reasons: [aiResult.reason],
        mfaRequired: aiResult.recommended_action !== 'Allow Login',
      };

      // Combine rule-based and AI assessments, taking the higher risk.
      const levelPriority = { low: 1, medium: 2, high: 3 };
      finalRisk = {
        score: Math.max(ruleRisk.score, aiRisk.score),
        level:
          levelPriority[ruleRisk.level] >= levelPriority[aiRisk.level]
            ? ruleRisk.level
            : aiRisk.level,
        mfaRequired: ruleRisk.mfaRequired || aiRisk.mfaRequired,
        reasons: [...ruleRisk.reasons, ...aiRisk.reasons],
      };
    } catch (aiError) {
      logger.warn('AI service unavailable, falling back to rule-based risk assessment', {
        error: aiError.message,
      });
      finalRisk = ruleRisk;
    }

    // --- Impossible-travel detection ---
    // Compare this attempt's location against the user's last successful login.
    // If they are implausibly far apart in a short time window, raise the risk.
    let activityGeo = null;
    try {
      const { getIpGeolocation } = require('../services/ipService');
      const { assessImpossibleTravel } = require('../utils/geolocation');

      const currentGeo = await getIpGeolocation(ip);
      const lastLogin = await LoginActivity.findOne({
        user: user._id,
        success: true,
        mfaVerified: true,
        latitude: { $ne: null },
      }).sort({ createdAt: -1 });

      const travel = assessImpossibleTravel(
        lastLogin
          ? {
              country: lastLogin.country,
              city: lastLogin.city,
              latitude: lastLogin.latitude,
              longitude: lastLogin.longitude,
              ts: new Date(lastLogin.createdAt).getTime(),
            }
          : null,
        {
          country: currentGeo.country,
          city: currentGeo.city,
          latitude: currentGeo.latitude,
          longitude: currentGeo.longitude,
          ts: Date.now(),
        }
      );

      if (travel.impossible && travel.reason) {
        finalRisk.reasons.push(travel.reason);
        // Impossible travel is always treated as high risk.
        finalRisk.score = Math.max(finalRisk.score, 80);
        finalRisk.level = 'high';
        finalRisk.mfaRequired = true;
      }

      // Stash current geo on the activity record below.
      activityGeo = currentGeo;
    } catch (geoError) {
      logger.warn('Impossible-travel check failed', { error: geoError.message });
    }

    const activity = await LoginActivity.create({
      user: user._id,
      ip,
      userAgent,
      deviceHash,
      isNewDevice,
      isNewIp,
      country: activityGeo?.country,
      city: activityGeo?.city,
      latitude: activityGeo?.latitude || null,
      longitude: activityGeo?.longitude || null,
      riskScore: finalRisk.score,
      riskLevel: finalRisk.level,
      riskReasons: finalRisk.reasons,
      ruleRiskScore: ruleRisk.score,
      ruleRiskLevel: ruleRisk.level,
      aiRiskScore: aiRisk.score > 0 ? aiRisk.score : null,
      aiRiskLevel: aiRisk.score > 0 ? aiRisk.level : null,
      mfaRequired: true,
      mfaVerified: false,
      success: false, // becomes true once the session is actually issued
    });

    // Compute session-login context features from real application data.
    // These are derived from existing DB records — no random values are generated.
    const computedFeatures = await computeSessionContextFeatures({
      user,
      deviceHash,
      currentGeo: activityGeo,
    });

    // Store the computed features on the activity record for later inspection.
    if (computedFeatures.device_seen_before !== undefined) {
      // We don't have a deviceSeenBefore field on the schema, but we keep
      // the data on the document in a flexible way for audit purposes.
      activity.deviceSeenBefore = computedFeatures.device_seen_before;
    }
    activity.timeSinceLastLoginMs = computedFeatures.time_since_last_login;
    activity.distanceFromLastKm = computedFeatures.distance_from_last_location;
    activity.recentFailedLoginsCount = computedFeatures.number_of_recent_failed_logins;
    activity.successfulMfaHistoryCount = computedFeatures.successful_mfa_history;
    await activity.save();

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
      } minutes. Reason for extra verification: ${finalRisk.reasons.join('; ')}`,
      html: `<p>Your one-time passcode is <strong>${code}</strong>.</p><p>It expires in ${
        process.env.OTP_EXPIRES_MINUTES || 10
      } minutes.</p><p>Reason for extra verification: ${finalRisk.reasons.join('; ')}</p>`,
    });

    loginAttemptsTotal.inc({ outcome: 'mfa_required', risk_level: finalRisk.level });
    loginRiskScore.observe(finalRisk.score);

    return res.status(200).json({
      message: 'A verification code has been sent to your email. Enter it to complete sign-in.',
      mfaRequired: true,
      loginId: otpDoc._id,
      ...(delivered ? {} : { devOtpCode: code }),
      risk: {
        level: finalRisk.level,
        score: finalRisk.score,
        reasons: finalRisk.reasons,
        aiAssessment: aiRisk.score > 0 ? aiRisk : null, // AI data when the service responded
      },
      // Session-login context features computed from real application data.
      contextFeatures: computedFeatures,
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

    // A brand-new authenticated session must start clean: drop any stale
    // "requires re-authentication" flag left over from a previous session.
    clearSessionByUserId(user._id);

    // Attach the authenticated user to the request so the session monitor
    // can key the new session by userId (stable across access-token rotation).
    req.user = user;

    user.trustedDevices.push({ deviceHash: otpDoc.deviceHash, userAgent: otpDoc.userAgent, ip: otpDoc.ip });
    user.lastLoginAt = new Date();
    await user.save();

    if (otpDoc.loginActivity) {
      otpDoc.loginActivity.mfaVerified = true;
      otpDoc.loginActivity.success = true;
      await otpDoc.loginActivity.save();
    }

    loginVerificationTotal.inc({ outcome: 'success' });

    const token = generateAuthToken(user._id);
    setAuthCookie(res, token);
    await issueRefreshToken(res, user._id, { req });

    // Compute session-login context features at the moment the new session is
    // fully established. The device has just been added to trustedDevices above,
    // so device_seen_before will now return true for this exact device.
    const computedContextFeatures = await computeSessionContextFeatures({
      user,
      deviceHash: otpDoc.deviceHash,
      currentGeo: {
        latitude: otpDoc.loginActivity?.latitude || null,
        longitude: otpDoc.loginActivity?.longitude || null,
      },
    });

    // Initialize the monitored session for the newly authenticated user.
    // Creates the session entry (keyed by userId) and establishes the
    // security baseline. Idempotent: reuses an existing session if one was
    // already created by an authenticated action.
    const session = await initializeSession(req);

    // Copy the persisted login risk components onto the in-memory monitored
    // session so /admin/active-sessions can expose them. null means the
    // component was genuinely unavailable (e.g. the AI service was down).
    if (session && otpDoc.loginActivity) {
      const activity = otpDoc.loginActivity;
      session.loginRisk = {
        ruleBased: {
          score: activity.ruleRiskScore ?? null,
          level: activity.ruleRiskLevel ?? null,
        },
        ai: {
          score: activity.aiRiskScore ?? null,
          level: activity.aiRiskLevel ?? null,
        },
      };
    }

    const contextFeatures = {
      device_seen_before: computedContextFeatures.device_seen_before,
      time_since_last_login: computedContextFeatures.time_since_last_login,
      user_typical_login_hour: computedContextFeatures.user_typical_login_hour,
      time_since_previous_session: computedContextFeatures.time_since_previous_session,
      distance_from_last_location: computedContextFeatures.distance_from_last_location,
      number_of_recent_failed_logins: computedContextFeatures.number_of_recent_failed_logins,
      successful_mfa_history: computedContextFeatures.successful_mfa_history,
    };

    return res.json({
      message: 'Verification successful, login complete.',
      token,
      user: user.toSafeObject(),
      contextFeatures,
    });
  } catch (err) {
    next(err);
  }
}

async function requestReauthentication(req, res, next) {
  try {
    const sessionStatus = getSessionStatus(req);

    if (!sessionStatus?.requiresReauthentication) {
      return res.status(400).json({
        message: 'Re-authentication is not required for this session.',
      });
    }

    const code = generateOtp();

    await OtpToken.updateMany(
      { user: req.user._id, purpose: 'reauth', consumed: false },
      { $set: { consumed: true } }
    );

    const otpDoc = await OtpToken.create({
      user: req.user._id,
      email: req.user.email,
      name: req.user.name,
      purpose: 'reauth',
      codeHash: hashOtp(code),
      expiresAt: new Date(Date.now() + Number(process.env.OTP_EXPIRES_MINUTES || 10) * 60000),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || 'unknown',
    });

    const { delivered } = await sendEmail({
      to: req.user.email,
      subject: 'Your Assure Docs re-authentication code',
      text: `Your one-time passcode is ${code}. It expires in ${
        process.env.OTP_EXPIRES_MINUTES || 10
      } minutes.`,
      html: `<p>Your one-time passcode is <strong>${code}</strong>.</p><p>It expires in ${
        process.env.OTP_EXPIRES_MINUTES || 10
      } minutes.</p>`,
    });

    return res.status(200).json({
      message: delivered
        ? 'A re-authentication code has been sent to your email.'
        : 'SMTP is not configured. In development, the OTP is available below.',
      reauthId: otpDoc._id,
      ...(delivered ? {} : { devOtpCode: code }),
    });
  } catch (err) {
    next(err);
  }
}

async function verifyReauthentication(req, res, next) {
  try {
    const { reauthId, code } = req.body;
    const sessionStatus = getSessionStatus(req);

    if (!sessionStatus?.requiresReauthentication) {
      return res.status(400).json({
        message: 'Re-authentication is not required for this session.',
      });
    }

    const otpDoc = await OtpToken.findOne({
      _id: reauthId,
      user: req.user._id,
      purpose: 'reauth',
      consumed: false,
    });

    if (!otpDoc || otpDoc.expiresAt < new Date()) {
      return res.status(400).json({ message: 'This code is invalid or has expired. Please try again.' });
    }

    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      return res.status(429).json({ message: 'Too many incorrect attempts. Please request a new code.' });
    }

    if (hashOtp(String(code || '')) !== otpDoc.codeHash) {
      otpDoc.attempts += 1;
      await otpDoc.save();
      return res.status(400).json({ message: 'Incorrect code, please try again.' });
    }

    otpDoc.consumed = true;
    await otpDoc.save();

    await refreshSessionBaselineAfterReauth(req);

    return res.json({
      message: 'Re-authentication successful. Session restored.',
      reauthenticationRequired: false,
      user: req.user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/stepup/request
// Issues a fresh OTP with purpose='stepup' so the user can verify a sensitive action.
// The user must be authenticated. If the session is already flagged for risk-based
// reauthentication, the client is told to use the reauth flow instead.
async function requestStepUp(req, res, next) {
  try {
    // Risk-based reauth has its own dedicated flow.
    if (getSessionStatus(req)?.requiresReauthentication) {
      return res.status(400).json({
        message: 'Session requires re-authentication. Use the re-authentication flow instead.',
        useReauthFlow: true,
      });
    }

    const code = generateOtp();

    // Invalidate any prior pending step-up OTP for this user.
    await OtpToken.updateMany(
      { user: req.user._id, purpose: 'stepup', consumed: false },
      { $set: { consumed: true } }
    );

    const otpDoc = await OtpToken.create({
      user: req.user._id,
      email: req.user.email,
      name: req.user.name,
      purpose: 'stepup',
      codeHash: hashOtp(code),
      expiresAt: new Date(Date.now() + Number(process.env.OTP_EXPIRES_MINUTES || 10) * 60000),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || 'unknown',
    });

    const { delivered } = await sendEmail({
      to: req.user.email,
      subject: 'Assure Docs — additional verification required',
      text: `Your one-time passcode is ${code}. It expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes.`,
      html: `<p>Your one-time passcode is <strong>${code}</strong>.</p><p>It expires in ${process.env.OTP_EXPIRES_MINUTES || 10} minutes.</p>`,
    });

    return res.status(200).json({
      message: delivered
        ? 'A verification code has been sent to your email.'
        : 'SMTP is not configured. In development, the OTP is available below.',
      reauthId: otpDoc._id,
      expiresAt: otpDoc.expiresAt,
      ...(delivered ? {} : { devOtpCode: code }),
    });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/auth/stepup/verify
// Validates the step-up OTP and establishes a short-lived step-up verification
// on the session. Does NOT touch risk-based reauthentication state.
async function verifyStepUp(req, res, next) {
  try {
    const { reauthId, code } = req.body;

    // Risk-based reauth has its own dedicated flow.
    if (getSessionStatus(req)?.requiresReauthentication) {
      return res.status(400).json({
        message: 'Session requires re-authentication. Use the re-authentication flow instead.',
        useReauthFlow: true,
      });
    }

    const otpDoc = await OtpToken.findOne({
      _id: reauthId,
      user: req.user._id,
      purpose: 'stepup',
      consumed: false,
    });

    if (!otpDoc || otpDoc.expiresAt < new Date()) {
      return res.status(400).json({ message: 'This code is invalid or has expired. Please try again.' });
    }

    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      return res.status(429).json({ message: 'Too many incorrect attempts. Please request a new code.' });
    }

    if (hashOtp(String(code || '')) !== otpDoc.codeHash) {
      otpDoc.attempts += 1;
      await otpDoc.save();
      return res.status(400).json({ message: 'Incorrect code, please try again.' });
    }

    otpDoc.consumed = true;
    await otpDoc.save();

    // Establish step-up verification on the session — does NOT clear requiresReauthentication.
    const stepUpVerified = establishStepUpVerification(req);

    return res.json({
      message: 'Verification successful.',
      stepUpVerified: {
        purpose: stepUpVerified.purpose,
        expiresAt: stepUpVerified.expiresAt,
      },
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
      ...(delivered ? {} : { devOtpCode: code }),
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
  const rawToken = getRefreshToken(req);
  if (rawToken) {
    const tokenHash = require('crypto').createHash('sha256').update(rawToken).digest('hex');
    const refreshDoc = await RefreshToken.findOne({ tokenHash });
    if (refreshDoc) {
      clearSessionByUserId(refreshDoc.user);
    }
    await RefreshToken.updateOne({ tokenHash }, { revoked: true, revokedAt: new Date() }).exec();
  }
  clearAuthCookies(res);
  res.json({ message: 'Logged out' });
}

// @route POST /api/auth/refresh
// Rotates the refresh token: revokes the current one and issues a fresh
// short-lived access token + a new refresh token.
async function refresh(req, res, next) {
  try {
    const rawToken = getRefreshToken(req);
    if (!rawToken) {
      return res.status(401).json({ message: 'Refresh token missing' });
    }

    const token = await RefreshToken.consume(rawToken);
    if (!token) {
      return res.status(401).json({ message: 'Invalid, expired, or revoked refresh token' });
    }

    const user = await User.findById(token.user);
    if (!user) {
      return res.status(401).json({ message: 'User no longer exists' });
    }

    const accessToken = generateAuthToken(user._id);
    setAuthCookie(res, accessToken);
    await issueRefreshToken(res, user._id, { req });

    res.json({ token: accessToken, user: user.toSafeObject() });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/auth/me
async function me(req, res) {
  res.json({ user: req.user.toSafeObject() });
}

module.exports = {
  register,
  verifySignup,
  verifyEmail,
  resendVerification,
  login,
  verifyMfa,
  requestReauthentication,
  verifyReauthentication,
  requestStepUp,
  verifyStepUp,
  adminSignup,
  verifyAdminSignup,
  refresh,
  logout,
  me,
};
