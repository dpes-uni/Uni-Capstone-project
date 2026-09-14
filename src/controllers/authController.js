```javascript
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const LoginActivity = require('../models/LoginActivity');
const OtpToken = require('../models/OtpToken');
const RefreshToken = require('../models/RefreshToken');
const { scoreLogin } = require('../utils/riskEngine');
const { sendEmail } = require('../utils/sendEmail');
const { generateOtp, hashOtp } = require('../utils/otp');
const logger = require('../utils/logger');
const {
  loginAttemptsTotal,
  loginRiskScore,
  loginVerificationTotal,
} = require('../utils/metrics');

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


// ==========================================================
// REGISTER
// ==========================================================

// @route POST /api/auth/register
// Creates a pending signup and ALWAYS sends a 6-digit OTP
// to the signup email.
async function register(req, res, next) {
  try {
    const { name, email, password, role } = req.body;
    const normalizedEmail = (email || '').toLowerCase().trim();

    if (!name || !normalizedEmail || !password) {
      return res.status(400).json({
        message: 'Name, email and password are required.',
      });
    }

    const existing = await User.findOne({
      email: normalizedEmail,
    });

    if (existing) {
      return res.status(409).json({
        message: 'An account with this email already exists',
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const code = generateOtp();

    await OtpToken.updateMany(
      {
        email: normalizedEmail,
        purpose: 'signup',
        consumed: false,
      },
      {
        $set: {
          consumed: true,
        },
      }
    );

    const otpDoc = await OtpToken.create({
      email: normalizedEmail,
      name,
      role: ['student', 'agent', 'institution'].includes(role)
        ? role
        : 'student',
      passwordHash,
      purpose: 'signup',
      codeHash: hashOtp(code),
      expiresAt: new Date(
        Date.now() +
          Number(process.env.OTP_EXPIRES_MINUTES || 10) * 60000
      ),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || 'unknown',
    });

    const { delivered } = await sendEmail({
      to: normalizedEmail,
      subject: 'Your Assure Docs signup verification code',
      text: `Your Assure Docs signup OTP is ${code}. It expires in ${
        process.env.OTP_EXPIRES_MINUTES || 10
      } minutes.`,
      html: `<div style="font-family:Arial,sans-serif">
        <h2>Assure Docs Signup</h2>
        <p>Your verification code is:</p>
        <p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p>
        <p>This code expires in ${
          process.env.OTP_EXPIRES_MINUTES || 10
        } minutes.</p>
        <p>If you did not request this account, ignore this email.</p>
      </div>`,
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


// ==========================================================
// VERIFY SIGNUP
// ==========================================================

// @route POST /api/auth/register/verify
async function verifySignup(req, res, next) {
  try {
    const { signupId, code } = req.body;

    const otpDoc = await OtpToken.findOne({
      _id: signupId,
      purpose: 'signup',
      consumed: false,
    }).select('+passwordHash');

    if (!otpDoc || otpDoc.expiresAt < new Date()) {
      return res.status(400).json({
        message:
          'This OTP is invalid or has expired. Please sign up again.',
      });
    }

    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      return res.status(429).json({
        message:
          'Too many incorrect attempts. Please sign up again.',
      });
    }

    if (hashOtp(String(code || '')) !== otpDoc.codeHash) {
      otpDoc.attempts += 1;
      await otpDoc.save();

      return res.status(400).json({
        message: 'Incorrect OTP. Please try again.',
      });
    }

    const existing = await User.findOne({
      email: otpDoc.email,
    });

    if (existing) {
      otpDoc.consumed = true;
      await otpDoc.save();

      return res.status(409).json({
        message: 'An account with this email already exists.',
      });
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
      message:
        'Account created and email verified successfully. You can now sign in.',
      user: user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}


// ==========================================================
// VERIFY EMAIL
// ==========================================================

// @route GET /api/auth/verify-email/:token
async function verifyEmail(req, res, next) {
  try {
    const { token } = req.params;
    const hashed = hashToken(token);

    const user = await User.findOne({
      verificationToken: hashed,
      verificationTokenExpires: {
        $gt: Date.now(),
      },
    }).select('+verificationToken +verificationTokenExpires');

    if (!user) {
      return res.status(400).json({
        message:
          'Verification link is invalid or has expired',
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;

    await user.save();

    return res.json({
      message:
        'Email verified successfully. You can now sign in.',
    });
  } catch (err) {
    next(err);
  }
}


// ==========================================================
// RESEND VERIFICATION
// ==========================================================

// @route POST /api/auth/resend-verification
async function resendVerification(req, res, next) {
  try {
    const { email } = req.body;

    const user = await User.findOne({
      email: (email || '').toLowerCase(),
    });

    // Avoid leaking whether an account exists.
    const genericMessage = {
      message:
        'If that account exists and is unverified, a new link has been sent.',
    };

    if (!user || user.isVerified) {
      return res.json(genericMessage);
    }

    const verificationToken = generateRandomToken(24);

    user.verificationToken = hashToken(
      verificationToken
    );

    user.verificationTokenExpires =
      Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const verifyLink =
      `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;

    await sendEmail({
      to: user.email,
      subject: 'Verify your Assure Docs account',
      text:
        `Verify your email using this link ` +
        `(valid 24 hours): ${verifyLink}`,
      html:
        `<p>Verify your email using the link below ` +
        `(valid 24 hours):</p>` +
        `<p><a href="${verifyLink}">${verifyLink}</a></p>`,
    });

    return res.json(genericMessage);
  } catch (err) {
    next(err);
  }
}


// ==========================================================
// LOGIN
// ==========================================================

// @route POST /api/auth/login
//
// Adaptive authentication:
//
//     Low risk
//         -> Allow Login
//         -> Issue session directly
//
//     Medium/High risk
//         -> Require existing email OTP MFA
//
//     Block Login
//         -> Reject login
//
// Python AI provides risk assessment.
// Node.js remains responsible for enforcing the
// authentication decision.
async function login(req, res, next) {
  try {
    const {
      email,
      password,
      adminOnly = false,
    } = req.body;

    const user = await User.findOne({
      email: (email || '').toLowerCase(),
    }).select('+passwordHash');

    const ip = getClientIp(req);
    const userAgent =
      req.headers['user-agent'] || 'unknown';

    const deviceHash = deviceFingerprint(req);

    // ------------------------------------------------------
    // User existence
    // ------------------------------------------------------

    if (!user) {
      loginAttemptsTotal.inc({
        outcome: 'failed',
        risk_level: 'unknown',
      });

      return res.status(401).json({
        message: 'Invalid email or password',
      });
    }


    // ------------------------------------------------------
    // Account lock
    // ------------------------------------------------------

    if (user.isLocked()) {
      loginAttemptsTotal.inc({
        outcome: 'locked',
        risk_level: 'unknown',
      });

      const minutesLeft = Math.ceil(
        (user.lockUntil - Date.now()) / 60000
      );

      return res.status(423).json({
        message:
          `Account temporarily locked due to repeated ` +
          `failed attempts. Try again in ` +
          `${minutesLeft} minute(s).`,
      });
    }


    // ------------------------------------------------------
    // Password verification
    // ------------------------------------------------------

    const passwordOk =
      await user.comparePassword(password);

    if (!passwordOk) {
      user.failedLoginAttempts += 1;

      const maxAttempts = Number(
        process.env.MAX_FAILED_ATTEMPTS || 5
      );

      if (
        user.failedLoginAttempts >= maxAttempts
      ) {
        user.lockUntil = new Date(
          Date.now() +
            Number(process.env.LOCK_MINUTES || 15) *
              60000
        );

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

      loginAttemptsTotal.inc({
        outcome: 'failed',
        risk_level: 'unknown',
      });

      return res.status(401).json({
        message: 'Invalid email or password',
      });
    }


    // ------------------------------------------------------
    // Email verification
    // ------------------------------------------------------

    if (!user.isVerified) {
      loginAttemptsTotal.inc({
        outcome: 'pending',
        risk_level: 'unknown',
      });

      return res.status(403).json({
        message:
          'Please verify your email before signing in',
      });
    }


    // ------------------------------------------------------
    // Admin access check
    // ------------------------------------------------------

    if (
      adminOnly &&
      user.role !== 'admin' &&
      user.role !== 'institution'
    ) {
      loginAttemptsTotal.inc({
        outcome: 'forbidden',
        risk_level: 'unknown',
      });

      return res.status(403).json({
        message:
          'This login is for administrators only.',
      });
    }


    // ======================================================
    // ADAPTIVE RISK ASSESSMENT
    // ======================================================

    const isNewDevice =
      !user.trustedDevices.some(
        (d) => d.deviceHash === deviceHash
      );

    const isNewIp =
      !user.trustedDevices.some(
        (d) => d.ip === ip
      );


    // ------------------------------------------------------
    // Rule-based risk
    // ------------------------------------------------------

    const ruleRisk = scoreLogin({
      user,
      deviceHash,
      ip,
      isNewDevice,
      isNewIp,
      recentFailedAttempts:
        user.failedLoginAttempts,
    });


    // ------------------------------------------------------
    // Default risk if AI unavailable
    // ------------------------------------------------------

    let aiRisk = {
      score: 0,
      level: 'low',
      recommendedAction: 'Allow Login',
      reasons: [],
      mfaRequired: false,
    };

    let finalRisk = {
      score: ruleRisk.score,
      level: ruleRisk.level,
      reasons: [...ruleRisk.reasons],
      mfaRequired: ruleRisk.mfaRequired,
      recommendedAction:
        ruleRisk.level === 'low'
          ? 'Allow Login'
          : 'Require Email OTP',
    };


    // ======================================================
    // PYTHON AI RISK ASSESSMENT
    // ======================================================

    try {
      const aiService =
        require('../services/aiService');

      const loginAttemptData =
        await aiService.buildLoginAttempt(
          user,
          deviceHash,
          ip,
          userAgent,
          req,
          user.failedLoginAttempts
        );

      const aiResult =
        await aiService.assessRisk(
          loginAttemptData
        );


      // ----------------------------------------------------
      // Preserve complete Python RiskResult
      // ----------------------------------------------------

      aiRisk = {
        score: Number(aiResult.risk_score),
        level: String(
          aiResult.risk_level
        ).toLowerCase(),
        recommendedAction:
          aiResult.recommended_action,
        reasons: [
          aiResult.reason,
        ],
        mfaRequired:
          aiResult.recommended_action !==
          'Allow Login',
      };


      // ----------------------------------------------------
      // Combine rule + AI risk
      // ----------------------------------------------------

      const levelPriority = {
        low: 1,
        medium: 2,
        high: 3,
      };

      const ruleLevel =
        String(ruleRisk.level).toLowerCase();

      const aiLevel =
        String(aiRisk.level).toLowerCase();

      const highestRiskLevel =
        levelPriority[ruleLevel] >=
        levelPriority[aiLevel]
          ? ruleLevel
          : aiLevel;


      // ----------------------------------------------------
      // Determine whether MFA is required
      // ----------------------------------------------------

      const mfaRequired =
        ruleRisk.mfaRequired ||
        aiRisk.mfaRequired;


      // ----------------------------------------------------
      // Determine final recommended action
      //
      // Block takes priority.
      // Otherwise MFA takes priority.
      // Otherwise allow.
      // ----------------------------------------------------

      let recommendedAction =
        'Allow Login';

      if (
        aiRisk.recommendedAction ===
        'Block Login'
      ) {
        recommendedAction =
          'Block Login';
      } else if (mfaRequired) {
        if (
          aiRisk.recommendedAction ===
          'Require Additional Verification'
        ) {
          recommendedAction =
            'Require Additional Verification';
        } else {
          recommendedAction =
            'Require Email OTP';
        }
      }


      finalRisk = {
        score: Math.max(
          Number(ruleRisk.score) || 0,
          Number(aiRisk.score) || 0
        ),
        level: highestRiskLevel,
        reasons: [
          ...ruleRisk.reasons,
          ...aiRisk.reasons,
        ],
        mfaRequired,
        recommendedAction,
      };

    } catch (aiError) {
      // ----------------------------------------------------
      // AI unavailable:
      //
      // Fall back safely to the existing rule engine.
      // The application does not fail closed solely because
      // the optional AI service is unavailable.
      // ----------------------------------------------------

      logger.warn(
        'AI service unavailable, falling back to rule-based risk assessment',
        {
          error: aiError.message,
        }
      );

      finalRisk = {
        score: ruleRisk.score,
        level: ruleRisk.level,
        reasons: [...ruleRisk.reasons],
        mfaRequired: ruleRisk.mfaRequired,
        recommendedAction:
          ruleRisk.mfaRequired
            ? 'Require Email OTP'
            : 'Allow Login',
      };
    }


    // ======================================================
    // IMPOSSIBLE TRAVEL DETECTION
    // ======================================================

    let activityGeo = null;

    try {
      const {
        getIpGeolocation,
      } = require('../services/ipService');

      const {
        assessImpossibleTravel,
      } = require('../utils/geolocation');

      const currentGeo =
        await getIpGeolocation(ip);

      const lastLogin =
        await LoginActivity.findOne({
          user: user._id,
          success: true,
          mfaVerified: true,
          latitude: {
            $ne: null,
          },
        }).sort({
          createdAt: -1,
        });


      const travel =
        assessImpossibleTravel(
          lastLogin
            ? {
                country: lastLogin.country,
                city: lastLogin.city,
                latitude: lastLogin.latitude,
                longitude: lastLogin.longitude,
                ts: new Date(
                  lastLogin.createdAt
                ).getTime(),
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


      if (
        travel.impossible &&
        travel.reason
      ) {
        finalRisk.reasons.push(
          travel.reason
        );

        // Impossible travel is treated as high risk.
        finalRisk.score =
          Math.max(
            finalRisk.score,
            80
          );

        finalRisk.level = 'high';
        finalRisk.mfaRequired = true;

        finalRisk.recommendedAction =
          'Require Additional Verification';
      }

      activityGeo = currentGeo;

    } catch (geoError) {
      logger.warn(
        'Impossible-travel check failed',
        {
          error: geoError.message,
        }
      );
    }


    // ======================================================
    // LOGIN ACTIVITY
    // ======================================================

    const activity =
      await LoginActivity.create({
        user: user._id,
        ip,
        userAgent,
        deviceHash,
        isNewDevice,
        isNewIp,
        country:
          activityGeo?.country,
        city:
          activityGeo?.city,
        latitude:
          activityGeo?.latitude || null,
        longitude:
          activityGeo?.longitude || null,
        riskScore:
          finalRisk.score,
        riskLevel:
          finalRisk.level,
        riskReasons:
          finalRisk.reasons,

        // This is updated below depending on the
        // adaptive authentication decision.
        mfaRequired:
          finalRisk.recommendedAction !==
          'Allow Login',

        mfaVerified:
          false,

        success:
          false,
      });


    // ======================================================
    // RESET FAILED LOGIN ATTEMPTS
    // ======================================================

    user.failedLoginAttempts = 0;
    await user.save();


    // ======================================================
    // DECISION 1 — BLOCK
    // ======================================================

    if (
      finalRisk.recommendedAction ===
      'Block Login'
    ) {
      activity.mfaRequired = false;
      activity.mfaVerified = false;
      activity.success = false;

      await activity.save();

      loginAttemptsTotal.inc({
        outcome: 'blocked',
        risk_level:
          finalRisk.level,
      });

      loginRiskScore.observe(
        finalRisk.score
      );

      return res.status(403).json({
        message:
          'Login blocked due to elevated security risk.',
        mfaRequired: false,
        risk: {
          level:
            finalRisk.level,
          score:
            finalRisk.score,
          reasons:
            finalRisk.reasons,
          aiAssessment:
            aiRisk.score > 0
              ? aiRisk
              : null,
        },
      });
    }


    // ======================================================
    // DECISION 2 — ALLOW
    // ======================================================

    if (
      finalRisk.recommendedAction ===
      'Allow Login'
    ) {
      activity.mfaRequired = false;
      activity.mfaVerified = true;
      activity.success = true;

      await activity.save();


      // Update user's last login.
      user.lastLoginAt =
        new Date();

      await user.save();


      // Issue normal authentication tokens.
      const token =
        generateAuthToken(
          user._id
        );

      setAuthCookie(
        res,
        token
      );

      await issueRefreshToken(
        res,
        user._id,
        {
          req,
        }
      );


      loginAttemptsTotal.inc({
        outcome: 'success',
        risk_level:
          finalRisk.level,
      });

      loginRiskScore.observe(
        finalRisk.score
      );


      return res.status(200).json({
        message:
          'Login successful.',
        mfaRequired: false,
        token,
        user:
          user.toSafeObject(),
        risk: {
          level:
            finalRisk.level,
          score:
            finalRisk.score,
          reasons:
            finalRisk.reasons,
          aiAssessment:
            aiRisk.score > 0
              ? aiRisk
              : null,
        },
      });
    }


    // ======================================================
    // DECISION 3 — MFA REQUIRED
    // ======================================================

    activity.mfaRequired = true;
    activity.mfaVerified = false;
    activity.success = false;

    await activity.save();


    // ------------------------------------------------------
    // Generate OTP
    // ------------------------------------------------------

    const code =
      generateOtp();


    const otpDoc =
      await OtpToken.create({
        user: user._id,
        loginActivity:
          activity._id,
        adminOnly,
        codeHash:
          hashOtp(code),
        expiresAt:
          new Date(
            Date.now() +
              Number(
                process.env
                  .OTP_EXPIRES_MINUTES ||
                  10
              ) *
                60000
          ),
        deviceHash,
        ip,
        userAgent,
      });


    // ------------------------------------------------------
    // Send OTP
    // ------------------------------------------------------

    const {
      delivered,
    } = await sendEmail({
      to: user.email,
      subject:
        'Your Assure Docs verification code',

      text:
        `Your one-time passcode is ${code}. ` +
        `It expires in ${
          process.env
            .OTP_EXPIRES_MINUTES ||
          10
        } minutes. ` +
        `Reason for extra verification: ` +
        `${finalRisk.reasons.join('; ')}`,

      html:
        `<p>Your one-time passcode is ` +
        `<strong>${code}</strong>.</p>` +
        `<p>It expires in ${
          process.env
            .OTP_EXPIRES_MINUTES ||
          10
        } minutes.</p>` +
        `<p>Reason for extra verification: ` +
        `${finalRisk.reasons.join('; ')}</p>`,
    });


    loginAttemptsTotal.inc({
      outcome:
        'mfa_required',
      risk_level:
        finalRisk.level,
    });

    loginRiskScore.observe(
      finalRisk.score
    );


    return res.status(200).json({
      message:
        'A verification code has been sent to your email. Enter it to complete sign-in.',

      mfaRequired: true,

      loginId:
        otpDoc._id,

      ...(delivered
        ? {}
        : {
            devOtpCode: code,
          }),

      risk: {
        level:
          finalRisk.level,
        score:
          finalRisk.score,
        reasons:
          finalRisk.reasons,

        aiAssessment:
          aiRisk.score > 0
            ? aiRisk
            : null,
      },
    });

  } catch (err) {
    next(err);
  }
}


// ==========================================================
// VERIFY MFA
// ==========================================================

// @route POST /api/auth/verify-mfa
//
// Completes the login flow for medium/high-risk attempts.
async function verifyMfa(req, res, next) {
  try {
    const {
      loginId,
      code,
    } = req.body;


    const otpDoc =
      await OtpToken.findById(
        loginId
      ).populate(
        'loginActivity'
      );


    if (
      !otpDoc ||
      otpDoc.consumed ||
      otpDoc.expiresAt < new Date()
    ) {
      return res.status(400).json({
        message:
          'This code is invalid or has expired. Please sign in again.',
      });
    }


    if (
      otpDoc.attempts >=
      otpDoc.maxAttempts
    ) {
      return res.status(429).json({
        message:
          'Too many incorrect attempts. Please sign in again.',
      });
    }


    if (
      hashOtp(code) !==
      otpDoc.codeHash
    ) {
      otpDoc.attempts += 1;
      await otpDoc.save();

      return res.status(400).json({
        message:
          'Incorrect code, please try again.',
      });
    }


    otpDoc.consumed = true;

    await otpDoc.save();


    const user =
      await User.findById(
        otpDoc.user
      );


    if (!user) {
      return res.status(404).json({
        message:
          'User not found',
      });
    }


    // ------------------------------------------------------
    // Trust the successfully verified device.
    // ------------------------------------------------------

    user.trustedDevices.push({
      deviceHash:
        otpDoc.deviceHash,
      userAgent:
        otpDoc.userAgent,
      ip:
        otpDoc.ip,
    });

    user.lastLoginAt =
      new Date();

    await user.save();


    // ------------------------------------------------------
    // Mark login activity as successful.
    // ------------------------------------------------------

    if (
      otpDoc.loginActivity
    ) {
      otpDoc.loginActivity.mfaVerified =
        true;

      otpDoc.loginActivity.success =
        true;

      await otpDoc.loginActivity.save();
    }


    loginVerificationTotal.inc({
      outcome:
        'success',
    });


    // ------------------------------------------------------
    // Issue authentication tokens.
    // ------------------------------------------------------

    const token =
      generateAuthToken(
        user._id
      );

    setAuthCookie(
      res,
      token
    );

    await issueRefreshToken(
      res,
      user._id,
      {
        req,
      }
    );


    return res.json({
      message:
        'Verification successful, login complete.',
      token,
      user:
        user.toSafeObject(),
    });

  } catch (err) {
    next(err);
  }
}


// ==========================================================
// ADMIN SIGNUP
// ==========================================================

// @route POST /api/auth/admin-signup
async function adminSignup(req, res, next) {
  try {
    const {
      name,
      email,
      password,
      signupKey,
    } = req.body;

    const normalizedEmail =
      (email || '')
        .toLowerCase()
        .trim();


    if (
      !process.env.ADMIN_SIGNUP_KEY ||
      signupKey !==
        process.env.ADMIN_SIGNUP_KEY
    ) {
      return res.status(403).json({
        message:
          'Invalid administrator signup key.',
      });
    }


    if (
      !name ||
      !normalizedEmail ||
      !password
    ) {
      return res.status(400).json({
        message:
          'Name, email and password are required.',
      });
    }


    if (
      password.length < 8
    ) {
      return res.status(400).json({
        message:
          'Password must be at least 8 characters long.',
      });
    }


    const existing =
      await User.findOne({
        email:
          normalizedEmail,
      });


    if (existing) {
      return res.status(409).json({
        message:
          'An account with this email already exists.',
      });
    }


    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    const code =
      generateOtp();


    await OtpToken.updateMany(
      {
        email:
          normalizedEmail,
        purpose:
          'admin_signup',
        consumed:
          false,
      },
      {
        $set: {
          consumed: true,
        },
      }
    );


    const otpDoc =
      await OtpToken.create({
        email:
          normalizedEmail,
        name,
        passwordHash,
        purpose:
          'admin_signup',
        codeHash:
          hashOtp(code),
        expiresAt:
          new Date(
            Date.now() +
              Number(
                process.env
                  .ADMIN_OTP_EXPIRES_MINUTES ||
                  10
              ) *
                60000
          ),
        ip:
          getClientIp(req),
        userAgent:
          req.headers['user-agent'] ||
          'unknown',
      });


    const {
      delivered,
    } = await sendEmail({
      to:
        normalizedEmail,
      subject:
        'Assure Docs admin signup verification code',

      text:
        `Your Assure Docs administrator signup OTP is ${code}. ` +
        `It expires in ${
          process.env
            .ADMIN_OTP_EXPIRES_MINUTES ||
          10
        } minutes.`,

      html:
        `<div style="font-family:Arial,sans-serif">` +
        `<h2>Assure Docs Admin Signup</h2>` +
        `<p>Your verification code is:</p>` +
        `<p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p>` +
        `<p>This code expires in ${
          process.env
            .ADMIN_OTP_EXPIRES_MINUTES ||
          10
        } minutes.</p>` +
        `<p>If you did not request administrator access, ignore this email.</p>` +
        `</div>`,
    });


    return res.status(201).json({
      message:
        delivered
          ? 'Verification code sent to your Gmail/email address.'
          : 'SMTP is not configured. In development, the OTP is available below.',

      signupId:
        otpDoc._id,

      email:
        normalizedEmail,

      ...(delivered
        ? {}
        : {
            devOtpCode: code,
          }),
    });

  } catch (err) {
    next(err);
  }
}


// ==========================================================
// VERIFY ADMIN SIGNUP
// ==========================================================

// @route POST /api/auth/admin-signup/verify
async function verifyAdminSignup(
  req,
  res,
  next
) {
  try {
    const {
      signupId,
      code,
    } = req.body;


    const otpDoc =
      await OtpToken.findOne({
        _id:
          signupId,
        purpose:
          'admin_signup',
        consumed:
          false,
      }).select(
        '+passwordHash'
      );


    if (
      !otpDoc ||
      otpDoc.expiresAt < new Date()
    ) {
      return res.status(400).json({
        message:
          'This OTP is invalid or has expired. Please start signup again.',
      });
    }


    if (
      otpDoc.attempts >=
      otpDoc.maxAttempts
    ) {
      return res.status(429).json({
        message:
          'Too many incorrect attempts. Please start signup again.',
      });
    }


    if (
      hashOtp(
        String(code || '')
      ) !==
      otpDoc.codeHash
    ) {
      otpDoc.attempts += 1;
      await otpDoc.save();

      return res.status(400).json({
        message:
          'Incorrect OTP. Please try again.',
      });
    }


    const existing =
      await User.findOne({
        email:
          otpDoc.email,
      });


    if (existing) {
      otpDoc.consumed = true;
      await otpDoc.save();

      return res.status(409).json({
        message:
          'An account with this email already exists.',
      });
    }


    const user =
      await User.create({
        name:
          otpDoc.name,
        email:
          otpDoc.email,
        passwordHash:
          otpDoc.passwordHash,
        role:
          'admin',
        isVerified:
          true,
      });


    otpDoc.user =
      user._id;

    otpDoc.consumed =
      true;

    await otpDoc.save();


    return res.status(201).json({
      message:
        'Administrator account created and email verified successfully.',
      user:
        user.toSafeObject(),
    });

  } catch (err) {
    next(err);
  }
}


// ==========================================================
// LOGOUT
// ==========================================================

// @route POST /api/auth/logout
async function logout(req, res) {
  const rawToken =
    getRefreshToken(req);

  if (rawToken) {
    const tokenHash =
      require('crypto')
        .createHash('sha256')
        .update(rawToken)
        .digest('hex');

    await RefreshToken.updateOne(
      {
        tokenHash,
      },
      {
        revoked:
          true,
        revokedAt:
          new Date(),
      }
    ).exec();
  }

  clearAuthCookies(res);

  res.json({
    message:
      'Logged out',
  });
}


// ==========================================================
// REFRESH TOKEN
// ==========================================================

// @route POST /api/auth/refresh
async function refresh(req, res, next) {
  try {
    const rawToken =
      getRefreshToken(req);


    if (!rawToken) {
      return res.status(401).json({
        message:
          'Refresh token missing',
      });
    }


    const token =
      await RefreshToken.consume(
        rawToken
      );


    if (!token) {
      return res.status(401).json({
        message:
          'Invalid, expired, or revoked refresh token',
      });
    }


    const user =
      await User.findById(
        token.user
      );


    if (!user) {
      return res.status(401).json({
        message:
          'User no longer exists',
      });
    }


    const accessToken =
      generateAuthToken(
        user._id
      );

    setAuthCookie(
      res,
      accessToken
    );

    await issueRefreshToken(
      res,
      user._id,
      {
        req,
      }
    );


    res.json({
      token:
        accessToken,
      user:
        user.toSafeObject(),
    });

  } catch (err) {
    next(err);
  }
}


// ==========================================================
// CURRENT USER
// ==========================================================

// @route GET /api/auth/me
async function me(req, res) {
  res.json({
    user:
      req.user.toSafeObject(),
  });
}


// ==========================================================
// EXPORTS
// ==========================================================

module.exports = {
  register,
  verifySignup,
  verifyEmail,
  resendVerification,
  login,
  verifyMfa,
  adminSignup,
  verifyAdminSignup,
  refresh,
  logout,
  me,
};
```
