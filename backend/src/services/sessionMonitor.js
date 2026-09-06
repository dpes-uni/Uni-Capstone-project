const aiService = require('./aiService');
const logger = require('../utils/logger');
const { hashToken, getClientIp } = require('../utils/generateToken');
const { getIpGeolocation, detectVpn } = require('./ipService');
const { recordSecurityEvent } = require('./securityEventService');

// In-memory session store keyed by userId.
// Each session holds both behavioural state and security baseline.
const sessions = new Map();

const RAPID_ACTION_WINDOW_MS = 10_000;
const RAPID_ACTION_COUNT = 5;

// Adaptive risk thresholds from environment configuration.
const RISK_HIGH_THRESHOLD = Number(process.env.RISK_HIGH_THRESHOLD ?? 61);
const RISK_CRITICAL_THRESHOLD = Number(process.env.RISK_CRITICAL_THRESHOLD ?? 81);

// Accumulation / decay tuning.
const SUSPICIOUS_EVENT_CONTRIBUTION = Number(
  process.env.SESSION_RISK_CONTRIBUTION ?? 15
);
const DECAY_PER_SECOND = Number(
  process.env.SESSION_RISK_DECAY_PER_SECOND ?? 0.05
);

// Step-up MFA verification window. How long a verified step-up token is
// valid for after the user successfully completes the OTP challenge.
const STEP_UP_VERIFY_WINDOW_MS = Number(
  process.env.STEP_UP_VERIFY_WINDOW_MS ?? 2 * 60 * 1000
);

function getRequestToken(req) {
  const authHeader = req?.headers?.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  if (req?.cookies?.token) {
    return req.cookies.token;
  }

  return null;
}

/**
 * Get the session key for an authenticated request.
 *
 * Priority: userId (stable across access-token refresh/rotation)
 *           > token hash (fallback for unauthenticated requests)
 *
 * Using the userId as the primary key means a session's risk state
 * survives access-token rotation via /auth/refresh. The token hash
 * is only used as a fallback when req.user is not yet available
 * (e.g. before JWT middleware has populated it).
 */
function getSessionKey(req) {
  if (req?.user?._id) {
    return `user:${req.user._id}`;
  }

  const token = getRequestToken(req);
  if (token) {
    return hashToken(token);
  }

  return null;
}

function getSessionStatus(req) {
  const key = getSessionKey(req);

  if (!key) {
    return null;
  }

  const session = sessions.get(key);
  if (session) {
    applyDecay(session);
  }
  return session || null;
}

function getRiskScore(riskResult) {
  const score = Number(riskResult?.risk_score);
  return Number.isFinite(score) ? score : 0;
}

function getRiskLevel(riskResult) {
  return String(riskResult?.risk_level || '').toLowerCase();
}

// Determine session risk from the AI result using configured thresholds.
function classifySessionRisk(riskResult) {
  if (!riskResult || typeof riskResult !== 'object') {
    return 'low';
  }

  const score = getRiskScore(riskResult);
  const level = getRiskLevel(riskResult);

  // Critical — strongest response.
  if (level === 'critical' || score >= RISK_CRITICAL_THRESHOLD) {
    return 'critical';
  }

  // High — require re-authentication.
  if (level === 'high' || score >= RISK_HIGH_THRESHOLD) {
    return 'high';
  }

  // Medium — use the existing elevated response.
  if (level === 'medium') {
    return 'medium';
  }

  return 'low';
}

function isHighRiskSession(riskResult) {
  return classifySessionRisk(riskResult) === 'high';
}

function isCriticalRiskSession(riskResult) {
  return classifySessionRisk(riskResult) === 'critical';
}

// Determine if a meaningful context change is present.
function hasMeaningfulContextChange(changes) {
  if (!changes) return false;
  return Boolean(
    changes.deviceChanged ||
    changes.browserChanged ||
    changes.osChanged ||
    changes.locationChanged ||
    changes.vpnChanged
  );
}

// Classify accumulated risk using the same thresholds.
function classifyAccumulatedRisk(accumulatedRisk) {
  if (accumulatedRisk >= RISK_CRITICAL_THRESHOLD) return 'critical';
  if (accumulatedRisk >= RISK_HIGH_THRESHOLD) return 'high';
  return 'low';
}

// Apply decay to the accumulated risk value.
function applyDecay(session) {
  if (!session.accumulatedRisk || !session.accumulatedRiskUpdatedAt) {
    return;
  }
  const elapsed = (Date.now() - session.accumulatedRiskUpdatedAt) / 1000;
  const decayed = session.accumulatedRisk - elapsed * DECAY_PER_SECOND;
  session.accumulatedRisk = Math.max(0, Math.min(100, decayed));
  session.accumulatedRiskUpdatedAt = Date.now();
}

// Accumulate suspicious risk contribution from a new event.
// Returns the updated accumulated risk value.
function accumulateRisk(session, riskResult) {
  applyDecay(session);
  const riskClass = classifySessionRisk(riskResult);
  if (riskClass === 'low' || session.requiresReauthentication) {
    return session.accumulatedRisk || 0;
  }
  // Only contribute when the session is not already flagged.
  session.accumulatedRisk = Math.min(100, (session.accumulatedRisk || 0) + SUSPICIOUS_EVENT_CONTRIBUTION);
  session.accumulatedRiskUpdatedAt = Date.now();
  return session.accumulatedRisk;
}

function updateSessionRiskState(session, riskResult) {
  session.lastRiskCheckedAt = new Date();
  session.lastRiskResult = riskResult || null;

  if (!riskResult) {
    session.riskDecision = session.requiresReauthentication
      ? 'reauth_required'
      : 'unknown';
    return session.requiresReauthentication;
  }

  // Accumulate from suspicious events (preserves AI result above).
  accumulateRisk(session, riskResult);

  const aiClass = classifySessionRisk(riskResult);
  const accumulatedClass = classifyAccumulatedRisk(session.accumulatedRisk || 0);

  // Highest class between AI and accumulated risk wins.
  const classOrder = { low: 0, medium: 1, high: 2, critical: 3 };
  const finalClass =
    classOrder[accumulatedClass] > classOrder[aiClass]
      ? accumulatedClass
      : aiClass;

  if (finalClass === 'high' || finalClass === 'critical') {
    session.requiresReauthentication = true;
    session.riskDecision = 'reauth_required';
  } else if (!session.requiresReauthentication) {
    session.requiresReauthentication = false;
    session.riskDecision = 'continue';
  }

  return session.requiresReauthentication;
}

function clearSessionReauthentication(req) {
  const session = getSessionStatus(req);

  if (!session) {
    return false;
  }

  session.requiresReauthentication = false;
  session.lastRiskResult = null;
  session.lastRiskCheckedAt = null;
  session.riskDecision = 'continue';
  session.actionTimestamps = [];
  session.failedActions = 0;
  session.accumulatedRisk = 0;
  session.accumulatedRiskUpdatedAt = null;

  return true;
}


/**
 * Get an existing monitored session or create one.
 * New sessions automatically establish a security baseline.
 */
function getOrCreateSession(req) {
  const key = getSessionKey(req);

  if (!key) {
    throw new Error('Authenticated request is required');
  }

  let session = sessions.get(key);

  if (!session) {
    session = {
      userId: req.user._id,
      username: req.user.email,
      userRole: req.user.role,

      startedAt: Date.now(),

      documentsViewed: 0,
      documentsDownloaded: 0,
      documentsUploaded: 0,
      verificationActions: 0,
      failedActions: 0,

      actionTimestamps: [],
      requiresReauthentication: false,
      lastRiskResult: null,
      lastRiskCheckedAt: null,
      riskDecision: 'unknown',
      accumulatedRisk: 0,
      accumulatedRiskUpdatedAt: null,

      // Security baseline captured at session start (for context-change detection).
      // Populated asynchronously by establishSessionBaseline().
      securityBaseline: null,
    };

    sessions.set(key, session);
  }

  return session;
}


/**
 * Record an action timestamp and determine whether
 * the current activity qualifies as rapid activity.
 */
function recordAction(session, now) {
  session.actionTimestamps.push(now);

  const cutoff =
    now - RAPID_ACTION_WINDOW_MS;

  session.actionTimestamps =
    session.actionTimestamps.filter(
      (timestamp) =>
        timestamp >= cutoff
    );

  return (
    session.actionTimestamps.length >=
    RAPID_ACTION_COUNT
  );
}


/**
 * Record a meaningful authenticated-session event.
 *
 * Supported events:
 *
 *   document_viewed
 *   document_downloaded
 *   document_uploaded
 *   verification_action
 *   failed_action
 *
 * The Node backend does NOT determine unusual_activity.
 * The Python SessionPredictor remains responsible for
 * detecting unusual behaviour.
 */
async function recordSessionEvent(
  req,
  eventType
) {
  if (!req || !req.user) {
    throw new Error(
      'Authenticated request is required'
    );
  }


  const session =
    getOrCreateSession(req);

  const now = Date.now();


  // --------------------------------------------------------
  // Update session counters
  // --------------------------------------------------------

  switch (eventType) {
    case 'document_viewed':
      session.documentsViewed += 1;
      break;

    case 'document_downloaded':
      session.documentsDownloaded += 1;
      break;

    case 'document_uploaded':
      session.documentsUploaded += 1;
      break;

    case 'verification_action':
      session.verificationActions += 1;
      break;

    case 'failed_action':
      session.failedActions += 1;
      break;

    default:
      throw new Error(
        `Unsupported session event: ${eventType}`
      );
  }


  // --------------------------------------------------------
  // Rapid-action detection
  // --------------------------------------------------------

  const rapidActions =
    recordAction(
      session,
      now
    );


  // --------------------------------------------------------
  // Capture current session context and compare to baseline
  // --------------------------------------------------------

  const currentContext = await captureSessionContext(req);

  // Establish baseline on first interaction if not yet set.
  if (!session.securityBaseline) {
    session.securityBaseline = currentContext;
  }

  const contextChanges = compareSessionContext(
    session.securityBaseline,
    currentContext
  );

  // Record meaningful context change.
  if (hasMeaningfulContextChange(contextChanges)) {
    recordSecurityEvent({
      user: session.userId,
      eventType: 'CONTEXT_CHANGE',
      contextChanges,
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'],
    }).catch(() => {});
  }

  // --------------------------------------------------------
  // Build Python SessionEvent
  // --------------------------------------------------------

  const sessionData = {
    username:
      session.username,

    userRole:
      session.userRole,

    sessionDurationMinutes:
      Math.max(
        0,
        Math.floor(
          (now - session.startedAt) /
            60000
        )
      ),

    documentsViewed:
      session.documentsViewed,

    documentsDownloaded:
      session.documentsDownloaded,

    documentsUploaded:
      session.documentsUploaded,

    verificationActions:
      session.verificationActions,

    failedActions:
      session.failedActions,

    rapidActions,

    // The live Node backend does not determine
    // whether behaviour is unusual.
    //
    // This remains false for compatibility with
    // the current Python SessionEvent contract.
    unusualActivity: false,

    // Context-change signals for the session AI.
    contextChanges,
  };


  // --------------------------------------------------------
  // Send session event to Python AI
  // --------------------------------------------------------

  try {
    const riskResult =
      await aiService.assessSessionRisk(
        sessionData
      );

    const wasAlreadyReauthRequired = session.requiresReauthentication;
    const requiresReauthentication =
      updateSessionRiskState(
        session,
        riskResult
      );

    // Record threshold + re-auth events only on the transition edge.
    if (!wasAlreadyReauthRequired && requiresReauthentication) {
      const aiClass = classifySessionRisk(riskResult);
      if (aiClass === 'high' || aiClass === 'critical') {
        recordSecurityEvent({
          user: session.userId,
          eventType: 'RISK_THRESHOLD_REACHED',
          riskScore: riskResult.risk_score,
          riskLevel: riskResult.risk_level,
          recommendedAction: riskResult.recommended_action,
          reason: riskResult.reason,
          accumulatedRisk: session.accumulatedRisk,
          ip: getClientIp(req),
          userAgent: req.headers['user-agent'],
        }).catch(() => {});
      }
      recordSecurityEvent({
        user: session.userId,
        eventType: 'REAUTH_REQUIRED',
        riskScore: riskResult.risk_score,
        riskLevel: riskResult.risk_level,
        accumulatedRisk: session.accumulatedRisk,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'],
      }).catch(() => {});
    }

    const logPayload = {
      user:
        session.username,

      event:
        eventType,

      riskLevel:
        riskResult.risk_level,

      riskScore:
        riskResult.risk_score,

      recommendedAction:
        riskResult.recommended_action,

      accumulatedRisk:
        session.accumulatedRisk,

      requiresReauthentication,
    };

    if (requiresReauthentication) {
      logger.warn(
        'Active session marked for re-authentication',
        logPayload
      );
    } else {
      logger.info(
        'Active session risk assessed',
        logPayload
      );
    }

    return {
      sessionData,
      riskResult,
      requiresReauthentication,
      riskDecision:
        session.riskDecision,
      accumulatedRisk:
        session.accumulatedRisk,
    };

  } catch (error) {
    /**
     * Session monitoring must not break an otherwise valid
     * document operation merely because the AI service is
     * temporarily unavailable.
     *
     * Enforcement/fail-safe behaviour will be handled by
     * the session re-authentication layer in P1.
     */

    logger.warn(
      'Active session AI assessment unavailable',
      {
        user:
          session.username,

        event:
          eventType,

        error:
          error.message,
      }
    );


    return {
      sessionData,
      riskResult: null,
      requiresReauthentication:
        Boolean(session.requiresReauthentication),
      riskDecision: session.riskDecision,
      accumulatedRisk:
        session.accumulatedRisk,
    };
  }
}


/**
 * Remove the monitored session.
 *
 * This will be called when the user logs out or when the
 * session is otherwise terminated.
 */
function clearSession(req) {
  const key = getSessionKey(req);

  if (key) {
    sessions.delete(key);
  }
}

// ================================================================
// Session Context Baseline
// ================================================================

/**
 * Capture the security context from the current request.
 * Uses the existing aiService device extraction and ipService geolocation.
 */
async function captureSessionContext(req) {
  const ip = getClientIp(req);

  // Device info from User-Agent parsing (already used by aiService)
  const { device, browser, operatingSystem } = aiService.extractDeviceInfo(req);

  // Geolocation
  const geo = await getIpGeolocation(ip);

  // VPN detection from org/ASN
  const vpnDetected = detectVpn({ org: geo.org, asn: geo.asn });

  return {
    device,
    browser,
    operatingSystem,
    ip,
    country: geo.country,
    city: geo.city,
    vpnDetected,
    loginAt: Date.now(),
  };
}

/**
 * Compare current context against baseline and return explicit change flags.
 */
function compareSessionContext(baseline, current) {
  const noChange = {
    deviceChanged: false,
    browserChanged: false,
    osChanged: false,
    ipChanged: false,
    locationChanged: false,
    vpnChanged: false,
  };

  if (!baseline || !current) {
    return noChange;
  }

  return {
    deviceChanged: current.device !== baseline.device,
    browserChanged: current.browser !== baseline.browser,
    osChanged: current.operatingSystem !== baseline.operatingSystem,
    // IP changes are common with mobile/carrier networks. Flag only when
    // the country also changes, or when VPN status flips.
    ipChanged: current.ip !== baseline.ip && current.country !== baseline.country,
    locationChanged: current.country !== baseline.country,
    vpnChanged: current.vpnDetected !== baseline.vpnDetected,
  };
}

/**
 * Establish the security baseline for a session.
 * Called once when the session is first created (after MFA verification).
 */
async function establishSessionBaseline(req) {
  const key = getSessionKey(req);
  if (!key) return;

  const session = sessions.get(key);
  if (!session) return;

  session.securityBaseline = await captureSessionContext(req);
}

/**
 * Remove a monitored session by user id directly.
 *
 * Used when a user completes a brand-new login or logs out, so that
 * any stale "requires re-authentication" flag from a previous session
 * does not survive into the new authenticated session.
 */
function clearSessionByUserId(userId) {
  if (!userId) {
    return false;
  }

  const key = `user:${userId}`;
  return sessions.delete(key);
}

// Refresh the trusted baseline after a successful re-authentication.
// Captures the current verified context, resets risk state, and installs
// the captured context as the new baseline. No-op if no session exists.
async function refreshSessionBaselineAfterReauth(req) {
  const key = getSessionKey(req);
  if (!key) return false;

  const session = sessions.get(key);
  if (!session) return false;

  const verifiedContext = await captureSessionContext(req);
  const previousBaseline = session.securityBaseline;
  clearSessionReauthentication(req);
  session.securityBaseline = verifiedContext;

  // Record successful re-authentication.
  recordSecurityEvent({
    user: session.userId,
    eventType: 'REAUTH_SUCCESS',
    ip: getClientIp(req),
    userAgent: req.headers['user-agent'],
  }).catch(() => {});

  return true;
}


// ---------------------------------------------------------------------------
// Step-up MFA verification state.
//
// Step-up verification is a separate, action-level control from the risk-based
// reauthentication flag. A user with a valid JWT can still be challenged to
// provide a fresh OTP for a sensitive action, regardless of session risk.
//
// stepUpVerified is written to the same in-memory session object as
// requiresReauthentication. It is single-use (consumed before next()) and
// short-lived (STEP_UP_VERIFY_WINDOW_MS, default 2 minutes). Establishing
// step-up verification does NOT clear requiresReauthentication — that flag
// remains under the control of /auth/reauth/verify.
// ---------------------------------------------------------------------------

function establishStepUpVerification(req, opts = {}) {
  const key = getSessionKey(req);
  if (!key) return null;

  const session = sessions.get(key) || {};
  const now = Date.now();
  const expiresAt = now + STEP_UP_VERIFY_WINDOW_MS;
  const verifiedAt = now;

  session.stepUpVerified = {
    purpose: 'stepup',
    verifiedAt: new Date(verifiedAt),
    expiresAt: new Date(expiresAt),
  };

  if (!sessions.has(key)) {
    sessions.set(key, session);
  }

  if (opts.persist !== false && req?.headers) {
    recordSecurityEvent({
      user: req.user?._id || null,
      eventType: 'STEP_UP_VERIFIED',
      reason: 'Step-up MFA verification completed.',
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'],
    }).catch(() => {});
  }

  return session.stepUpVerified;
}

function consumeStepUpVerification(req) {
  const session = getSessionStatus(req);
  if (!session || !session.stepUpVerified) return null;

  const verification = session.stepUpVerified;
  delete session.stepUpVerified;
  return verification;
}

function clearStepUpVerification(req) {
  const session = getSessionStatus(req);
  if (!session) return false;
  if (!session.stepUpVerified) return false;
  delete session.stepUpVerified;
  return true;
}

function isStepUpVerificationValid(req) {
  const session = getSessionStatus(req);
  if (!session || !session.stepUpVerified) return false;
  const expiresAt = new Date(session.stepUpVerified.expiresAt).getTime();
  return expiresAt > Date.now();
}

function isStepUpVerificationRequired(req) {
  // Risk-based re-authentication takes precedence — its flow is responsible
  // for clearing that flag, so step-up is a no-op while it is pending.
  if (isSessionReauthenticationRequired(req)) return false;
  return !isStepUpVerificationValid(req);
}


module.exports = {
  sessions,
  recordSessionEvent,
  clearSession,
  clearSessionByUserId,
  clearSessionReauthentication,
  getSessionStatus,
  establishSessionBaseline,
  captureSessionContext,
  compareSessionContext,
  classifySessionRisk,
  classifyAccumulatedRisk,
  getRiskScore,
  getRiskLevel,
  isHighRiskSession,
  isCriticalRiskSession,
  applyDecay,
  accumulateRisk,
  refreshSessionBaselineAfterReauth,
  isSessionReauthenticationRequired: (req) =>
    Boolean(getSessionStatus(req)?.requiresReauthentication),
  // Step-up MFA helpers
  establishStepUpVerification,
  consumeStepUpVerification,
  clearStepUpVerification,
  isStepUpVerificationValid,
  isStepUpVerificationRequired,
  STEP_UP_VERIFY_WINDOW_MS,
};
