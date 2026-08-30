const aiService = require('./aiService');
const logger = require('../utils/logger');
const { hashToken } = require('../utils/generateToken');

const sessions = new Map();

const RAPID_ACTION_WINDOW_MS = 10_000;
const RAPID_ACTION_COUNT = 5;

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

  return sessions.get(key) || null;
}

function isHighRiskSession(riskResult) {
  if (!riskResult || typeof riskResult !== 'object') {
    return false;
  }

  const riskLevel = String(riskResult.risk_level || '').toLowerCase();
  const recommendedAction = String(riskResult.recommended_action || '');

  return (
    riskLevel === 'high' &&
    recommendedAction === 'Require Additional Verification'
  );
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

  const requiresReauthentication = isHighRiskSession(riskResult);

  if (requiresReauthentication) {
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

  return true;
}


/**
 * Get an existing monitored session or create one.
 */
function getOrCreateSession(req) {
  const key = getSessionKey(req);

  if (!key) {
    throw new Error('Authenticated request is required');
  }

  let session = sessions.get(key);

  if (!session) {
    session = {
      userId: key,
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
  };


  // --------------------------------------------------------
  // Send session event to Python AI
  // --------------------------------------------------------

  try {
    const riskResult =
      await aiService.assessSessionRisk(
        sessionData
      );

    const requiresReauthentication =
      updateSessionRiskState(
        session,
        riskResult
      );

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


module.exports = {
  sessions,
  recordSessionEvent,
  clearSession,
  clearSessionByUserId,
  clearSessionReauthentication,
  getSessionStatus,
  isSessionReauthenticationRequired: (req) =>
    Boolean(getSessionStatus(req)?.requiresReauthentication),
};
