const axios = require('axios');
const { getIpGeolocation, detectVpn } = require('./ipService');
const LoginActivity = require('../models/LoginActivity');
const logger = require('../utils/logger');

/**
 * The Python service performs risk assessment.
 * The Node.js backend is responsible for enforcing
 * authentication and re-authentication decisions.
 */
class AiService {
  constructor() {
    this.baseUrl =
      process.env.AI_SERVICE_URL ||
      'http://127.0.0.1:8000';

    this.timeout = 5000;
  }


  // ========================================================
  // DEVICE INFORMATION
  // ========================================================

  /**
   * Extract basic device, browser and operating-system
   * information from the request User-Agent.
   *
   * @param {Object} req Express request object
   * @returns {Object} Device information
   */
  extractDeviceInfo(req) {
    const userAgent =
      req?.headers?.['user-agent'] ||
      'unknown';

    let device = 'Unknown';
    let browser = 'Unknown';
    let operatingSystem = 'Unknown';


    // ------------------------------------------------------
    // Operating system
    // ------------------------------------------------------

    if (/windows/i.test(userAgent)) {
      operatingSystem = 'Windows';
    } else if (
      /macintosh|mac os x/i.test(userAgent)
    ) {
      operatingSystem = 'MacOS';
    } else if (/android/i.test(userAgent)) {
      operatingSystem = 'Android';
    } else if (
      /iphone|ipad|ipod|ios/i.test(userAgent)
    ) {
      operatingSystem = 'iOS';
    } else if (/linux/i.test(userAgent)) {
      operatingSystem = 'Linux';
    }


    // ------------------------------------------------------
    // Browser
    // ------------------------------------------------------

    if (/edg/i.test(userAgent)) {
      browser = 'Edge';
    } else if (/opr\//i.test(userAgent)) {
      browser = 'Opera';
    } else if (
      /chrome|crios/i.test(userAgent)
    ) {
      browser = 'Chrome';
    } else if (
      /firefox|fxios/i.test(userAgent)
    ) {
      browser = 'Firefox';
    } else if (/safari/i.test(userAgent)) {
      browser = 'Safari';
    }


    // ------------------------------------------------------
    // Device type
    // ------------------------------------------------------

    if (
      /tablet|ipad|playbook|silk/i.test(
        userAgent
      )
    ) {
      device = 'Tablet';
    } else if (
      /mobile|android|iphone|ipod/i.test(
        userAgent
      )
    ) {
      device = 'Mobile';
    } else {
      device = 'Desktop';
    }


    return {
      device,
      browser,
      operatingSystem,
    };
  }


  // ========================================================
  // LOGIN AI
  // ========================================================

  /**
   * Build the LoginAttempt payload expected by Python.
   *
   * @param {Object} user User document
   * @param {string} deviceHash Device fingerprint
   * @param {string} ip Client IP
   * @param {string} userAgent User-Agent
   * @param {Object} req Express request
   * @param {number} failedLoginAttempts Failed login attempts
   * @returns {Promise<Object>} LoginAttempt payload
   */
  async buildLoginAttempt(
    user,
    deviceHash,
    ip,
    userAgent,
    req,
    failedLoginAttempts = 0
  ) {
    if (!user) {
      throw new Error(
        'User is required to build a login attempt'
      );
    }

    if (!req) {
      throw new Error(
        'Request is required to build a login attempt'
      );
    }

    const {
      device,
      browser,
      operatingSystem,
    } = this.extractDeviceInfo(req);


    // ------------------------------------------------------
    // IP geolocation
    // ------------------------------------------------------

    const {
      country,
      city,
      org,
      asn,
    } = await getIpGeolocation(ip);


    // ------------------------------------------------------
    // Trusted device
    // ------------------------------------------------------

    const trustedDevices =
      Array.isArray(user.trustedDevices)
        ? user.trustedDevices
        : [];

    const isNewDevice =
      !trustedDevices.some(
        (entry) =>
          entry.deviceHash === deviceHash
      );

    const isTrustedDevice =
      !isNewDevice;


    // ------------------------------------------------------
    // VPN / proxy detection
    //
    // Best-effort heuristic based on the IP's owning
    // organisation / ASN. Without a commercial VPN feed this
    // is not definitive, but it surfaces the common anonymiser
    // networks instead of always reporting false.
    // ------------------------------------------------------

    const isVpnDetected = detectVpn({ org, asn });


    // ------------------------------------------------------
    // Trusted location
    //
    // A location is trusted when the user has successfully
    // logged in from that country before. On first login there
    // is no baseline, so we treat the location as trusted
    // (the login still goes through MFA regardless).
    // ------------------------------------------------------

    let isTrustedLocation = true;

    try {
      const knownCountries = await LoginActivity.distinct(
        'country',
        {
          user: user._id,
          success: true,
          mfaVerified: true,
          country: { $nin: [null, 'Unknown'] },
        }
      );

      if (knownCountries.length > 0) {
        isTrustedLocation = knownCountries.includes(country);
      }
    } catch (historyError) {
      logger.warn(
        'trusted-location history lookup failed; defaulting to untrusted',
        { error: historyError.message }
      );
      isTrustedLocation = false;
    }


    // ------------------------------------------------------
    // Login hour
    // ------------------------------------------------------

    const loginHour =
      new Date().getHours();


    return {
      username: user.email,

      device,

      browser,

      operating_system:
        operatingSystem,

      ip_address:
        ip,

      country,

      city,

      login_hour:
        loginHour,

      failed_login_attempts:
        Number(failedLoginAttempts),

      new_device:
        Boolean(isNewDevice),

      vpn_detected:
        Boolean(isVpnDetected),

      trusted_device:
        Boolean(isTrustedDevice),

      trusted_location:
        Boolean(isTrustedLocation),
    };
  }


  /**
   * Call Python Login Risk AI.
   *
   * Endpoint:
   *   POST /predict
   *
   * @param {Object} loginAttemptData LoginAttempt payload
   * @returns {Promise<Object>} Python RiskResult
   */
  async assessRisk(loginAttemptData) {
    if (
      !loginAttemptData ||
      typeof loginAttemptData !== 'object'
    ) {
      throw new Error(
        'Invalid login AI request data'
      );
    }

    try {
      const response =
        await axios.post(
          `${this.baseUrl}/predict`,
          loginAttemptData,
          {
            timeout:
              this.timeout,

            // Flask is currently bound to IPv4.
            family: 4,

            headers: {
              'Content-Type':
                'application/json',
            },
          }
        );


      const result =
        response.data;


      this.validateRiskResult(
        result,
        'login'
      );


      return result;

    } catch (error) {
      logger.error(
        'AI login risk service call failed',
        {
          error:
            error.message,
        }
      );

      throw new Error(
        `AI service unavailable: ${error.message}`
      );
    }
  }


  // ========================================================
  // ACTIVE SESSION AI
  // ========================================================

  /**
   * Build the SessionEvent payload expected by Python.
   *
   * Expected Python fields:
   *
   *   username
   *   user_role
   *   session_duration_minutes
   *   documents_viewed
   *   documents_downloaded
   *   documents_uploaded
   *   verification_actions
   *   failed_actions
   *   rapid_actions
   *   unusual_activity
   *
   * IMPORTANT:
   *
   * The live Node.js backend should collect behavioural
   * features. It should not independently decide whether
   * behaviour is unusual.
   *
   * `unusual_activity` therefore remains optional and
   * defaults to false only for compatibility with the
   * current Python SessionEvent contract and existing
   * prediction endpoint.
   *
   * @param {Object} sessionData Session activity data
   * @returns {Object} SessionEvent payload
   */
  buildSessionEvent(sessionData = {}) {
    if (
      !sessionData ||
      typeof sessionData !== 'object'
    ) {
      throw new Error(
        'Invalid session data'
      );
    }


    const {
      username,
      userRole,

      sessionDurationMinutes,

      documentsViewed,
      documentsDownloaded,
      documentsUploaded,
      verificationActions,

      failedActions,
      rapidActions,

      unusualActivity,
    } = sessionData;


    // ------------------------------------------------------
    // Required identity information
    // ------------------------------------------------------

    if (
      typeof username !== 'string' ||
      username.trim().length === 0
    ) {
      throw new Error(
        'Session username is required'
      );
    }


    if (
      typeof userRole !== 'string' ||
      userRole.trim().length === 0
    ) {
      throw new Error(
        'Session user role is required'
      );
    }


    // ------------------------------------------------------
    // Numeric feature validation
    // ------------------------------------------------------

    const numericFields = {
      sessionDurationMinutes,
      documentsViewed,
      documentsDownloaded,
      documentsUploaded,
      verificationActions,
      failedActions,
    };


    for (
      const [field, value]
      of Object.entries(numericFields)
    ) {
      if (
        value === undefined ||
        value === null ||
        !Number.isFinite(
          Number(value)
        ) ||
        Number(value) < 0
      ) {
        throw new Error(
          `${field} must be a non-negative number`
        );
      }
    }


    // ------------------------------------------------------
    // Boolean feature validation
    // ------------------------------------------------------

    if (
      rapidActions !== undefined &&
      typeof rapidActions !== 'boolean'
    ) {
      throw new Error(
        'rapidActions must be a boolean'
      );
    }


    if (
      unusualActivity !== undefined &&
      typeof unusualActivity !== 'boolean'
    ) {
      throw new Error(
        'unusualActivity must be a boolean'
      );
    }


    // ------------------------------------------------------
    // Build Python-compatible payload
    // ------------------------------------------------------

    return {
      username:
        username.trim(),

      user_role:
        userRole.trim(),

      session_duration_minutes:
        Number(
          sessionDurationMinutes
        ),

      documents_viewed:
        Number(
          documentsViewed
        ),

      documents_downloaded:
        Number(
          documentsDownloaded
        ),

      documents_uploaded:
        Number(
          documentsUploaded
        ),

      verification_actions:
        Number(
          verificationActions
        ),

      failed_actions:
        Number(
          failedActions
        ),

      rapid_actions:
        rapidActions === true,

      // Compatibility with the current Python
      // SessionEvent contract.
      //
      // The live backend should not calculate this value.
      unusual_activity:
        unusualActivity === true,
    };
  }


  /**
   * Call Python Session Monitoring AI.
   *
   * Endpoint:
   *   POST /predict-session
   *
   * @param {Object} sessionData Session activity data
   * @returns {Promise<Object>} Python RiskResult
   */
  async assessSessionRisk(sessionData) {
    const sessionEvent =
      this.buildSessionEvent(
        sessionData
      );


    try {
      const response =
        await axios.post(
          `${this.baseUrl}/predict-session`,
          sessionEvent,
          {
            timeout:
              this.timeout,

            // Flask is currently bound to IPv4.
            family: 4,

            headers: {
              'Content-Type':
                'application/json',
            },
          }
        );


      const result =
        response.data;


      this.validateRiskResult(
        result,
        'session'
      );


      return result;

    } catch (error) {
      logger.error(
        'AI session risk service call failed',
        {
          error:
            error.message,
        }
      );

      throw new Error(
        `AI session service unavailable: ${error.message}`
      );
    }
  }


  // ========================================================
  // RISK RESULT VALIDATION
  // ========================================================

  /**
   * Validate the common RiskResult returned by Python.
   *
   * Expected structure:
   *
   * {
   *   risk_score: number,
   *   risk_level: string,
   *   recommended_action: string,
   *   reason: string
   * }
   *
   * @param {Object} result Python response
   * @param {string} source login/session
   */
  validateRiskResult(
    result,
    source
  ) {
    if (
      !result ||
      typeof result !== 'object'
    ) {
      throw new Error(
        `Invalid ${source} AI response`
      );
    }


    if (
      !Number.isFinite(
        Number(result.risk_score)
      )
    ) {
      throw new Error(
        `Invalid ${source} AI risk score`
      );
    }


    if (
      typeof result.risk_level !==
      'string' ||
      result.risk_level.trim()
        .length === 0
    ) {
      throw new Error(
        `Invalid ${source} AI risk level`
      );
    }


    if (
      typeof result.recommended_action !==
      'string' ||
      result.recommended_action
        .trim()
        .length === 0
    ) {
      throw new Error(
        `Invalid ${source} AI recommended action`
      );
    }


    if (
      typeof result.reason !==
      'string'
    ) {
      throw new Error(
        `Invalid ${source} AI reason`
      );
    }
  }


  // ========================================================
  // AI HEALTH CHECK
  // ========================================================

  /**
   * Check whether the Python AI service is healthy.
   *
   * Endpoint:
   *   GET /health
   *
   * @returns {Promise<boolean>} Service health status
   */
  async isHealthy() {
    try {
      const response =
        await axios.get(
          `${this.baseUrl}/health`,
          {
            timeout:
              this.timeout,

            // Flask is currently bound to IPv4.
            family: 4,
          }
        );


      return (
        response.data &&
        response.data.status ===
          'healthy'
      );

    } catch (error) {
      return false;
    }
  }
}


// ==========================================================
// SINGLE SERVICE INSTANCE
// ==========================================================

module.exports =
  new AiService();
