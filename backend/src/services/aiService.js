const axios = require('axios');
const { getIpGeolocation } = require('./ipService');
const logger = require('../utils/logger');

/**
 * Service for communicating with the Python AI anomaly detection service.
 */
class AiService {
  constructor() {
    this.baseUrl = process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000';
    this.timeout = 5000; // 5 seconds timeout
  }

  /**
   * Extract device information from request headers.
   * @param {Object} req - Express request object
   * @returns {Object} Device information
   */
  extractDeviceInfo(req) {
    const userAgent = req.headers['user-agent'] || 'unknown';

    // Simple device/browser/OS detection
    let device = 'Unknown';
    let browser = 'Unknown';
    let operatingSystem = 'Unknown';

    // Detect operating system
    if (/windows/i.test(userAgent)) {
      operatingSystem = 'Windows';
    } else if (/macintosh|mac os x/i.test(userAgent)) {
      operatingSystem = 'MacOS';
    } else if (/linux/i.test(userAgent)) {
      operatingSystem = 'Linux';
    } else if (/android/i.test(userAgent)) {
      operatingSystem = 'Android';
    } else if (/ios|iphone|ipad|ipod/i.test(userAgent)) {
      operatingSystem = 'iOS';
    }

    // Detect browser
    if (/edg/i.test(userAgent)) {
      browser = 'Edge';
    } else if (/opr\//i.test(userAgent)) {
      browser = 'Opera';
    } else if (/chrome|crios/i.test(userAgent)) {
      browser = 'Chrome';
    } else if (/safari/i.test(userAgent)) {
      browser = 'Safari';
    } else if (/firefox|fxios/i.test(userAgent)) {
      browser = 'Firefox';
    }

    // Detect device type
    if (/mobile|android|iphone|ipad|ipod/i.test(userAgent)) {
      device = 'Mobile';
    } else if (/tablet|ipad|playbook|silk/i.test(userAgent)) {
      device = 'Tablet';
    } else {
      device = 'Desktop';
    }

    return { device, browser, operatingSystem };
  }

  /**
   * Convert backend login data to AI service LoginAttempt format.
   * @param {Object} user - User object from database
   * @param {string} deviceHash - Device fingerprint hash
   * @param {string} ip - IP address
   * @param {string} userAgent - User agent string
   * @param {Object} req - Express request object
   * @param {number} failedLoginAttempts - User's failed login attempts count
   * @returns {Promise<Object>} LoginAttempt data for AI service
   */
  async buildLoginAttempt(user, deviceHash, ip, userAgent, req, failedLoginAttempts = 0) {
    // Extract device information
    const { device, browser, operatingSystem } = this.extractDeviceInfo(req);

    // Get geolocation data
    const { country, city } = await getIpGeolocation(ip);

    // Determine if this is a new device
    const isNewDevice = !user.trustedDevices.some(d => d.deviceHash === deviceHash);

    // Determine if this is a trusted device (simplified)
    const isTrustedDevice = !isNewDevice; // In a real system, this might be more complex

    // Determine if this is a trusted location (simplified - would need to store user's trusted locations)
    const isTrustedLocation = false; // Placeholder - would need implementation

    // Determine if VPN is detected (simplified)
    const isVpnDetected = false; // Placeholder - would need VPN detection service

    // Get login hour
    const loginHour = new Date().getHours();

    return {
      username: user.email,
      device,
      browser,
      operating_system: operatingSystem,
      ip_address: ip,
      country,
      city,
      login_hour: loginHour,
      failed_login_attempts: failedLoginAttempts,
      new_device: isNewDevice,
      vpn_detected: isVpnDetected,
      trusted_device: isTrustedDevice,
      trusted_location: isTrustedLocation,
    };
  }

  /**
   * Call the AI service to get risk assessment for a login attempt.
   * @param {Object} loginAttemptData - Login attempt data in AI service format
   * @returns {Promise<Object>} Risk assessment result
   */
  async assessRisk(loginAttemptData) {
    try {
      const response = await axios.post(`${this.baseUrl}/predict`, loginAttemptData, {
        timeout: this.timeout,
        family: 4, // prefer IPv4 (Flask dev server binds IPv4 only; avoids ::1 flakiness)
        headers: {
          'Content-Type': 'application/json',
        },
      });

      return response.data;
    } catch (error) {
      logger.error('AI service call failed', { error: error.message });
      // Throw error to be handled by caller
      throw new Error(`AI service unavailable: ${error.message}`);
    }
  }

  /**
   * Check if AI service is healthy.
   * @returns {Promise<boolean>} True if service is healthy
   */
  async isHealthy() {
    try {
      const response = await axios.get(`${this.baseUrl}/health`, {
        timeout: this.timeout,
        family: 4, // prefer IPv4 (Flask dev server binds IPv4 only)
      });
      return response.data.status === 'healthy';
    } catch (error) {
      return false;
    }
  }
}

module.exports = new AiService();