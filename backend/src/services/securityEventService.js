/**
 * securityEventService — record structured security events.
 *
 * Failure-tolerant: never throws on DB failure. Always logs the failure
 * using the existing Winston logger so the audit gap is visible.
 */

const SecurityEvent = require('../models/SecurityEvent');
const logger = require('../utils/logger');

async function recordSecurityEvent(payload) {
  if (!payload || !payload.user || !payload.eventType) {
    logger.warn('Skipped security event: missing user or eventType', {
      hasUser: Boolean(payload?.user),
      hasEventType: Boolean(payload?.eventType),
    });
    return null;
  }

  try {
    const doc = await SecurityEvent.create({
      user: payload.user,
      eventType: payload.eventType,
      riskScore: payload.riskScore ?? null,
      riskLevel: payload.riskLevel ?? null,
      recommendedAction: payload.recommendedAction ?? null,
      reason: payload.reason ?? null,
      accumulatedRisk: payload.accumulatedRisk ?? null,
      contextChanges: payload.contextChanges || undefined,
      ip: payload.ip ?? null,
      userAgent: payload.userAgent ?? null,
    });
    return doc;
  } catch (error) {
    logger.error('Failed to record security event', {
      eventType: payload.eventType,
      user: String(payload.user),
      error: error.message,
    });
    return null;
  }
}

module.exports = { recordSecurityEvent };
