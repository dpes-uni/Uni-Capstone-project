/**
 * actionThresholds.js
 *
 * Action-specific risk thresholds.
 *
 * Different actions require different security responses:
 *   normal action     → standard threshold (RISK_HIGH_THRESHOLD, default 61)
 *   sensitive action  → stricter threshold (RISK_MEDIUM_THRESHOLD, default 30)
 *
 * Sensitive actions are those that modify system state or
 * expose protected data (document upload, verification changes).
 * Normal actions are read-only (document view, download).
 *
 * Unknown/unconfigured actions default to the standard (normal)
 * threshold so security is never silently disabled.
 *
 * All thresholds are derived from existing environment configuration
 * — no new magic numbers are introduced.
 */

// Actions that modify state or expose protected data.
// These require a stricter re-authentication threshold.
const SENSITIVE_ACTIONS = new Set([
  'document_uploaded',
  'verification_action',
]);

/**
 * Get the action-specific "high risk" threshold.
 *
 * @param {string|null|undefined} actionType - The event type from recordSessionEvent.
 * @returns {number} The risk score threshold for classifying a session as "high".
 */
function getActionHighThreshold(actionType) {
  // Unknown or unconfigured action: use the universal high threshold.
  // Security is never silently disabled — the default is the standard threshold.
  if (!actionType || !SENSITIVE_ACTIONS.has(actionType)) {
    return Number(process.env.RISK_HIGH_THRESHOLD ?? 61);
  }

  // Sensitive action: use the medium threshold as the high threshold.
  // This preserves the existing security intent: what would be a "medium"
  // risk on a normal action becomes a "high" risk (re-auth required) on a
  // sensitive action.
  return Number(process.env.RISK_MEDIUM_THRESHOLD ?? 30);
}

/**
 * Whether the given action type is classified as sensitive.
 *
 * @param {string} actionType
 * @returns {boolean}
 */
function isSensitiveAction(actionType) {
  return Boolean(actionType && SENSITIVE_ACTIONS.has(actionType));
}

module.exports = {
  SENSITIVE_ACTIONS,
  getActionHighThreshold,
  isSensitiveAction,
};
