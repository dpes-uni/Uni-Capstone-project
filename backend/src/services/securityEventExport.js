/**
 * securityEventExport — export persisted SecurityEvent records for
 * evaluation purposes (CSV and JSON).
 *
 * Exports only evaluation-relevant, system-generated fields plus a stable
 * event_id derived from the persisted MongoDB _id. Sensitive authentication
 * values and identity fields are never included.
 *
 * ground_truth is always exported as null and is never calculated or inferred
 * from any system-generated risk field.
 */

const SecurityEvent = require('../models/SecurityEvent');

const SENSITIVE_FIELDS = [
  'password',
  'otp',
  'token',
  'refreshToken',
  'secret',
  'code',
];

// Fields exported in evaluation exports.
const EXPORT_FIELDS = [
  'event_id',
  'createdAt',
  'timestamp',
  'eventType',
  'riskScore',
  'riskLevel',
  'recommendedAction',
  'reason',
  'accumulatedRisk',
  'contextChanges',
  'ground_truth',
];

/**
 * Build a MongoDB filter query from optional filters.
 */
function buildQuery(filters = {}) {
  const query = {};

  if (filters.eventType) {
    query.eventType = filters.eventType;
  }

  if (filters.since || filters.until) {
    query.createdAt = {};
    if (filters.since) {
      query.createdAt.$gte = new Date(filters.since);
    }
    if (filters.until) {
      query.createdAt.$lte = new Date(filters.until);
    }
  }

  return query;
}

/**
 * Find persisted SecurityEvent documents matching the optional filters.
 * Returns a Promise resolving to an array of documents.
 */
async function findEvents(filters = {}) {
  const query = buildQuery(filters);
  let q = SecurityEvent.find(query).sort({ createdAt: 1 });
  if (filters.limit) {
    q = q.limit(filters.limit);
  }
  return q.exec();
}

/**
 * Map a persisted document to the evaluation-export shape.
 * event_id is derived from the persisted MongoDB _id.
 */
function mapToExport(doc) {
  const obj = doc.toObject ? doc.toObject() : doc;
  return {
    event_id: String(obj._id),
    createdAt: obj.createdAt,
    timestamp: obj.createdAt,
    eventType: obj.eventType,
    riskScore: obj.riskScore,
    riskLevel: obj.riskLevel,
    recommendedAction: obj.recommendedAction,
    reason: obj.reason,
    accumulatedRisk: obj.accumulatedRisk,
    contextChanges: obj.contextChanges,
    ground_truth: null,
  };
}

/**
 * Escape a single CSV field value.
 */
function escapeCSV(value) {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

/**
 * Export matching SecurityEvent records as a CSV string.
 * Includes a header row followed by data rows.
 */
async function exportCSV(filters = {}) {
  const docs = await findEvents(filters);
  const rows = docs.map(mapToExport);

  if (rows.length === 0) {
    return EXPORT_FIELDS.map(escapeCSV).join(',');
  }

  const header = EXPORT_FIELDS.map(escapeCSV).join(',');
  const lines = rows.map((row) =>
    EXPORT_FIELDS.map((field) => escapeCSV(row[field])).join(',')
  );

  return [header, ...lines].join('\n');
}

/**
 * Export matching SecurityEvent records as a JSON string.
 */
async function exportJSON(filters = {}) {
  const docs = await findEvents(filters);
  return JSON.stringify(docs.map(mapToExport), null, 2);
}

module.exports = {
  exportCSV,
  exportJSON,
  findEvents,
  mapToExport,
  buildQuery,
  EXPORT_FIELDS,
};
