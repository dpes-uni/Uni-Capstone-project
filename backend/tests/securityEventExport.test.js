/**
 * Focused tests for securityEventExport (Category 6B, Option A).
 *
 * Covers CSV export, JSON export, stable event_id, ground_truth handling,
 * sensitive field exclusion, filtering, and empty result handling.
 *
 * The SecurityEvent model is mocked — no database is required.
 */

jest.mock('../src/models/SecurityEvent', () => ({
  find: jest.fn(),
}));

const SecurityEvent = require('../src/models/SecurityEvent');
const {
  exportCSV,
  exportJSON,
  findEvents,
  mapToExport,
  buildQuery,
  EXPORT_FIELDS,
} = require('../src/services/securityEventExport');

const SAMPLE_DOC = {
  _id: '65000000000000000000000a',
  eventType: 'CONTEXT_CHANGE',
  riskScore: 30,
  riskLevel: 'medium',
  recommendedAction: 'Verify identity',
  reason: 'location changed',
  accumulatedRisk: 15,
  contextChanges: { ipChanged: true, locationChanged: true },
  createdAt: '2026-09-19T10:00:00.000Z',
  // Fields that must NEVER appear in exports.
  user: 'u1',
  ip: '1.2.3.4',
  userAgent: 'TestAgent/1.0',
  password: 'hunter2',
  otp: '123456',
  token: 'abc123',
  secret: 'topsecret',
  code: '9999',
};

const mockChain = (docs) => {
  const exec = jest.fn().mockResolvedValue(docs);
  SecurityEvent.find.mockImplementation((query) => {
    const filtered = query && query.eventType
      ? docs.filter((d) => d.eventType === query.eventType)
      : docs;
    return {
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue(filtered),
    };
  });
  return exec;
};

const exportedKeys = (obj) => Object.keys(JSON.parse(JSON.stringify(obj)));

// Minimal CSV-aware row parser (handles quoted fields containing commas).
const parseCSVRow = (row) => {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < row.length; i++) {
    const c = row[i];
    if (inQuotes) {
      if (c === '"') {
        if (row[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = false;
      } else { cur += c; }
    } else if (c === '"') { inQuotes = true; }
    else if (c === ',') { fields.push(cur); cur = ''; }
    else { cur += c; }
  }
  fields.push(cur);
  return fields;
};

describe('securityEventExport', () => {
  beforeEach(() => {
    SecurityEvent.find.mockClear();
  });

  // ---- stable event_id ----------------------------------------------------
  test('event_id is derived from the persisted MongoDB _id', () => {
    const mapped = mapToExport(SAMPLE_DOC);
    expect(mapped.event_id).toBe(String(SAMPLE_DOC._id));
  });

  test('event_id is stable across repeated export of the same record', async () => {
    mockChain([SAMPLE_DOC]);
    const out1 = await exportJSON();
    const out2 = await exportJSON();
    const doc1 = JSON.parse(out1)[0];
    const doc2 = JSON.parse(out2)[0];
    expect(doc1.event_id).toBe(doc2.event_id);
    expect(doc1.event_id).toBe(String(SAMPLE_DOC._id));
  });

  // ---- JSON export --------------------------------------------------------
  test('exportJSON returns a valid JSON array of exported records', async () => {
    mockChain([SAMPLE_DOC]);
    const json = await exportJSON();
    const parsed = JSON.parse(json);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    const keys = exportedKeys(parsed[0]);
    EXPECT_SUBSET(keys, EXPORT_FIELDS);
  });

  // ---- CSV export ---------------------------------------------------------
  test('exportCSV returns a CSV string with a header and data rows', async () => {
    mockChain([SAMPLE_DOC]);
    const csv = await exportCSV();
    const lines = csv.split('\n');
    expect(lines.length).toBe(2);
    expect(lines[0]).toBe(EXPORT_FIELDS.join(','));
    expect(lines[1]).toContain(String(SAMPLE_DOC._id));
    expect(lines[1]).toContain(SAMPLE_DOC.eventType);
  });

  test('exportCSV escapes fields containing commas or quotes', async () => {
    const doc = { ...SAMPLE_DOC, reason: 'has, a comma and "quotes"' };
    mockChain([doc]);
    const csv = await exportCSV();
    const lines = csv.split('\n');
    expect(lines[1]).toContain('"has, a comma and ""quotes"""');
  });

  // ---- ground_truth remains null/empty ------------------------------------
  test('ground_truth is null in JSON export', async () => {
    mockChain([SAMPLE_DOC]);
    const parsed = JSON.parse(await exportJSON());
    for (const record of parsed) {
      expect(record.ground_truth).toBeNull();
    }
  });

  test('ground_truth is empty in CSV export', async () => {
    mockChain([SAMPLE_DOC]);
    const csv = await exportCSV();
    const lines = csv.split('\n');
    const groundTruthIdx = EXPORT_FIELDS.indexOf('ground_truth');
    const value = parseCSVRow(lines[1])[groundTruthIdx];
    expect(value).toBe(''); // CSV encodes null as empty string
  });

  test('mapToExport always sets ground_truth to null without calculation', () => {
    const mapped = mapToExport(SAMPLE_DOC);
    expect(mapped.ground_truth).toBeNull();
  });

  // ---- sensitive fields excluded -----------------------------------------
  test('sensitive fields are excluded from JSON export', async () => {
    mockChain([SAMPLE_DOC]);
    const parsed = JSON.parse(await exportJSON());
    const keys = exportedKeys(parsed[0]);
    for (const sensitive of ['password', 'otp', 'token', 'secret', 'code']) {
      expect(keys).not.toContain(sensitive);
    }
  });

  test('sensitive fields are excluded from CSV export', async () => {
    mockChain([SAMPLE_DOC]);
    const csv = await exportCSV();
    for (const sensitive of ['password', 'otp', 'token', 'secret', 'code']) {
      expect(csv).not.toContain(String(SAMPLE_DOC[sensitive]));
    }
  });

  test('identity fields are excluded from JSON export', async () => {
    mockChain([SAMPLE_DOC]);
    const parsed = JSON.parse(await exportJSON());
    const keys = exportedKeys(parsed[0]);
    for (const identity of ['user', 'ip', 'userAgent']) {
      expect(keys).not.toContain(identity);
    }
  });

  test('identity fields are excluded from CSV export', async () => {
    mockChain([SAMPLE_DOC]);
    const csv = await exportCSV();
    for (const identity of ['user', 'ip', 'userAgent']) {
      expect(csv).not.toContain(String(SAMPLE_DOC[identity]));
    }
  });

  // ---- filtering ----------------------------------------------------------
  test('filter by eventType', async () => {
    const other = { ...SAMPLE_DOC, _id: 'b', eventType: 'REAUTH_REQUIRED' };
    mockChain([SAMPLE_DOC, other]);
    const parsed = JSON.parse(await exportJSON({ eventType: 'CONTEXT_CHANGE' }));
    expect(parsed.length).toBe(1);
    expect(parsed[0].eventType).toBe('CONTEXT_CHANGE');

    const queryCall = SecurityEvent.find.mock.calls[0][0];
    expect(queryCall.eventType).toBe('CONTEXT_CHANGE');
  });

  test('filter by since', async () => {
    mockChain([SAMPLE_DOC]);
    await exportJSON({ since: '2026-09-19T09:00:00.000Z' });
    const queryCall = SecurityEvent.find.mock.calls[0][0];
    expect(queryCall.createdAt.$gte.getTime()).toBe(
      new Date('2026-09-19T09:00:00.000Z').getTime()
    );
  });

  test('filter by until', async () => {
    mockChain([SAMPLE_DOC]);
    await exportJSON({ until: '2026-09-19T11:00:00.000Z' });
    const queryCall = SecurityEvent.find.mock.calls[0][0];
    expect(queryCall.createdAt.$lte.getTime()).toBe(
      new Date('2026-09-19T11:00:00.000Z').getTime()
    );
  });

  test('filter by limit', async () => {
    const docs = [SAMPLE_DOC, { ...SAMPLE_DOC, _id: 'b' }];
    mockChain(docs);
    await exportJSON({ limit: 1 });
    const chain = SecurityEvent.find.mock.results[0].value;
    expect(chain.limit).toHaveBeenCalledWith(1);
  });

  test('combined filters are merged in the query', async () => {
    mockChain([SAMPLE_DOC]);
    await exportJSON({
      eventType: 'CONTEXT_CHANGE',
      since: '2026-09-19T09:00:00.000Z',
      until: '2026-09-19T11:00:00.000Z',
      limit: 5,
    });
    const queryCall = SecurityEvent.find.mock.calls[0][0];
    expect(queryCall.eventType).toBe('CONTEXT_CHANGE');
    expect(queryCall.createdAt.$gte.getTime()).toBe(
      new Date('2026-09-19T09:00:00.000Z').getTime()
    );
    expect(queryCall.createdAt.$lte.getTime()).toBe(
      new Date('2026-09-19T11:00:00.000Z').getTime()
    );
    const chain = SecurityEvent.find.mock.results[0].value;
    expect(chain.limit).toHaveBeenCalledWith(5);
    expect(chain.sort).toHaveBeenCalledWith({ createdAt: 1 });
  });

  // ---- empty result handling ----------------------------------------------
  test('empty results return empty CSV header only', async () => {
    mockChain([]);
    const csv = await exportCSV();
    expect(csv).toBe(EXPORT_FIELDS.join(','));
    expect(csv.split('\n').length).toBe(1);
  });

  test('empty results return empty JSON array', async () => {
    mockChain([]);
    const json = await exportJSON();
    expect(JSON.parse(json)).toEqual([]);
  });

  test('findEvents returns empty array for no matches', async () => {
    mockChain([]);
    const docs = await findEvents({ eventType: 'REAUTH_REQUIRED' });
    expect(docs).toEqual([]);
  });

  // ---- helper --------------------------------------------------------------
  function EXPECT_SUBSET(keys, subset) {
    for (const k of subset) {
      expect(keys).toContain(k);
    }
  }
});

describe('securityEventExport buildQuery unit', () => {
  test('empty filters returns empty query', () => {
    expect(buildQuery({})).toEqual({});
  });

  test('since and until build a range query', () => {
    const q = buildQuery({
      since: '2026-01-01T00:00:00.000Z',
      until: '2026-12-31T23:59:59.000Z',
    });
    expect(q.createdAt.$gte).toEqual(new Date('2026-01-01T00:00:00.000Z'));
    expect(q.createdAt.$lte).toEqual(new Date('2026-12-31T23:59:59.000Z'));
  });
});
