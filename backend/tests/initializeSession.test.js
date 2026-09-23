/**
 * Focused test for sessionMonitor.initializeSession().
 *
 * Verifies the admin-session initialization change introduced in the MFA
 * verification flow (authController.verifyMfa -> sessionMonitor.initializeSession):
 *
 *   1. initializeSession() returns null when the request carries no
 *      authenticated user.
 *   2. initializeSession() creates a new monitored session keyed by userId,
 *      with zero activity counters and no fabricated risk values.
 *   3. initializeSession() establishes the security baseline on the new
 *      session.
 *   4. initializeSession() is idempotent: a second call reuses the existing
 *      session and does not reset activity counters or risk state.
 */

process.env.RISK_MEDIUM_THRESHOLD = "30";
process.env.RISK_HIGH_THRESHOLD = "61";
process.env.RISK_CRITICAL_THRESHOLD = "81";

jest.mock("../src/services/aiService", () => ({
  extractDeviceInfo: jest.fn(() => ({
    device: "Desktop",
    browser: "Chrome",
    operatingSystem: "Windows",
  })),
  assessSessionRisk: jest.fn(),
}));

jest.mock("../src/services/ipService", () => ({
  getIpGeolocation: jest.fn(async () => ({
    country: "Australia",
    city: "Sydney",
    org: "",
    asn: null,
  })),
  detectVpn: jest.fn(() => false),
}));

const sessionMonitor = require("../src/services/sessionMonitor");

const mockReq = (overrides = {}) => ({
  user: { _id: "admin-001", email: "admin@test.com", role: "admin" },
  headers: { "user-agent": "jest" },
  ip: "127.0.0.1",
  ...overrides,
});

const keyFor = (userId) => "user:" + userId;

describe("sessionMonitor.initializeSession()", () => {
  beforeEach(() => {
    sessionMonitor.sessions.clear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    sessionMonitor.sessions.clear();
  });

  test("returns null when the request has no authenticated user", async () => {
    const result = await sessionMonitor.initializeSession({ headers: {}, ip: "127.0.0.1" });
    expect(result).toBeNull();
    expect(sessionMonitor.sessions.size).toBe(0);
  });

  test("returns null when req.user exists but has no _id", async () => {
    const result = await sessionMonitor.initializeSession({ user: { email: "a@test.com" }, headers: {}, ip: "127.0.0.1" });
    expect(result).toBeNull();
    expect(sessionMonitor.sessions.size).toBe(0);
  });

  test("creates a new session keyed by userId with zero activity and no fabricated risk", async () => {
    const req = mockReq();
    const session = await sessionMonitor.initializeSession(req);

    expect(session).not.toBeNull();
    expect(sessionMonitor.sessions.get(keyFor(req.user._id))).toBe(session);

    expect(session.documentsViewed).toBe(0);
    expect(session.documentsDownloaded).toBe(0);
    expect(session.documentsUploaded).toBe(0);
    expect(session.verificationActions).toBe(0);
    expect(session.failedActions).toBe(0);
    expect(session.actionTimestamps).toEqual([]);

    expect(session.lastRiskResult).toBeNull();
    expect(session.lastRiskCheckedAt).toBeNull();
    expect(session.riskDecision).toBe("unknown");
    expect(session.accumulatedRisk).toBe(0);
    expect(session.accumulatedRiskUpdatedAt).toBeNull();
    expect(session.riskLevel).toBe("low");
    expect(session.requiresReauthentication).toBe(false);
    expect(session.reauthCooldownUntil).toBeNull();
  });

  test("establishes the security baseline on the new session", async () => {
    const req = mockReq();
    const session = await sessionMonitor.initializeSession(req);

    expect(session.securityBaseline).not.toBeNull();
    expect(session.securityBaseline.device).toBe("Desktop");
    expect(session.securityBaseline.browser).toBe("Chrome");
    expect(session.securityBaseline.operatingSystem).toBe("Windows");
    expect(session.securityBaseline.country).toBe("Australia");
    expect(session.securityBaseline.city).toBe("Sydney");
    expect(session.securityBaseline.vpnDetected).toBe(false);
    expect(typeof session.securityBaseline.ip).toBe("string");
    expect(typeof session.securityBaseline.loginAt).toBe("number");
  });

  test("stores the current session context and zeroed context changes at initialization", async () => {
    const req = mockReq();
    const session = await sessionMonitor.initializeSession(req);

    expect(session.currentSessionContext).not.toBeNull();
    expect(session.currentSessionContext.device).toBe("Desktop");
    expect(session.currentSessionContext.browser).toBe("Chrome");
    expect(session.currentSessionContext.operatingSystem).toBe("Windows");
    expect(session.currentSessionContext.country).toBe("Australia");
    expect(session.currentSessionContext.city).toBe("Sydney");
    expect(session.currentSessionContext.vpnDetected).toBe(false);
    expect(typeof session.currentSessionContext.ip).toBe("string");
    expect(typeof session.currentSessionContext.loginAt).toBe("number");

    expect(session.contextChanges).not.toBeNull();
    expect(session.contextChanges.deviceChanged).toBe(false);
    expect(session.contextChanges.browserChanged).toBe(false);
    expect(session.contextChanges.osChanged).toBe(false);
    expect(session.contextChanges.ipChanged).toBe(false);
    expect(session.contextChanges.locationChanged).toBe(false);
    expect(session.contextChanges.vpnChanged).toBe(false);
  });

  test("is idempotent: a second call reuses the existing session", async () => {
    const req = mockReq();
    const first = await sessionMonitor.initializeSession(req);

    first.documentsViewed = 3;
    first.failedActions = 1;
    first.requiresReauthentication = true;
    first.accumulatedRisk = 42;

    const second = await sessionMonitor.initializeSession(req);

    expect(second).toBe(first);
    expect(sessionMonitor.sessions.size).toBe(1);

    expect(second.documentsViewed).toBe(3);
    expect(second.failedActions).toBe(1);
    expect(second.requiresReauthentication).toBe(true);
    expect(second.accumulatedRisk).toBe(42);

    expect(second.securityBaseline).not.toBeNull();
  });

  test("is idempotent across different users without cross-contamination", async () => {
    const admin = mockReq({ user: { _id: "admin-001", email: "admin@test.com", role: "admin" } });
    const student = mockReq({ user: { _id: "student-001", email: "student@test.com", role: "student" } });

    const adminSession = await sessionMonitor.initializeSession(admin);
    const studentSession = await sessionMonitor.initializeSession(student);

    expect(adminSession).not.toBe(studentSession);
    expect(sessionMonitor.sessions.size).toBe(2);
    expect(sessionMonitor.sessions.get(keyFor("admin-001"))).toBe(adminSession);
    expect(sessionMonitor.sessions.get(keyFor("student-001"))).toBe(studentSession);
    expect(adminSession.userRole).toBe("admin");
    expect(studentSession.userRole).toBe("student");
  });
});
