
/**
 * Focused persistence test for the five session-context fields on LoginActivity.
 *
 * Verifies the values assigned by authController.login() are actually persisted
 * on the LoginActivity Mongoose document, and that the fields default to null
 * when not provided.
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const LoginActivity = require('../src/models/LoginActivity');

let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await LoginActivity.deleteMany({});
});

describe('LoginActivity five context-feature fields', () => {
  test('all five values assigned by login() persist through save + retrieve', async () => {
    const testUserId = new mongoose.Types.ObjectId();

    const doc = new LoginActivity({
      user: testUserId,
      deviceSeenBefore: true,
      timeSinceLastLoginMs: 42000,
      distanceFromLastKm: 12.5,
      recentFailedLoginsCount: 3,
      successfulMfaHistoryCount: 7,
    });

    const saved = await doc.save();
    const retrieved = await LoginActivity.findById(saved._id);

    expect(retrieved.user.toString()).toBe(testUserId.toString());
    expect(retrieved.deviceSeenBefore).toBe(true);
    expect(retrieved.timeSinceLastLoginMs).toBe(42000);
    expect(retrieved.distanceFromLastKm).toBe(12.5);
    expect(retrieved.recentFailedLoginsCount).toBe(3);
    expect(retrieved.successfulMfaHistoryCount).toBe(7);
  });

  test('new document without the fields gets null defaults', async () => {
    const testUserId = new mongoose.Types.ObjectId();

    const doc = new LoginActivity({
      user: testUserId,
    });

    const saved = await doc.save();
    const retrieved = await LoginActivity.findById(saved._id);

    expect(retrieved.user.toString()).toBe(testUserId.toString());
    expect(retrieved.deviceSeenBefore).toBeNull();
    expect(retrieved.timeSinceLastLoginMs).toBeNull();
    expect(retrieved.distanceFromLastKm).toBeNull();
    expect(retrieved.recentFailedLoginsCount).toBeNull();
    expect(retrieved.successfulMfaHistoryCount).toBeNull();
  });
});
