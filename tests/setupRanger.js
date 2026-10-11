/**
 * Setup for ranger tests only. Used via Jest project so afterEach does NOT wipe
 * cases/rangermissions/threatreports, allowing ranger tests to create data and use it.
 */
require('dotenv').config();
const mongoose = require('mongoose');

jest.setTimeout(60000);

let connected = false;

beforeAll(async () => {
  if (process.env.SKIP_DB === 'true') return;
  try {
    const mongoUri = process.env.MONGODB_TEST_URI || process.env.MONGODB_URI || 'mongodb+srv://SE:%23SE2026@se.nxqezs4.mongodb.net/AF?appName=SE&retryWrites=true&w=majority';
    await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 30000 });
    connected = true;
  } catch (err) {
    console.warn('⚠  MongoDB not reachable – skipping DB setup:', err.message);
  }
});

afterAll(async () => {
  if (connected) {
    await mongoose.disconnect();
  }
});

afterEach(async () => {
  if (!connected) return;
  // Do NOT clean cases, rangermissions, threatreports so ranger tests can create and use them in the same run.
  const collections = mongoose.connection.collections;
  const collectionsToClean = ['incidents', 'assignments', 'notifications', 'resources', 'staff'];
  for (const key in collections) {
    if (collectionsToClean.includes(key.toLowerCase())) {
      const collection = collections[key];
      await collection.deleteMany({});
    }
  }
});
