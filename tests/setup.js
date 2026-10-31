/**
 * tests/setup.js
 * Setup test environment.
 * Membuat database temporary untuk testing.
 */
const path = require('path');
const fs = require('fs');

// Set environment variables SEBELUM load config
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.JWT_SERVICE_SECRET = 'test-service-secret';
process.env.GATEWAY_SECRET = 'test-gateway-secret';
process.env.SERVICE_CLIENT_ID = 'grade-service';
process.env.SERVICE_CLIENT_SECRET = 'test-service-client-secret';
process.env.GATEWAY_PORT = '3100';
process.env.GRADE_SERVICE_PORT = '3101';
process.env.TRANSCRIPT_SERVICE_PORT = '3102';
process.env.GATEWAY_URL = 'http://localhost:3100';
process.env.GRADE_SERVICE_URL = 'http://localhost:3101';
process.env.TRANSCRIPT_SERVICE_URL = 'http://localhost:3102';
process.env.ACCESS_START_HOUR = '7';
process.env.ACCESS_END_HOUR = '21';
process.env.APP_TIMEZONE = 'Asia/Jakarta';
process.env.NODE_ENV = 'test';

const testDbDir = path.resolve(__dirname, '..', 'database');
const testDbPath = path.resolve(testDbDir, 'test.db');
process.env.DB_PATH = './database/test.db';

// Hapus database test lama jika ada
function cleanTestDb() {
  for (const ext of ['', '-wal', '-shm']) {
    const f = testDbPath + ext;
    if (fs.existsSync(f)) {
      try { fs.unlinkSync(f); } catch (e) { /* ignore */ }
    }
  }
}

module.exports = { testDbPath, cleanTestDb };
