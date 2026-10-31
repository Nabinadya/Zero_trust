/**
 * shared/config.js
 * Konfigurasi terpusat yang membaca dari environment variables.
 * Semua secret dan konfigurasi sensitif diambil dari .env
 */
const path = require('path');

// Load .env dari root proyek
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const config = {
  // JWT
  jwtSecret: process.env.JWT_SECRET,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
  jwtServiceSecret: process.env.JWT_SERVICE_SECRET,
  accessTokenExpiry: process.env.ACCESS_TOKEN_EXPIRY || '10m',
  refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRY || '1d',
  serviceTokenExpiry: process.env.SERVICE_TOKEN_EXPIRY || '5m',

  // Gateway
  gatewaySecret: process.env.GATEWAY_SECRET,

  // Service client
  serviceClientId: process.env.SERVICE_CLIENT_ID,
  serviceClientSecret: process.env.SERVICE_CLIENT_SECRET,

  // Ports
  gatewayPort: parseInt(process.env.GATEWAY_PORT, 10) || 3000,
  gradeServicePort: parseInt(process.env.GRADE_SERVICE_PORT, 10) || 3001,
  transcriptServicePort: parseInt(process.env.TRANSCRIPT_SERVICE_PORT, 10) || 3002,

  // Database
  dbPath: process.env.DB_PATH || './database/zero-trust.db',

  // Access hours
  accessStartHour: parseInt(process.env.ACCESS_START_HOUR, 10) || 7,
  accessEndHour: parseInt(process.env.ACCESS_END_HOUR, 10) || 21,
  appTimezone: process.env.APP_TIMEZONE || 'Asia/Jakarta',

  // Service URLs
  gradeServiceUrl: process.env.GRADE_SERVICE_URL || 'http://localhost:3001',
  transcriptServiceUrl: process.env.TRANSCRIPT_SERVICE_URL || 'http://localhost:3002',
  gatewayUrl: process.env.GATEWAY_URL || 'http://localhost:3000',

  // Environment
  nodeEnv: process.env.NODE_ENV || 'development',
};

module.exports = config;
