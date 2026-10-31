module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  testTimeout: 30000,
  // Setiap file test dijalankan secara serial
  maxWorkers: 1,
};
