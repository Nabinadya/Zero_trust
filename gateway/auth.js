/**
 * gateway/auth.js
 * Route autentikasi di API Gateway.
 * Menangani login, refresh, logout, dan penerbitan token service.
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const router = express.Router();
const config = require('../shared/config');
const {
  signAccessToken,
  signRefreshToken,
  signServiceToken,
  verifyRefreshToken,
} = require('../shared/token');
const { getDatabase } = require('../shared/database');
const { logAudit } = require('./audit');

/**
 * POST /auth/login
 * Autentikasi pengguna dengan username, password, dan device ID.
 */
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const deviceId = req.headers['x-device-id'];
  const requestId = req.headers['x-request-id'] || null;

  if (!username || !password) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/login',
      subject: username || 'unknown', role: null, deviceId,
      decision: 'DENY', reason: 'Missing username or password',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Username dan password wajib diisi' });
  }

  if (!deviceId) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/login',
      subject: username, role: null, deviceId: null,
      decision: 'DENY', reason: 'Missing X-Device-ID header',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Header X-Device-ID wajib disertakan' });
  }

  const db = getDatabase();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/login',
      subject: username, role: null, deviceId,
      decision: 'DENY', reason: 'User not found',
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/login',
      subject: username, role: user.role, deviceId,
      decision: 'DENY', reason: 'Invalid password',
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }

  // Verifikasi device terdaftar untuk user ini
  const device = db.prepare(
    'SELECT * FROM devices WHERE user_id = ? AND device_id = ?'
  ).get(user.id, deviceId);

  if (!device) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/login',
      subject: username, role: user.role, deviceId,
      decision: 'DENY', reason: 'Device not registered for user',
      ipAddress: req.ip,
    });
    return res.status(403).json({ error: 'Perangkat tidak terdaftar untuk akun ini' });
  }

  // Generate tokens
  const accessToken = signAccessToken(
    { sub: user.id, role: user.role, username: user.username },
    config.jwtSecret,
    config.accessTokenExpiry
  );

  const refreshToken = signRefreshToken(
    { sub: user.id, role: user.role },
    config.jwtRefreshSecret,
    config.refreshTokenExpiry
  );

  // Simpan hash refresh token di database
  const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
  ).run(user.id, refreshTokenHash, expiresAt);

  logAudit({
    requestId, method: 'POST', endpoint: '/auth/login',
    subject: username, role: user.role, deviceId,
    decision: 'ALLOW', reason: 'Login successful',
    ipAddress: req.ip,
  });

  res.json({
    message: 'Login berhasil',
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      nama: user.nama,
      nim: user.nim,
    },
  });
});

/**
 * POST /auth/refresh
 * Memperbarui access token menggunakan refresh token yang valid.
 */
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  const requestId = req.headers['x-request-id'] || null;

  if (!refreshToken) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/refresh',
      subject: 'unknown', role: null, deviceId: null,
      decision: 'DENY', reason: 'Missing refresh token',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Refresh token wajib disertakan' });
  }

  // Verifikasi JWT refresh token
  let decoded;
  try {
    decoded = verifyRefreshToken(refreshToken, config.jwtRefreshSecret);
  } catch (err) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/refresh',
      subject: 'unknown', role: null, deviceId: null,
      decision: 'DENY', reason: `Invalid refresh token: ${err.message}`,
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Refresh token tidak valid atau kedaluwarsa' });
  }

  // Cek apakah refresh token ada di database dan belum dicabut
  const db = getDatabase();
  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const storedToken = db.prepare(
    'SELECT * FROM refresh_tokens WHERE token_hash = ? AND user_id = ?'
  ).get(tokenHash, decoded.sub);

  if (!storedToken) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/refresh',
      subject: `user_id:${decoded.sub}`, role: decoded.role, deviceId: null,
      decision: 'DENY', reason: 'Refresh token not found in database',
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Refresh token tidak ditemukan' });
  }

  if (storedToken.is_revoked) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/refresh',
      subject: `user_id:${decoded.sub}`, role: decoded.role, deviceId: null,
      decision: 'DENY', reason: 'Refresh token has been revoked',
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Refresh token telah dicabut' });
  }

  // Ambil data user
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.sub);
  if (!user) {
    return res.status(401).json({ error: 'User tidak ditemukan' });
  }

  // Generate access token baru
  const accessToken = signAccessToken(
    { sub: user.id, role: user.role, username: user.username },
    config.jwtSecret,
    config.accessTokenExpiry
  );

  logAudit({
    requestId, method: 'POST', endpoint: '/auth/refresh',
    subject: user.username, role: user.role, deviceId: null,
    decision: 'ALLOW', reason: 'Token refreshed successfully',
    ipAddress: req.ip,
  });

  res.json({
    message: 'Token diperbarui',
    accessToken,
  });
});

/**
 * POST /auth/logout
 * Mencabut refresh token.
 */
router.post('/logout', (req, res) => {
  const { refreshToken } = req.body;
  const requestId = req.headers['x-request-id'] || null;

  if (!refreshToken) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/logout',
      subject: 'unknown', role: null, deviceId: null,
      decision: 'DENY', reason: 'Missing refresh token',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Refresh token wajib disertakan' });
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshToken, config.jwtRefreshSecret);
  } catch (err) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/logout',
      subject: 'unknown', role: null, deviceId: null,
      decision: 'DENY', reason: `Invalid refresh token: ${err.message}`,
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Refresh token tidak valid' });
  }

  const db = getDatabase();
  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

  const storedToken = db.prepare(
    'SELECT * FROM refresh_tokens WHERE token_hash = ? AND user_id = ?'
  ).get(tokenHash, decoded.sub);

  if (!storedToken) {
    return res.status(401).json({ error: 'Refresh token tidak ditemukan' });
  }

  if (storedToken.is_revoked) {
    return res.status(401).json({ error: 'Refresh token sudah dicabut sebelumnya' });
  }

  // Cabut refresh token
  db.prepare(
    'UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?'
  ).run(storedToken.id);

  logAudit({
    requestId, method: 'POST', endpoint: '/auth/logout',
    subject: `user_id:${decoded.sub}`, role: decoded.role, deviceId: null,
    decision: 'ALLOW', reason: 'Logout successful, refresh token revoked',
    ipAddress: req.ip,
  });

  res.json({ message: 'Logout berhasil, refresh token dicabut' });
});

/**
 * POST /auth/service
 * Menerbitkan token service untuk komunikasi antar-service.
 */
router.post('/service', (req, res) => {
  const { clientId, clientSecret } = req.body;
  const requestId = req.headers['x-request-id'] || null;

  if (!clientId || !clientSecret) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/service',
      subject: clientId || 'unknown', role: 'service', deviceId: null,
      decision: 'DENY', reason: 'Missing client credentials',
      ipAddress: req.ip,
    });
    return res.status(400).json({ error: 'Client ID dan client secret wajib diisi' });
  }

  const db = getDatabase();
  const client = db.prepare(
    'SELECT * FROM service_clients WHERE client_id = ? AND is_active = 1'
  ).get(clientId);

  if (!client) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/service',
      subject: clientId, role: 'service', deviceId: null,
      decision: 'DENY', reason: 'Service client not found or inactive',
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Kredensial service tidak valid' });
  }

  if (!bcrypt.compareSync(clientSecret, client.client_secret_hash)) {
    logAudit({
      requestId, method: 'POST', endpoint: '/auth/service',
      subject: clientId, role: 'service', deviceId: null,
      decision: 'DENY', reason: 'Invalid client secret',
      ipAddress: req.ip,
    });
    return res.status(401).json({ error: 'Kredensial service tidak valid' });
  }

  const serviceToken = signServiceToken(
    { sub: client.client_id, service_name: client.service_name },
    config.jwtServiceSecret,
    config.serviceTokenExpiry
  );

  logAudit({
    requestId, method: 'POST', endpoint: '/auth/service',
    subject: clientId, role: 'service', deviceId: null,
    decision: 'ALLOW', reason: 'Service token issued',
    ipAddress: req.ip,
  });

  res.json({
    message: 'Service token diterbitkan',
    serviceToken,
  });
});

module.exports = router;
