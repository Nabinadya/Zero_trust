/**
 * shared/token.js
 * Utility untuk JWT token: sign, verify, dan helper terkait.
 * Menggunakan jsonwebtoken dengan algorithm whitelist.
 */
const jwt = require('jsonwebtoken');

const ALLOWED_ALGORITHMS = ['HS256'];

/**
 * Membuat access token pengguna.
 * @param {object} payload - { sub, role, username }
 * @param {string} secret
 * @param {string} expiresIn
 * @returns {string}
 */
function signAccessToken(payload, secret, expiresIn) {
  return jwt.sign(
    { sub: payload.sub, role: payload.role, username: payload.username, type: 'access' },
    secret,
    { algorithm: 'HS256', expiresIn }
  );
}

/**
 * Membuat refresh token.
 * @param {object} payload - { sub, role }
 * @param {string} secret
 * @param {string} expiresIn
 * @returns {string}
 */
function signRefreshToken(payload, secret, expiresIn) {
  return jwt.sign(
    { sub: payload.sub, role: payload.role, type: 'refresh' },
    secret,
    { algorithm: 'HS256', expiresIn }
  );
}

/**
 * Membuat token service.
 * @param {object} payload - { sub, role: 'service', service_name }
 * @param {string} secret
 * @param {string} expiresIn
 * @returns {string}
 */
function signServiceToken(payload, secret, expiresIn) {
  return jwt.sign(
    { sub: payload.sub, role: 'service', service_name: payload.service_name, type: 'service' },
    secret,
    { algorithm: 'HS256', expiresIn }
  );
}

/**
 * Verifikasi access token.
 * @param {string} token
 * @param {string} secret
 * @returns {object} decoded payload
 * @throws {Error} jika verifikasi gagal
 */
function verifyAccessToken(token, secret) {
  const decoded = jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS });
  if (decoded.type !== 'access') {
    throw new Error('Token type mismatch: expected access token');
  }
  return decoded;
}

/**
 * Verifikasi refresh token.
 * @param {string} token
 * @param {string} secret
 * @returns {object} decoded payload
 * @throws {Error}
 */
function verifyRefreshToken(token, secret) {
  const decoded = jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS });
  if (decoded.type !== 'refresh') {
    throw new Error('Token type mismatch: expected refresh token');
  }
  return decoded;
}

/**
 * Verifikasi service token.
 * @param {string} token
 * @param {string} secret
 * @returns {object} decoded payload
 * @throws {Error}
 */
function verifyServiceToken(token, secret) {
  const decoded = jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS });
  if (decoded.type !== 'service' || decoded.role !== 'service') {
    throw new Error('Token type mismatch: expected service token');
  }
  return decoded;
}

/**
 * Verifikasi token generik (untuk gateway yang perlu tahu jenis token).
 * @param {string} token
 * @param {string} secret
 * @returns {object} decoded payload
 * @throws {Error}
 */
function verifyToken(token, secret) {
  return jwt.verify(token, secret, { algorithms: ALLOWED_ALGORITHMS });
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  signServiceToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyServiceToken,
  verifyToken,
  ALLOWED_ALGORITHMS,
};
