/**
 * shared/service-auth.js
 * Middleware verifikasi gateway secret dan token untuk backend services.
 * Setiap service WAJIB memverifikasi secara mandiri, tidak boleh
 * hanya mengandalkan gateway.
 */
const config = require('./config');
const { verifyAccessToken, verifyServiceToken } = require('./token');

/**
 * Middleware verifikasi gateway secret.
 * Menolak request tanpa X-Gateway-Secret yang valid.
 */
function verifyGatewaySecret(req, res, next) {
  const gatewaySecret = req.headers['x-gateway-secret'];

  if (!gatewaySecret) {
    return res.status(403).json({
      error: 'Akses ditolak: request harus melalui API Gateway',
    });
  }

  if (gatewaySecret !== config.gatewaySecret) {
    return res.status(403).json({
      error: 'Akses ditolak: gateway secret tidak valid',
    });
  }

  next();
}

/**
 * Middleware verifikasi access token pada service.
 * Token diteruskan gateway via Authorization header.
 * Service tetap memverifikasi signature, expiry, dan algorithm.
 */
function verifyUserToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  let token = null;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  if (!token) {
    return res.status(401).json({ error: 'Token tidak ditemukan' });
  }

  try {
    const decoded = verifyAccessToken(token, config.jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: `Token tidak valid: ${err.message}` });
  }
}

/**
 * Middleware verifikasi service token.
 * Digunakan oleh endpoint sinkronisasi yang hanya boleh diakses oleh service.
 */
function verifyServiceTokenMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  let token = null;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  if (!token) {
    return res.status(401).json({ error: 'Service token tidak ditemukan' });
  }

  try {
    const decoded = verifyServiceToken(token, config.jwtServiceSecret);
    req.serviceAuth = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: `Service token tidak valid: ${err.message}` });
  }
}

module.exports = { verifyGatewaySecret, verifyUserToken, verifyServiceTokenMiddleware };
