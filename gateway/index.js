/**
 * gateway/index.js
 * API Gateway — Policy Enforcement Point (PEP).
 * Port: 3000
 * 
 * Satu-satunya pintu masuk untuk semua request pengguna.
 * Menerapkan kebijakan Zero Trust sebelum meneruskan ke backend services.
 */
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const config = require('../shared/config');
const { getDatabase } = require('../shared/database');
const { createTables } = require('../shared/schema');
const authRouter = require('./auth');
const { evaluatePolicy } = require('./policy-engine');
const { logAudit } = require('./audit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// Parse JSON body
app.use(express.json());

// Tambahkan request ID ke setiap request
app.use((req, res, next) => {
  req.headers['x-request-id'] = req.headers['x-request-id'] || uuidv4();
  next();
});

// Inisialisasi database dan tabel
const db = getDatabase();
createTables(db);

// === Auth routes (ditangani langsung oleh gateway) ===
app.use('/auth', authRouter);

// === Admin endpoint: lihat audit logs ===
app.get('/admin/audit-logs', (req, res) => {
  const policy = evaluatePolicy(req);
  const requestId = req.headers['x-request-id'];
  const deviceId = req.headers['x-device-id'] || null;

  logAudit({
    requestId,
    method: 'GET',
    endpoint: '/admin/audit-logs',
    subject: policy.user ? policy.user.username || `user_id:${policy.user.sub}` : 'unknown',
    role: policy.user ? policy.user.role : null,
    deviceId,
    decision: policy.allowed ? 'ALLOW' : 'DENY',
    reason: policy.reason,
    ipAddress: req.ip,
  });

  if (!policy.allowed) {
    return res.status(policy.reason.includes('token') ? 401 : 403).json({
      error: policy.reason,
    });
  }

  const limit = parseInt(req.query.limit, 10) || 100;
  const offset = parseInt(req.query.offset, 10) || 0;
  const logs = db.prepare(
    'SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?'
  ).all(limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get();

  res.json({ logs, total: total.count, limit, offset });
});

// === Policy Enforcement untuk semua request non-auth ===
// Middleware yang mengevaluasi kebijakan sebelum meneruskan ke service
app.use((req, res, next) => {
  // Skip jika sudah ditangani (/auth/*, /admin/audit-logs)
  if (req.path.startsWith('/auth/')) {
    return next();
  }

  const policy = evaluatePolicy(req);
  const requestId = req.headers['x-request-id'];
  const deviceId = req.headers['x-device-id'] || null;

  // Log keputusan
  logAudit({
    requestId,
    method: req.method,
    endpoint: req.path,
    subject: policy.user ? (policy.user.username || policy.user.sub || 'service') : 'unknown',
    role: policy.user ? policy.user.role : null,
    deviceId,
    decision: policy.allowed ? 'ALLOW' : 'DENY',
    reason: policy.reason,
    ipAddress: req.ip,
  });

  if (!policy.allowed) {
    const statusCode = determineStatusCode(policy.reason);
    return res.status(statusCode).json({
      error: policy.reason,
    });
  }

  // Tambahkan gateway secret dan user info ke header sebelum forward
  req.headers['x-gateway-secret'] = config.gatewaySecret;
  // Forward user info agar service tahu siapa yang melakukan request
  if (policy.user) {
    req.headers['x-user-id'] = String(policy.user.sub);
    req.headers['x-user-role'] = policy.user.role;
    req.headers['x-user-username'] = policy.user.username || '';
  }
  if (policy.tokenType) {
    req.headers['x-token-type'] = policy.tokenType;
  }

  next();
});

/**
 * Tentukan HTTP status code berdasarkan alasan penolakan
 */
function determineStatusCode(reason) {
  if (!reason) return 403;
  const r = reason.toLowerCase();
  if (r.includes('missing authorization') || r.includes('invalid access token') ||
      r.includes('invalid service token') || r.includes('expired') ||
      r.includes('token type mismatch')) {
    return 401;
  }
  return 403;
}

// === Proxy ke Grade Service ===
app.use('/nilai', createProxyMiddleware({
  target: config.gradeServiceUrl,
  changeOrigin: true,
  pathRewrite: { '^/nilai': '/nilai' },
  // Jangan parse body lagi (sudah di-parse express)
  on: {
    proxyReq: (proxyReq, req) => {
      // Kirim body yang sudah di-parse
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    },
  },
}));

app.use('/kelas', createProxyMiddleware({
  target: config.gradeServiceUrl,
  changeOrigin: true,
  pathRewrite: { '^/kelas': '/kelas' },
  on: {
    proxyReq: (proxyReq, req) => {
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    },
  },
}));

// === Proxy ke Transcript Service ===
app.use('/transkrip', createProxyMiddleware({
  target: config.transcriptServiceUrl,
  changeOrigin: true,
  pathRewrite: { '^/transkrip': '/transkrip' },
  on: {
    proxyReq: (proxyReq, req) => {
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    },
  },
}));

// === 404 handler ===
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

// === Error handler ===
app.use((err, req, res, next) => {
  console.error('[GATEWAY ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Hanya start server jika dijalankan langsung (bukan saat testing)
if (require.main === module) {
  app.listen(config.gatewayPort, () => {
    console.log(`[API Gateway] berjalan di port ${config.gatewayPort}`);
    console.log(`[API Gateway] Policy Engine aktif`);
    console.log(`[API Gateway] Grade Service -> ${config.gradeServiceUrl}`);
    console.log(`[API Gateway] Transcript Service -> ${config.transcriptServiceUrl}`);
  });
}

module.exports = app;
