git/**
 * gateway/policy-engine.js
 * Policy Engine / Policy Administrator (PE/PA)
 * 
 * Memutuskan ALLOW atau DENY berdasarkan:
 * - Token validity (signature, expiry, algorithm)
 * - Role-based access
 * - Device verification
 * - Data ownership (class, grades, transcripts)
 * - Access hours (for grade modification and finalization)
 * - Service token distinction
 * 
 * Ini adalah inti dari pendekatan Zero Trust.
 */
const config = require('../shared/config');
const { verifyAccessToken, verifyServiceToken } = require('../shared/token');
const { getDatabase } = require('../shared/database');
const { isWithinAccessHours } = require('../shared/clock');
const { logAudit } = require('./audit');

/**
 * Evaluasi kebijakan akses untuk sebuah request.
 * @param {import('express').Request} req
 * @returns {{ allowed: boolean, reason: string, user: object|null, tokenType: string|null }}
 */
function evaluatePolicy(req) {
  const method = req.method;
  const path = req.path;
  const deviceId = req.headers['x-device-id'] || null;
  const authHeader = req.headers['authorization'] || '';
  const requestId = req.headers['x-request-id'] || null;

  // === AUTH endpoints: diizinkan tanpa token (dihandle oleh auth.js) ===
  if (path.startsWith('/auth/')) {
    return { allowed: true, reason: 'Auth endpoint - handled by auth module', user: null, tokenType: null };
  }

  // === Extract token ===
  let token = null;
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  if (!token) {
    return { allowed: false, reason: 'Missing authorization token', user: null, tokenType: null };
  }

  // === Coba verifikasi sebagai service token dulu, lalu access token ===
  let decoded = null;
  let tokenType = null;

  // Untuk endpoint sinkronisasi, hanya terima service token
  if (path === '/transkrip/sinkron' && method === 'POST') {
    try {
      decoded = verifyServiceToken(token, config.jwtServiceSecret);
      tokenType = 'service';
    } catch (err) {
      // Coba juga sebagai access token untuk memberikan error yang tepat
      try {
        const userDecoded = verifyAccessToken(token, config.jwtSecret);
        // Token user valid tapi tidak boleh digunakan untuk sinkronisasi
        return {
          allowed: false,
          reason: 'User tokens (including admin) are not allowed for sync endpoint. Service token required.',
          user: userDecoded,
          tokenType: 'access',
        };
      } catch (innerErr) {
        return {
          allowed: false,
          reason: `Invalid service token: ${err.message}`,
          user: null,
          tokenType: null,
        };
      }
    }

    // Service token valid - izinkan
    return {
      allowed: true,
      reason: 'Valid service token for sync',
      user: decoded,
      tokenType: 'service',
    };
  }

  // === Untuk endpoint lain, hanya terima access token ===
  try {
    decoded = verifyAccessToken(token, config.jwtSecret);
    tokenType = 'access';
  } catch (err) {
    return {
      allowed: false,
      reason: `Invalid access token: ${err.message}`,
      user: null,
      tokenType: null,
    };
  }

  // === Verifikasi device untuk semua endpoint non-auth ===
  if (!deviceId) {
    return {
      allowed: false,
      reason: 'Missing X-Device-ID header',
      user: decoded,
      tokenType,
    };
  }

  const db = getDatabase();
  const device = db.prepare(
    'SELECT * FROM devices WHERE user_id = ? AND device_id = ?'
  ).get(decoded.sub, deviceId);

  if (!device) {
    return {
      allowed: false,
      reason: 'Device not registered for this user',
      user: decoded,
      tokenType,
    };
  }

  // === Kebijakan per endpoint ===
  return evaluateEndpointPolicy(method, path, decoded, deviceId, req);
}

/**
 * Evaluasi kebijakan spesifik per endpoint.
 */
function evaluateEndpointPolicy(method, path, user, deviceId, req) {
  const db = getDatabase();

  // GET /nilai
  if (path === '/nilai' && method === 'GET') {
    if (user.role === 'mahasiswa' || user.role === 'dosen') {
      return { allowed: true, reason: `${user.role} accessing grades`, user, tokenType: 'access' };
    }
    // Admin tidak perlu akses endpoint ini
    return { allowed: false, reason: 'Role not authorized for this endpoint', user, tokenType: 'access' };
  }

  // PUT /nilai/:id
  const nilaiMatch = path.match(/^\/nilai\/(\d+)$/);
  if (nilaiMatch && method === 'PUT') {
    const gradeId = parseInt(nilaiMatch[1], 10);

    if (user.role !== 'dosen') {
      return { allowed: false, reason: 'Only dosen can update grades', user, tokenType: 'access' };
    }

    // Cek jam akses
    if (!isWithinAccessHours(config.accessStartHour, config.accessEndHour, config.appTimezone)) {
      return {
        allowed: false,
        reason: `Access denied: outside allowed hours (${config.accessStartHour}:00 - ${config.accessEndHour}:00)`,
        user,
        tokenType: 'access',
      };
    }

    // Cek kepemilikan kelas
    const grade = db.prepare(`
      SELECT g.*, c.dosen_id, c.is_finalized as class_finalized
      FROM grades g
      JOIN classes c ON g.class_id = c.id
      WHERE g.id = ?
    `).get(gradeId);

    if (!grade) {
      return { allowed: false, reason: 'Grade not found', user, tokenType: 'access' };
    }

    if (grade.dosen_id !== user.sub) {
      return { allowed: false, reason: 'Dosen does not own this class', user, tokenType: 'access' };
    }

    if (grade.is_finalized === 1) {
      return { allowed: false, reason: 'Grade already finalized', user, tokenType: 'access' };
    }

    return { allowed: true, reason: 'Dosen authorized to update grade', user, tokenType: 'access' };
  }

  // POST /kelas/:id/finalisasi (mendukung ID angka maupun kode kelas seperti CS202)
  const kelasMatch = path.match(/^\/kelas\/([^/]+)\/finalisasi$/);
  if (kelasMatch && method === 'POST') {
    const classParam = kelasMatch[1];

    if (user.role !== 'dosen') {
      return { allowed: false, reason: 'Only dosen can finalize classes', user, tokenType: 'access' };
    }

    // Cek jam akses
    if (!isWithinAccessHours(config.accessStartHour, config.accessEndHour, config.appTimezone)) {
      return {
        allowed: false,
        reason: `Access denied: outside allowed hours (${config.accessStartHour}:00 - ${config.accessEndHour}:00)`,
        user,
        tokenType: 'access',
      };
    }

    // Cek kepemilikan kelas (by ID atau kode_kelas)
    const kelas = db.prepare('SELECT * FROM classes WHERE id = ? OR kode_kelas = ?').get(classParam, classParam);
    if (!kelas) {
      return { allowed: false, reason: 'Class not found', user, tokenType: 'access' };
    }

    if (kelas.dosen_id !== user.sub) {
      return { allowed: false, reason: 'Dosen does not own this class', user, tokenType: 'access' };
    }

    if (kelas.is_finalized === 1) {
      return { allowed: false, reason: 'Class already finalized', user, tokenType: 'access' };
    }

    return { allowed: true, reason: 'Dosen authorized to finalize class', user, tokenType: 'access' };
  }

  // GET /transkrip/:nim
  const transkripMatch = path.match(/^\/transkrip\/([A-Za-z0-9]+)$/);
  if (transkripMatch && method === 'GET') {
    const nim = transkripMatch[1];

    if (user.role === 'admin') {
      return { allowed: true, reason: 'Admin can view all transcripts', user, tokenType: 'access' };
    }

    if (user.role === 'mahasiswa') {
      // Cek NIM miliknya
      const student = db.prepare('SELECT nim FROM users WHERE id = ?').get(user.sub);
      if (!student || student.nim !== nim) {
        return {
          allowed: false,
          reason: 'Mahasiswa can only view own transcript',
          user,
          tokenType: 'access',
        };
      }
      return { allowed: true, reason: 'Mahasiswa viewing own transcript', user, tokenType: 'access' };
    }

    // Dosen tidak memiliki akses transkrip
    return { allowed: false, reason: 'Dosen not authorized to view transcripts', user, tokenType: 'access' };
  }

  // POST /transkrip/sinkron — sudah ditangani di atas (service token check)
  // Seharusnya tidak sampai sini untuk endpoint ini

  // === Endpoint admin: GET /admin/audit-logs ===
  if (path === '/admin/audit-logs' && method === 'GET') {
    if (user.role !== 'admin') {
      return { allowed: false, reason: 'Only admin can view audit logs', user, tokenType: 'access' };
    }
    return { allowed: true, reason: 'Admin viewing audit logs', user, tokenType: 'access' };
  }

  // Default: deny unknown endpoints
  return { allowed: false, reason: 'Unknown endpoint or method', user, tokenType: 'access' };
}

module.exports = { evaluatePolicy };
