/**
 * gateway/audit.js
 * Modul audit log untuk API Gateway.
 * Mencatat keputusan ALLOW dan DENY ke database.
 * TIDAK menyimpan password, token lengkap, atau secret.
 */
const { getDatabase } = require('../shared/database');

/**
 * Mencatat keputusan akses ke audit_logs.
 * @param {object} entry
 * @param {string} entry.requestId
 * @param {string} entry.method
 * @param {string} entry.endpoint
 * @param {string} entry.subject - username atau identitas (BUKAN token)
 * @param {string} entry.role
 * @param {string} entry.deviceId
 * @param {string} entry.decision - 'ALLOW' atau 'DENY'
 * @param {string} entry.reason
 * @param {string} entry.ipAddress
 */
function logAudit(entry) {
  try {
    const db = getDatabase();
    db.prepare(`
      INSERT INTO audit_logs (request_id, method, endpoint, subject, role, device_id, decision, reason, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.requestId || null,
      entry.method || null,
      entry.endpoint || null,
      entry.subject || null,
      entry.role || null,
      entry.deviceId || null,
      entry.decision,
      entry.reason || null,
      entry.ipAddress || null
    );
  } catch (err) {
    // Log error ke console tapi jangan crash server
    console.error('[AUDIT ERROR] Failed to write audit log:', err.message);
  }
}

module.exports = { logAudit };
