/**
 * grade-service/index.js
 * Service Nilai — Port 3001
 * 
 * Mengelola data nilai mahasiswa.
 * Setiap request WAJIB melewati verifikasi:
 * 1. X-Gateway-Secret (dari gateway)
 * 2. Token JWT (signature, expiry, algorithm)
 * 
 * Service ini TIDAK boleh diakses langsung oleh pengguna.
 */
const express = require('express');
const config = require('../shared/config');
const { getDatabase } = require('../shared/database');
const { createTables } = require('../shared/schema');
const { verifyGatewaySecret, verifyUserToken } = require('../shared/service-auth');

const app = express();
app.use(express.json());

// Inisialisasi database
const db = getDatabase();
createTables(db);

// === Semua route memerlukan gateway secret ===
app.use(verifyGatewaySecret);

/**
 * GET /nilai
 * Mahasiswa: hanya melihat nilai miliknya.
 * Dosen: hanya melihat nilai kelas yang diampunya.
 */
app.get('/nilai', verifyUserToken, (req, res) => {
  const user = req.user;
  const db = getDatabase();

  try {
    if (user.role === 'mahasiswa') {
      const grades = db.prepare(`
        SELECT g.id, g.nilai, g.huruf, g.is_finalized,
               c.kode_kelas, c.nama_kelas, c.semester,
               u.nama as nama_mahasiswa, u.nim
        FROM grades g
        JOIN classes c ON g.class_id = c.id
        JOIN users u ON g.student_id = u.id
        WHERE g.student_id = ?
      `).all(user.sub);

      return res.json({ grades });
    }

    if (user.role === 'dosen') {
      const grades = db.prepare(`
        SELECT g.id, g.nilai, g.huruf, g.is_finalized,
               c.kode_kelas, c.nama_kelas, c.semester, c.id as class_id,
               u.nama as nama_mahasiswa, u.nim
        FROM grades g
        JOIN classes c ON g.class_id = c.id
        JOIN users u ON g.student_id = u.id
        WHERE c.dosen_id = ?
        ORDER BY c.kode_kelas, u.nama
      `).all(user.sub);

      return res.json({ grades });
    }

    return res.status(403).json({ error: 'Role tidak memiliki akses ke endpoint ini' });
  } catch (err) {
    console.error('[GRADE SERVICE ERROR]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * PUT /nilai/:id
 * Hanya dosen yang mengampu kelas terkait.
 * Nilai belum difinalisasi.
 * (Policy Engine sudah memverifikasi ownership & jam akses di gateway)
 * (Service tetap memverifikasi token dan gateway secret)
 */
app.put('/nilai/:id', verifyUserToken, (req, res) => {
  const gradeId = parseInt(req.params.id, 10);
  const user = req.user;
  const { nilai, huruf } = req.body;
  const db = getDatabase();

  if (nilai === undefined && huruf === undefined) {
    return res.status(400).json({ error: 'Nilai atau huruf wajib diisi' });
  }

  try {
    // Service juga memverifikasi ownership (defense in depth)
    const grade = db.prepare(`
      SELECT g.*, c.dosen_id, c.is_finalized as class_finalized
      FROM grades g
      JOIN classes c ON g.class_id = c.id
      WHERE g.id = ?
    `).get(gradeId);

    if (!grade) {
      return res.status(404).json({ error: 'Nilai tidak ditemukan' });
    }

    if (grade.dosen_id !== user.sub) {
      return res.status(403).json({ error: 'Anda bukan dosen pengampu kelas ini' });
    }

    if (grade.is_finalized === 1) {
      return res.status(403).json({ error: 'Nilai sudah difinalisasi, tidak dapat diubah' });
    }

    // Update nilai
    const updateFields = [];
    const updateValues = [];

    if (nilai !== undefined) {
      updateFields.push('nilai = ?');
      updateValues.push(nilai);
    }
    if (huruf !== undefined) {
      updateFields.push('huruf = ?');
      updateValues.push(huruf);
    }
    updateFields.push("updated_at = datetime('now')");
    updateValues.push(gradeId);

    db.prepare(
      `UPDATE grades SET ${updateFields.join(', ')} WHERE id = ?`
    ).run(...updateValues);

    const updated = db.prepare('SELECT * FROM grades WHERE id = ?').get(gradeId);

    res.json({
      message: 'Nilai berhasil diperbarui',
      grade: updated,
    });
  } catch (err) {
    console.error('[GRADE SERVICE ERROR]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /kelas/:id/finalisasi
 * Finalisasi kelas oleh dosen pengampu.
 * Setelah berhasil, melakukan sinkronisasi transkrip melalui gateway.
 */
app.post('/kelas/:id/finalisasi', verifyUserToken, async (req, res) => {
  const classParam = req.params.id;
  const user = req.user;
  const db = getDatabase();

  try {
    // Defense in depth: service juga cek ownership (by id atau kode_kelas)
    const kelas = db.prepare('SELECT * FROM classes WHERE id = ? OR kode_kelas = ?').get(classParam, classParam);

    if (!kelas) {
      return res.status(404).json({ error: 'Kelas tidak ditemukan' });
    }

    const classId = kelas.id;

    if (kelas.dosen_id !== user.sub) {
      return res.status(403).json({ error: 'Anda bukan dosen pengampu kelas ini' });
    }

    if (kelas.is_finalized === 1) {
      return res.status(400).json({ error: 'Kelas sudah difinalisasi sebelumnya' });
    }

    // Cek semua mahasiswa di kelas punya nilai
    const studentsWithoutGrades = db.prepare(`
      SELECT cs.student_id
      FROM class_students cs
      LEFT JOIN grades g ON cs.class_id = g.class_id AND cs.student_id = g.student_id
      WHERE cs.class_id = ? AND (g.nilai IS NULL OR g.huruf IS NULL)
    `).all(classId);

    if (studentsWithoutGrades.length > 0) {
      return res.status(400).json({
        error: 'Semua mahasiswa harus memiliki nilai sebelum finalisasi',
        students_without_grades: studentsWithoutGrades.length,
      });
    }

    // Finalisasi: update kelas dan semua nilai di dalamnya dalam transaksi
    const finalizeTransaction = db.transaction(() => {
      db.prepare('UPDATE classes SET is_finalized = 1 WHERE id = ?').run(classId);
      db.prepare('UPDATE grades SET is_finalized = 1 WHERE class_id = ?').run(classId);
    });

    finalizeTransaction();

    // === Sinkronisasi transkrip melalui gateway ===
    let syncResult = null;
    try {
      // 1. Dapatkan service token dari gateway
      const authResponse = await fetch(`${config.gatewayUrl}/auth/service`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientId: config.serviceClientId,
          clientSecret: config.serviceClientSecret,
        }),
      });

      if (!authResponse.ok) {
        throw new Error(`Failed to get service token: ${authResponse.status}`);
      }

      const authData = await authResponse.json();
      const serviceToken = authData.serviceToken;

      // 2. Ambil data nilai yang sudah difinalisasi
      const grades = db.prepare(`
        SELECT g.*, c.kode_kelas, c.nama_kelas, c.semester, c.sks,
               u.nim, u.id as student_id
        FROM grades g
        JOIN classes c ON g.class_id = c.id
        JOIN users u ON g.student_id = u.id
        WHERE g.class_id = ?
      `).all(classId);

      // 3. Kirim sinkronisasi melalui gateway (bukan langsung ke port 3002)
      const syncResponse = await fetch(`${config.gatewayUrl}/transkrip/sinkron`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${serviceToken}`,
        },
        body: JSON.stringify({ grades, classId }),
      });

      if (!syncResponse.ok) {
        const syncError = await syncResponse.json();
        throw new Error(`Sync failed: ${syncError.error || syncResponse.status}`);
      }

      syncResult = await syncResponse.json();
    } catch (syncErr) {
      // Sinkronisasi gagal — rollback finalisasi
      console.error('[GRADE SERVICE] Sync failed, rolling back finalization:', syncErr.message);
      const rollbackTransaction = db.transaction(() => {
        db.prepare('UPDATE classes SET is_finalized = 0 WHERE id = ?').run(classId);
        db.prepare('UPDATE grades SET is_finalized = 0 WHERE class_id = ?').run(classId);
      });
      rollbackTransaction();

      return res.status(500).json({
        error: 'Finalisasi dibatalkan karena sinkronisasi transkrip gagal',
        detail: syncErr.message,
      });
    }

    res.json({
      message: 'Kelas berhasil difinalisasi dan transkrip tersinkronisasi',
      classId,
      sync: syncResult,
    });
  } catch (err) {
    console.error('[GRADE SERVICE ERROR]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan pada Grade Service' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('[GRADE SERVICE ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(config.gradeServicePort, () => {
    console.log(`[Grade Service] berjalan di port ${config.gradeServicePort}`);
  });
}

module.exports = app;
