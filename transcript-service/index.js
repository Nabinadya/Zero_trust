/**
 * transcript-service/index.js
 * Service Transkrip — Port 3002
 * 
 * Mengelola data transkrip mahasiswa.
 * Setiap request WAJIB melewati verifikasi:
 * 1. X-Gateway-Secret (dari gateway)
 * 2. Token JWT yang sesuai (access token untuk GET, service token untuk POST sinkron)
 * 
 * Service ini TIDAK boleh diakses langsung oleh pengguna.
 */
const express = require('express');
const config = require('../shared/config');
const { getDatabase } = require('../shared/database');
const { createTables } = require('../shared/schema');
const {
  verifyGatewaySecret,
  verifyUserToken,
  verifyServiceTokenMiddleware,
} = require('../shared/service-auth');

const app = express();
app.use(express.json());

// Inisialisasi database
const db = getDatabase();
createTables(db);

// === Semua route memerlukan gateway secret ===
app.use(verifyGatewaySecret);

/**
 * GET /transkrip/:nim
 * Mahasiswa: hanya NIM miliknya.
 * Admin: semua NIM.
 * (Policy Engine sudah memverifikasi di gateway, service tetap verifikasi token)
 */
app.get('/transkrip/:nim', verifyUserToken, (req, res) => {
  const nim = req.params.nim;
  const user = req.user;
  const db = getDatabase();

  try {
    // Defense in depth: service juga cek ownership
    if (user.role === 'mahasiswa') {
      const student = db.prepare('SELECT nim FROM users WHERE id = ?').get(user.sub);
      if (!student || student.nim !== nim) {
        return res.status(403).json({ error: 'Anda hanya boleh melihat transkrip Anda sendiri' });
      }
    } else if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Anda tidak memiliki akses ke transkrip' });
    }

    const transcripts = db.prepare(`
      SELECT t.*, u.nama as nama_mahasiswa
      FROM transcripts t
      JOIN users u ON t.student_id = u.id
      WHERE t.nim = ?
      ORDER BY t.semester, t.kode_kelas
    `).all(nim);

    // Hitung IPK
    let totalBobot = 0;
    let totalSks = 0;
    const nilaiToAngka = { 'A': 4, 'B': 3, 'C': 2, 'D': 1, 'E': 0 };

    for (const t of transcripts) {
      if (t.huruf && nilaiToAngka[t.huruf] !== undefined) {
        totalBobot += nilaiToAngka[t.huruf] * t.sks;
        totalSks += t.sks;
      }
    }

    const ipk = totalSks > 0 ? (totalBobot / totalSks).toFixed(2) : '0.00';

    res.json({
      nim,
      transcripts,
      summary: {
        total_sks: totalSks,
        ipk: parseFloat(ipk),
      },
    });
  } catch (err) {
    console.error('[TRANSCRIPT SERVICE ERROR]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /transkrip/sinkron
 * Hanya menerima service token (bukan user token, termasuk admin).
 * Menyinkronkan data nilai yang sudah difinalisasi ke transkrip.
 */
app.post('/transkrip/sinkron', verifyServiceTokenMiddleware, (req, res) => {
  const { grades, classId } = req.body;
  const db = getDatabase();

  if (!grades || !Array.isArray(grades) || grades.length === 0) {
    return res.status(400).json({ error: 'Data grades wajib disertakan' });
  }

  try {
    const upsertTranscript = db.prepare(`
      INSERT INTO transcripts (student_id, nim, kode_kelas, nama_kelas, sks, nilai, huruf, semester, synced_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(student_id, kode_kelas) DO UPDATE SET
        nilai = excluded.nilai,
        huruf = excluded.huruf,
        synced_at = datetime('now')
    `);

    const syncTransaction = db.transaction(() => {
      for (const grade of grades) {
        upsertTranscript.run(
          grade.student_id,
          grade.nim,
          grade.kode_kelas,
          grade.nama_kelas,
          grade.sks,
          grade.nilai,
          grade.huruf,
          grade.semester
        );
      }
    });

    syncTransaction();

    res.json({
      message: 'Sinkronisasi transkrip berhasil',
      synced_count: grades.length,
      classId,
    });
  } catch (err) {
    console.error('[TRANSCRIPT SERVICE ERROR]', err.message);
    return res.status(500).json({ error: 'Sinkronisasi gagal: ' + err.message });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan pada Transcript Service' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('[TRANSCRIPT SERVICE ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(config.transcriptServicePort, () => {
    console.log(`[Transcript Service] berjalan di port ${config.transcriptServicePort}`);
  });
}

module.exports = app;
