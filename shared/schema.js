/**
 * shared/schema.js
 * Skema database untuk seluruh tabel.
 * Dipanggil saat seed dan inisialisasi testing.
 */

/**
 * Membuat seluruh tabel pada database yang diberikan.
 * Menggunakan IF NOT EXISTS agar aman dijalankan ulang.
 * @param {import('better-sqlite3').Database} db
 */
function createTables(db) {
  db.exec(`
    -- Tabel users: menyimpan semua pengguna (admin, dosen, mahasiswa)
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'dosen', 'mahasiswa')),
      nama TEXT NOT NULL,
      nim TEXT UNIQUE,
      nip TEXT UNIQUE,
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- Tabel devices: satu device per pengguna pada data awal
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT,
      registered_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(user_id, device_id)
    );

    -- Tabel classes: kelas yang diampu dosen
    CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kode_kelas TEXT UNIQUE NOT NULL,
      nama_kelas TEXT NOT NULL,
      dosen_id INTEGER NOT NULL,
      semester TEXT NOT NULL,
      sks INTEGER NOT NULL DEFAULT 3,
      is_finalized INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (dosen_id) REFERENCES users(id)
    );

    -- Tabel class_students: relasi kelas-mahasiswa
    CREATE TABLE IF NOT EXISTS class_students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      class_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL,
      FOREIGN KEY (class_id) REFERENCES classes(id),
      FOREIGN KEY (student_id) REFERENCES users(id),
      UNIQUE(class_id, student_id)
    );

    -- Tabel grades: nilai mahasiswa per kelas
    CREATE TABLE IF NOT EXISTS grades (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      class_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL,
      nilai REAL,
      huruf TEXT,
      is_finalized INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (class_id) REFERENCES classes(id),
      FOREIGN KEY (student_id) REFERENCES users(id),
      UNIQUE(class_id, student_id)
    );

    -- Tabel transcripts: transkrip mahasiswa
    CREATE TABLE IF NOT EXISTS transcripts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      nim TEXT NOT NULL,
      kode_kelas TEXT NOT NULL,
      nama_kelas TEXT NOT NULL,
      sks INTEGER NOT NULL,
      nilai REAL,
      huruf TEXT,
      semester TEXT NOT NULL,
      synced_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (student_id) REFERENCES users(id),
      UNIQUE(student_id, kode_kelas)
    );

    -- Tabel refresh_tokens: menyimpan hash refresh token
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      is_revoked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Tabel service_clients: kredensial untuk identitas service
    CREATE TABLE IF NOT EXISTS service_clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT UNIQUE NOT NULL,
      client_secret_hash TEXT NOT NULL,
      service_name TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- Tabel audit_logs: log keputusan akses
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT DEFAULT (datetime('now')),
      request_id TEXT,
      method TEXT,
      endpoint TEXT,
      subject TEXT,
      role TEXT,
      device_id TEXT,
      decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
      reason TEXT,
      ip_address TEXT
    );
  `);
}

module.exports = { createTables };
