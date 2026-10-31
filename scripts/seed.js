/**
 * scripts/seed.js
 * Script seed database yang aman dijalankan ulang.
 * Menghapus data lama dan membuat data baru tanpa duplikasi.
 * Password di-hash menggunakan bcryptjs.
 */
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const bcrypt = require('bcryptjs');
const { createDatabase } = require('../shared/database');
const { createTables } = require('../shared/schema');

const DB_PATH = path.resolve(__dirname, '..', process.env.DB_PATH || './database/zero-trust.db');
const SALT_ROUNDS = 10;

function seed() {
  console.log('=== Memulai seed database ===');
  console.log('DB Path:', DB_PATH);

  const db = createDatabase(DB_PATH);

  // Buat tabel
  createTables(db);

  // Hapus data lama (urutan karena foreign key)
  const tables = [
    'audit_logs', 'refresh_tokens', 'transcripts', 'grades',
    'class_students', 'classes', 'devices', 'service_clients', 'users'
  ];
  for (const table of tables) {
    db.prepare(`DELETE FROM ${table}`).run();
  }
  console.log('Data lama dihapus.');

  // === USERS ===
  const password = 'password123';
  const hash = bcrypt.hashSync(password, SALT_ROUNDS);

  const insertUser = db.prepare(
    'INSERT INTO users (username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?)'
  );

  const users = [
    { username: 'admin1', role: 'admin', nama: 'Admin Utama', nim: null, nip: 'NIP001' },
    { username: 'dosen1', role: 'dosen', nama: 'Dr. Budi Santoso', nim: null, nip: 'NIP101' },
    { username: 'dosen2', role: 'dosen', nama: 'Dr. Siti Aminah', nim: null, nip: 'NIP102' },
    { username: 'mhs1', role: 'mahasiswa', nama: 'Andi Pratama', nim: 'MHS001', nip: null },
    { username: 'mhs2', role: 'mahasiswa', nama: 'Bela Putri', nim: 'MHS002', nip: null },
    { username: 'mhs3', role: 'mahasiswa', nama: 'Candra Wijaya', nim: 'MHS003', nip: null },
  ];

  const insertUsers = db.transaction(() => {
    for (const u of users) {
      insertUser.run(u.username, hash, u.role, u.nama, u.nim, u.nip);
    }
  });
  insertUsers();
  console.log('Users created:', users.length);

  // Ambil user IDs
  const getUser = db.prepare('SELECT id, username FROM users WHERE username = ?');
  const admin1 = getUser.get('admin1');
  const dosen1 = getUser.get('dosen1');
  const dosen2 = getUser.get('dosen2');
  const mhs1 = getUser.get('mhs1');
  const mhs2 = getUser.get('mhs2');
  const mhs3 = getUser.get('mhs3');

  // === DEVICES ===
  const insertDevice = db.prepare(
    'INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)'
  );

  const devices = [
    { user_id: admin1.id, device_id: 'DEVICE-ADMIN-001', device_name: 'Admin Laptop' },
    { user_id: dosen1.id, device_id: 'DEVICE-DSN-101', device_name: 'Dosen1 Laptop' },
    { user_id: dosen2.id, device_id: 'DEVICE-DSN-102', device_name: 'Dosen2 Laptop' },
    { user_id: mhs1.id, device_id: 'DEVICE-MHS-001', device_name: 'Andi Phone' },
    { user_id: mhs2.id, device_id: 'DEVICE-MHS-002', device_name: 'Bela Tablet' },
    { user_id: mhs3.id, device_id: 'DEVICE-MHS-003', device_name: 'Candra Laptop' },
  ];

  const insertDevices = db.transaction(() => {
    for (const d of devices) {
      insertDevice.run(d.user_id, d.device_id, d.device_name);
    }
  });
  insertDevices();
  console.log('Devices created:', devices.length);

  // === CLASSES ===
  const insertClass = db.prepare(
    'INSERT INTO classes (kode_kelas, nama_kelas, dosen_id, semester, sks) VALUES (?, ?, ?, ?, ?)'
  );

  insertClass.run('CS101', 'Pemrograman Dasar', dosen1.id, '2024/2025 Ganjil', 3);
  insertClass.run('CS202', 'Basis Data Lanjut', dosen2.id, '2024/2025 Ganjil', 3);
  console.log('Classes created: 2');

  const getClass = db.prepare('SELECT id FROM classes WHERE kode_kelas = ?');
  const cs101 = getClass.get('CS101');
  const cs202 = getClass.get('CS202');

  // === CLASS_STUDENTS ===
  const insertClassStudent = db.prepare(
    'INSERT INTO class_students (class_id, student_id) VALUES (?, ?)'
  );

  // CS101: mhs1, mhs2
  insertClassStudent.run(cs101.id, mhs1.id);
  insertClassStudent.run(cs101.id, mhs2.id);
  // CS202: mhs2, mhs3
  insertClassStudent.run(cs202.id, mhs2.id);
  insertClassStudent.run(cs202.id, mhs3.id);
  console.log('Class students assigned.');

  // === GRADES ===
  const insertGrade = db.prepare(
    'INSERT INTO grades (class_id, student_id, nilai, huruf, is_finalized) VALUES (?, ?, ?, ?, ?)'
  );

  // CS101 grades (belum final)
  insertGrade.run(cs101.id, mhs1.id, 85.0, 'A', 0);
  insertGrade.run(cs101.id, mhs2.id, 72.0, 'B', 0);
  // CS202 grades (belum final)
  insertGrade.run(cs202.id, mhs2.id, 90.0, 'A', 0);
  insertGrade.run(cs202.id, mhs3.id, 65.0, 'C', 0);
  console.log('Grades created: 4');

  // === TRANSCRIPTS (awalnya kosong, akan diisi saat sinkronisasi) ===
  console.log('Transcripts: kosong (akan diisi saat finalisasi + sinkronisasi)');

  // === SERVICE CLIENTS ===
  const serviceSecret = process.env.SERVICE_CLIENT_SECRET || 'default-service-secret';
  const serviceSecretHash = bcrypt.hashSync(serviceSecret, SALT_ROUNDS);
  const insertServiceClient = db.prepare(
    'INSERT INTO service_clients (client_id, client_secret_hash, service_name) VALUES (?, ?, ?)'
  );
  insertServiceClient.run(
    process.env.SERVICE_CLIENT_ID || 'grade-service',
    serviceSecretHash,
    'Grade Service'
  );
  console.log('Service clients created: 1');

  db.close();

  console.log('\n=== Seed selesai ===');
  console.log('\n--- Akun Demo ---');
  console.log('Password semua akun: password123 (di-hash bcrypt)');
  console.log('');
  console.log('| Username | Role      | NIM/NIP | Device ID        |');
  console.log('|----------|-----------|---------|------------------|');
  console.log('| admin1   | admin     | NIP001  | DEVICE-ADMIN-001 |');
  console.log('| dosen1   | dosen     | NIP101  | DEVICE-DSN-101   |');
  console.log('| dosen2   | dosen     | NIP102  | DEVICE-DSN-102   |');
  console.log('| mhs1     | mahasiswa | MHS001  | DEVICE-MHS-001   |');
  console.log('| mhs2     | mahasiswa | MHS002  | DEVICE-MHS-002   |');
  console.log('| mhs3     | mahasiswa | MHS003  | DEVICE-MHS-003   |');
  console.log('');
  console.log('--- Kelas ---');
  console.log('CS101 - Pemrograman Dasar (dosen1) -> mhs1, mhs2');
  console.log('CS202 - Basis Data Lanjut (dosen2) -> mhs2, mhs3');
}

seed();
