/**
 * tests/security.test.js
 * Pengujian keamanan otomatis untuk seluruh skenario Zero Trust.
 * 
 * Test ini menjalankan ketiga service dan melakukan request nyata
 * untuk memverifikasi kebijakan keamanan.
 */
const { cleanTestDb } = require('./setup');
// Clean test database BEFORE any modules load their DB connections
cleanTestDb();

const request = require('supertest');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');

// Now require modules after env vars are set
const config = require('../shared/config');
const { createDatabase } = require('../shared/database');
const { createTables } = require('../shared/schema');
const { setOverrideHour } = require('../shared/clock');

// Import apps
let gatewayApp, gradeApp, transcriptApp;
let gradeServer, transcriptServer;
let db;

const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_SERVICE_SECRET = process.env.JWT_SERVICE_SECRET;

// Seed test data
function seedTestData(db) {
  const hash = bcrypt.hashSync('password123', 10);

  // Users
  db.prepare(`INSERT INTO users (id, username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(1, 'admin1', hash, 'admin', 'Admin Utama', null, 'NIP001');
  db.prepare(`INSERT INTO users (id, username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(2, 'dosen1', hash, 'dosen', 'Dr. Budi', null, 'NIP101');
  db.prepare(`INSERT INTO users (id, username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(3, 'dosen2', hash, 'dosen', 'Dr. Siti', null, 'NIP102');
  db.prepare(`INSERT INTO users (id, username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(4, 'mhs1', hash, 'mahasiswa', 'Andi', 'MHS001', null);
  db.prepare(`INSERT INTO users (id, username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(5, 'mhs2', hash, 'mahasiswa', 'Bela', 'MHS002', null);
  db.prepare(`INSERT INTO users (id, username, password_hash, role, nama, nim, nip) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(6, 'mhs3', hash, 'mahasiswa', 'Candra', 'MHS003', null);

  // Devices
  db.prepare(`INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)`).run(1, 'DEVICE-ADMIN-001', 'Admin Laptop');
  db.prepare(`INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)`).run(2, 'DEVICE-DSN-101', 'Dosen1 Laptop');
  db.prepare(`INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)`).run(3, 'DEVICE-DSN-102', 'Dosen2 Laptop');
  db.prepare(`INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)`).run(4, 'DEVICE-MHS-001', 'Andi Phone');
  db.prepare(`INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)`).run(5, 'DEVICE-MHS-002', 'Bela Tablet');
  db.prepare(`INSERT INTO devices (user_id, device_id, device_name) VALUES (?, ?, ?)`).run(6, 'DEVICE-MHS-003', 'Candra Laptop');

  // Classes
  db.prepare(`INSERT INTO classes (id, kode_kelas, nama_kelas, dosen_id, semester, sks) VALUES (?, ?, ?, ?, ?, ?)`).run(1, 'CS101', 'Pemrograman Dasar', 2, '2024/2025 Ganjil', 3);
  db.prepare(`INSERT INTO classes (id, kode_kelas, nama_kelas, dosen_id, semester, sks) VALUES (?, ?, ?, ?, ?, ?)`).run(2, 'CS202', 'Basis Data Lanjut', 3, '2024/2025 Ganjil', 3);

  // Class students
  db.prepare(`INSERT INTO class_students (class_id, student_id) VALUES (?, ?)`).run(1, 4); // mhs1 in CS101
  db.prepare(`INSERT INTO class_students (class_id, student_id) VALUES (?, ?)`).run(1, 5); // mhs2 in CS101
  db.prepare(`INSERT INTO class_students (class_id, student_id) VALUES (?, ?)`).run(2, 5); // mhs2 in CS202
  db.prepare(`INSERT INTO class_students (class_id, student_id) VALUES (?, ?)`).run(2, 6); // mhs3 in CS202

  // Grades
  db.prepare(`INSERT INTO grades (id, class_id, student_id, nilai, huruf, is_finalized) VALUES (?, ?, ?, ?, ?, ?)`).run(1, 1, 4, 85.0, 'A', 0);
  db.prepare(`INSERT INTO grades (id, class_id, student_id, nilai, huruf, is_finalized) VALUES (?, ?, ?, ?, ?, ?)`).run(2, 1, 5, 72.0, 'B', 0);
  db.prepare(`INSERT INTO grades (id, class_id, student_id, nilai, huruf, is_finalized) VALUES (?, ?, ?, ?, ?, ?)`).run(3, 2, 5, 90.0, 'A', 0);
  db.prepare(`INSERT INTO grades (id, class_id, student_id, nilai, huruf, is_finalized) VALUES (?, ?, ?, ?, ?, ?)`).run(4, 2, 6, 65.0, 'C', 0);

  // Service clients
  const svcHash = bcrypt.hashSync(process.env.SERVICE_CLIENT_SECRET, 10);
  db.prepare(`INSERT INTO service_clients (client_id, client_secret_hash, service_name) VALUES (?, ?, ?)`).run('grade-service', svcHash, 'Grade Service');
}

let gatewayServer;

// Helper: login dan dapatkan token
async function loginUser(username, deviceId) {
  const res = await request(gatewayApp)
    .post('/auth/login')
    .set('X-Device-ID', deviceId)
    .send({ username, password: 'password123' });
  return res.body;
}

beforeAll(async () => {
  // Setup test database
  const testDbPath = path.resolve(__dirname, '..', 'database', 'test.db');
  db = createDatabase(testDbPath);
  createTables(db);
  seedTestData(db);

  // Perlu memanipulasi singleton agar modules menggunakan database test
  // Override getDatabase
  const dbModule = require('../shared/database');
  dbModule.getDatabase = function () { return db; };

  // Set waktu ke jam kerja (dalam jam akses)
  setOverrideHour(10);

  // Load apps
  gatewayApp = require('../gateway/index');
  gradeApp = require('../grade-service/index');
  transcriptApp = require('../transcript-service/index');

  // Start ALL services on test ports - gateway must also listen
  // so that proxy middleware can forward requests to backend services
  await new Promise((resolve) => {
    gradeServer = gradeApp.listen(parseInt(process.env.GRADE_SERVICE_PORT, 10), () => {
      console.log(`Test Grade Service on port ${process.env.GRADE_SERVICE_PORT}`);
      resolve();
    });
  });

  await new Promise((resolve) => {
    transcriptServer = transcriptApp.listen(parseInt(process.env.TRANSCRIPT_SERVICE_PORT, 10), () => {
      console.log(`Test Transcript Service on port ${process.env.TRANSCRIPT_SERVICE_PORT}`);
      resolve();
    });
  });

  // Gateway must also listen for proxy to work AND for grade-service to call back
  await new Promise((resolve) => {
    gatewayServer = gatewayApp.listen(parseInt(process.env.GATEWAY_PORT, 10), () => {
      console.log(`Test Gateway on port ${process.env.GATEWAY_PORT}`);
      resolve();
    });
  });
});

afterAll(async () => {
  setOverrideHour(null);
  if (gatewayServer) gatewayServer.close();
  if (gradeServer) gradeServer.close();
  if (transcriptServer) transcriptServer.close();
  if (db) db.close();

  // Clean up test database
  const fs = require('fs');
  const testDbPath = path.resolve(__dirname, '..', 'database', 'test.db');
  for (const ext of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(testDbPath + ext); } catch (e) { /* ignore */ }
  }
});

// =============================================
// TEST SUITE: AUTENTIKASI
// =============================================
describe('Autentikasi', () => {
  test('Login berhasil dengan kredensial dan device yang benar', async () => {
    const res = await request(gatewayApp)
      .post('/auth/login')
      .set('X-Device-ID', 'DEVICE-MHS-001')
      .send({ username: 'mhs1', password: 'password123' });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
    expect(res.body.user.role).toBe('mahasiswa');
  });

  test('Login gagal dengan password salah', async () => {
    const res = await request(gatewayApp)
      .post('/auth/login')
      .set('X-Device-ID', 'DEVICE-MHS-001')
      .send({ username: 'mhs1', password: 'wrongpassword' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBeDefined();
  });

  test('Login gagal dengan device tidak terdaftar', async () => {
    const res = await request(gatewayApp)
      .post('/auth/login')
      .set('X-Device-ID', 'UNKNOWN-DEVICE')
      .send({ username: 'mhs1', password: 'password123' });

    expect(res.status).toBe(403);
  });

  test('Login gagal tanpa X-Device-ID', async () => {
    const res = await request(gatewayApp)
      .post('/auth/login')
      .send({ username: 'mhs1', password: 'password123' });

    expect(res.status).toBe(400);
  });

  test('Login gagal dengan username tidak ada', async () => {
    const res = await request(gatewayApp)
      .post('/auth/login')
      .set('X-Device-ID', 'DEVICE-MHS-001')
      .send({ username: 'nobody', password: 'password123' });

    expect(res.status).toBe(401);
  });
});

// =============================================
// TEST SUITE: REFRESH TOKEN
// =============================================
describe('Refresh Token', () => {
  let refreshToken;

  beforeAll(async () => {
    const data = await loginUser('mhs1', 'DEVICE-MHS-001');
    refreshToken = data.refreshToken;
  });

  test('Refresh token berhasil menghasilkan access token baru', async () => {
    const res = await request(gatewayApp)
      .post('/auth/refresh')
      .send({ refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
  });

  test('Logout mencabut refresh token', async () => {
    // Login lagi untuk token baru
    const loginData = await loginUser('mhs1', 'DEVICE-MHS-001');
    const rt = loginData.refreshToken;

    // Logout
    const logoutRes = await request(gatewayApp)
      .post('/auth/logout')
      .send({ refreshToken: rt });

    expect(logoutRes.status).toBe(200);

    // Coba refresh dengan token yang sudah dicabut
    const refreshRes = await request(gatewayApp)
      .post('/auth/refresh')
      .send({ refreshToken: rt });

    expect(refreshRes.status).toBe(401);
  });

  test('Refresh token yang sudah dicabut ditolak', async () => {
    const loginData = await loginUser('mhs2', 'DEVICE-MHS-002');
    const rt = loginData.refreshToken;

    // Cabut
    await request(gatewayApp).post('/auth/logout').send({ refreshToken: rt });

    // Coba pakai lagi
    const res = await request(gatewayApp)
      .post('/auth/refresh')
      .send({ refreshToken: rt });

    expect(res.status).toBe(401);
  });
});

// =============================================
// TEST SUITE: TOKEN VALIDATION
// =============================================
describe('Token Validation', () => {
  test('Request tanpa token ditolak', async () => {
    const res = await request(gatewayApp)
      .get('/nilai')
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(401);
  });

  test('JWT kedaluwarsa ditolak', async () => {
    // Buat token yang sudah expired
    const expiredToken = jwt.sign(
      { sub: 4, role: 'mahasiswa', username: 'mhs1', type: 'access' },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '0s' }
    );

    // Tunggu sedikit agar benar-benar expired
    await new Promise(r => setTimeout(r, 1100));

    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${expiredToken}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(401);
  });

  test('JWT dengan signature tidak valid ditolak', async () => {
    const fakeToken = jwt.sign(
      { sub: 4, role: 'mahasiswa', username: 'mhs1', type: 'access' },
      'wrong-secret',
      { algorithm: 'HS256', expiresIn: '10m' }
    );

    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${fakeToken}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(401);
  });
});

// =============================================
// TEST SUITE: DEVICE VERIFICATION
// =============================================
describe('Device Verification', () => {
  let mhs1Token;

  beforeAll(async () => {
    const data = await loginUser('mhs1', 'DEVICE-MHS-001');
    mhs1Token = data.accessToken;
  });

  test('Request tanpa X-Device-ID di luar /auth/* ditolak', async () => {
    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${mhs1Token}`);

    expect(res.status).toBe(403);
  });

  test('Request dengan device milik user lain ditolak', async () => {
    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-002');

    expect(res.status).toBe(403);
  });

  test('Request dengan device terdaftar diterima', async () => {
    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(200);
  });
});

// =============================================
// TEST SUITE: AKSES NILAI
// =============================================
describe('Akses Nilai', () => {
  let mhs1Token, mhs2Token, dosen1Token, dosen2Token;

  beforeAll(async () => {
    const d1 = await loginUser('mhs1', 'DEVICE-MHS-001');
    mhs1Token = d1.accessToken;
    const d2 = await loginUser('mhs2', 'DEVICE-MHS-002');
    mhs2Token = d2.accessToken;
    const d3 = await loginUser('dosen1', 'DEVICE-DSN-101');
    dosen1Token = d3.accessToken;
    const d4 = await loginUser('dosen2', 'DEVICE-DSN-102');
    dosen2Token = d4.accessToken;
  });

  test('Mahasiswa melihat nilai miliknya sendiri', async () => {
    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(200);
    // Semua nilai harus milik mhs1
    for (const g of res.body.grades) {
      expect(g.nim).toBe('MHS001');
    }
  });

  test('Dosen melihat nilai kelas yang diampunya', async () => {
    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101');

    expect(res.status).toBe(200);
    // Semua nilai harus dari kelas CS101
    for (const g of res.body.grades) {
      expect(g.kode_kelas).toBe('CS101');
    }
  });

  test('Dosen mengubah nilai kelas sendiri berhasil', async () => {
    const res = await request(gatewayApp)
      .put('/nilai/1')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101')
      .send({ nilai: 90, huruf: 'A' });

    expect(res.status).toBe(200);
    expect(res.body.grade.nilai).toBe(90);
  });

  test('Dosen mengubah nilai kelas bukan miliknya ditolak', async () => {
    // dosen2 coba ubah grade 1 (milik kelas CS101 / dosen1)
    const res = await request(gatewayApp)
      .put('/nilai/1')
      .set('Authorization', `Bearer ${dosen2Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-102')
      .send({ nilai: 50, huruf: 'D' });

    expect(res.status).toBe(403);
  });
});

// =============================================
// TEST SUITE: JAM AKSES
// =============================================
describe('Jam Akses', () => {
  let dosen1Token;

  beforeAll(async () => {
    const data = await loginUser('dosen1', 'DEVICE-DSN-101');
    dosen1Token = data.accessToken;
  });

  test('Perubahan nilai di luar jam akses ditolak', async () => {
    // Set jam ke 22:00 (di luar 07-21)
    setOverrideHour(22);

    const res = await request(gatewayApp)
      .put('/nilai/1')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101')
      .send({ nilai: 88, huruf: 'A' });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('outside allowed hours');

    // Kembalikan ke jam kerja
    setOverrideHour(10);
  });

  test('Finalisasi di luar jam akses ditolak', async () => {
    setOverrideHour(5); // 05:00

    const res = await request(gatewayApp)
      .post('/kelas/1/finalisasi')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101');

    expect(res.status).toBe(403);

    setOverrideHour(10);
  });
});

// =============================================
// TEST SUITE: GATEWAY SECRET
// =============================================
describe('Gateway Secret', () => {
  let mhs1Token;

  beforeAll(async () => {
    const data = await loginUser('mhs1', 'DEVICE-MHS-001');
    mhs1Token = data.accessToken;
  });

  test('Request langsung ke Grade Service tanpa gateway secret ditolak', async () => {
    const res = await request(gradeApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('API Gateway');
  });

  test('Request dengan gateway secret tapi token tidak valid ditolak', async () => {
    const res = await request(gradeApp)
      .get('/nilai')
      .set('X-Gateway-Secret', GATEWAY_SECRET)
      .set('Authorization', 'Bearer invalid-token')
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(401);
  });

  test('Request langsung ke Transcript Service tanpa gateway secret ditolak', async () => {
    const res = await request(transcriptApp)
      .get('/transkrip/MHS001')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(403);
  });
});

// =============================================
// TEST SUITE: TRANSKRIP
// =============================================
describe('Transkrip', () => {
  let mhs1Token, mhs2Token, admin1Token, dosen1Token;

  beforeAll(async () => {
    const d1 = await loginUser('mhs1', 'DEVICE-MHS-001');
    mhs1Token = d1.accessToken;
    const d2 = await loginUser('mhs2', 'DEVICE-MHS-002');
    mhs2Token = d2.accessToken;
    const d3 = await loginUser('admin1', 'DEVICE-ADMIN-001');
    admin1Token = d3.accessToken;
    const d4 = await loginUser('dosen1', 'DEVICE-DSN-101');
    dosen1Token = d4.accessToken;
  });

  test('Mahasiswa melihat transkrip miliknya sendiri', async () => {
    const res = await request(gatewayApp)
      .get('/transkrip/MHS001')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(200);
    expect(res.body.nim).toBe('MHS001');
  });

  test('Mahasiswa mengakses transkrip mahasiswa lain ditolak', async () => {
    const res = await request(gatewayApp)
      .get('/transkrip/MHS002')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(403);
  });

  test('Admin melihat transkrip semua mahasiswa', async () => {
    const res = await request(gatewayApp)
      .get('/transkrip/MHS001')
      .set('Authorization', `Bearer ${admin1Token}`)
      .set('X-Device-ID', 'DEVICE-ADMIN-001');

    expect(res.status).toBe(200);
  });

  test('Dosen tidak boleh melihat transkrip', async () => {
    const res = await request(gatewayApp)
      .get('/transkrip/MHS001')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101');

    expect(res.status).toBe(403);
  });
});

// =============================================
// TEST SUITE: SINKRONISASI (SERVICE TOKEN)
// =============================================
describe('Sinkronisasi Transkrip', () => {
  let mhs1Token, admin1Token;

  beforeAll(async () => {
    const d1 = await loginUser('mhs1', 'DEVICE-MHS-001');
    mhs1Token = d1.accessToken;
    const d2 = await loginUser('admin1', 'DEVICE-ADMIN-001');
    admin1Token = d2.accessToken;
  });

  test('User biasa mencoba endpoint sinkronisasi ditolak', async () => {
    const res = await request(gatewayApp)
      .post('/transkrip/sinkron')
      .set('Authorization', `Bearer ${mhs1Token}`)
      .set('X-Device-ID', 'DEVICE-MHS-001')
      .send({ grades: [], classId: 1 });

    expect(res.status).toBe(403);
  });

  test('Token admin digunakan untuk sinkronisasi ditolak', async () => {
    const res = await request(gatewayApp)
      .post('/transkrip/sinkron')
      .set('Authorization', `Bearer ${admin1Token}`)
      .set('X-Device-ID', 'DEVICE-ADMIN-001')
      .send({ grades: [], classId: 1 });

    expect(res.status).toBe(403);
  });

  test('Service token valid melalui gateway diterima', async () => {
    // Dapatkan service token
    const authRes = await request(gatewayApp)
      .post('/auth/service')
      .send({
        clientId: process.env.SERVICE_CLIENT_ID,
        clientSecret: process.env.SERVICE_CLIENT_SECRET,
      });

    expect(authRes.status).toBe(200);
    const serviceToken = authRes.body.serviceToken;

    // Sinkronisasi melalui gateway
    const syncRes = await request(gatewayApp)
      .post('/transkrip/sinkron')
      .set('Authorization', `Bearer ${serviceToken}`)
      .send({
        grades: [
          {
            student_id: 4,
            nim: 'MHS001',
            kode_kelas: 'TEST101',
            nama_kelas: 'Test Kelas',
            sks: 3,
            nilai: 85,
            huruf: 'A',
            semester: '2024/2025 Ganjil',
          },
        ],
        classId: 1,
      });

    expect(syncRes.status).toBe(200);
    expect(syncRes.body.synced_count).toBe(1);
  });
});

// =============================================
// TEST SUITE: FINALISASI DAN SINKRONISASI E2E
// =============================================
describe('Finalisasi dan Sinkronisasi End-to-End', () => {
  test('Dosen pengampu berhasil memfinalisasi kelas dan sinkronisasi transkrip', async () => {
    setOverrideHour(10); // Dalam jam akses

    const data = await loginUser('dosen1', 'DEVICE-DSN-101');
    const dosen1Token = data.accessToken;

    const res = await request(gatewayApp)
      .post('/kelas/1/finalisasi')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101');

    expect(res.status).toBe(200);
    expect(res.body.message).toContain('berhasil');
    expect(res.body.sync).toBeDefined();
    expect(res.body.sync.synced_count).toBeGreaterThan(0);

    // Verifikasi transkrip ada
    const mhsData = await loginUser('mhs1', 'DEVICE-MHS-001');
    const transkripRes = await request(gatewayApp)
      .get('/transkrip/MHS001')
      .set('Authorization', `Bearer ${mhsData.accessToken}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(transkripRes.status).toBe(200);
    const cs101 = transkripRes.body.transcripts.find(t => t.kode_kelas === 'CS101');
    expect(cs101).toBeDefined();
  });

  test('Dosen mengubah nilai yang sudah difinalisasi ditolak', async () => {
    const data = await loginUser('dosen1', 'DEVICE-DSN-101');
    const dosen1Token = data.accessToken;

    const res = await request(gatewayApp)
      .put('/nilai/1')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101')
      .send({ nilai: 100, huruf: 'A' });

    expect(res.status).toBe(403);
  });

  test('Finalisasi kelas yang sudah final ditolak', async () => {
    const data = await loginUser('dosen1', 'DEVICE-DSN-101');
    const dosen1Token = data.accessToken;

    const res = await request(gatewayApp)
      .post('/kelas/1/finalisasi')
      .set('Authorization', `Bearer ${dosen1Token}`)
      .set('X-Device-ID', 'DEVICE-DSN-101');

    expect(res.status).toBe(403); // Policy engine denies already finalized
  });
});

// =============================================
// TEST SUITE: SERVICE TOKEN
// =============================================
describe('Service Token', () => {
  test('Service token diterbitkan dengan kredensial valid', async () => {
    const res = await request(gatewayApp)
      .post('/auth/service')
      .send({
        clientId: process.env.SERVICE_CLIENT_ID,
        clientSecret: process.env.SERVICE_CLIENT_SECRET,
      });

    expect(res.status).toBe(200);
    expect(res.body.serviceToken).toBeDefined();
  });

  test('Service token ditolak dengan kredensial tidak valid', async () => {
    const res = await request(gatewayApp)
      .post('/auth/service')
      .send({
        clientId: 'wrong-id',
        clientSecret: 'wrong-secret',
      });

    expect(res.status).toBe(401);
  });

  test('Service token tidak bisa digunakan untuk endpoint user (GET /nilai)', async () => {
    const authRes = await request(gatewayApp)
      .post('/auth/service')
      .send({
        clientId: process.env.SERVICE_CLIENT_ID,
        clientSecret: process.env.SERVICE_CLIENT_SECRET,
      });

    const serviceToken = authRes.body.serviceToken;

    const res = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${serviceToken}`)
      .set('X-Device-ID', 'DEVICE-DSN-101');

    // Service token should fail verifyAccessToken (type mismatch)
    expect(res.status).toBe(401);
  });
});

// =============================================
// TEST SUITE: AUDIT LOG
// =============================================
describe('Audit Log', () => {
  test('Request yang ditolak menghasilkan audit log', async () => {
    // Buat request yang pasti ditolak
    await request(gatewayApp)
      .get('/nilai')
      .set('X-Device-ID', 'DEVICE-MHS-001');
    // Tanpa token -> pasti ditolak

    // Login admin dan lihat audit logs
    const data = await loginUser('admin1', 'DEVICE-ADMIN-001');

    const res = await request(gatewayApp)
      .get('/admin/audit-logs')
      .set('Authorization', `Bearer ${data.accessToken}`)
      .set('X-Device-ID', 'DEVICE-ADMIN-001');

    expect(res.status).toBe(200);
    expect(res.body.logs.length).toBeGreaterThan(0);

    // Harus ada log DENY
    const denyLogs = res.body.logs.filter(l => l.decision === 'DENY');
    expect(denyLogs.length).toBeGreaterThan(0);
  });

  test('Non-admin tidak boleh melihat audit logs', async () => {
    const data = await loginUser('mhs1', 'DEVICE-MHS-001');

    const res = await request(gatewayApp)
      .get('/admin/audit-logs')
      .set('Authorization', `Bearer ${data.accessToken}`)
      .set('X-Device-ID', 'DEVICE-MHS-001');

    expect(res.status).toBe(403);
  });

  test('Audit log tidak menyimpan token atau password', async () => {
    const data = await loginUser('admin1', 'DEVICE-ADMIN-001');

    const res = await request(gatewayApp)
      .get('/admin/audit-logs?limit=50')
      .set('Authorization', `Bearer ${data.accessToken}`)
      .set('X-Device-ID', 'DEVICE-ADMIN-001');

    expect(res.status).toBe(200);

    // Periksa setiap log entry
    for (const log of res.body.logs) {
      const logStr = JSON.stringify(log);
      // Pastikan tidak ada token JWT (memiliki format xxx.xxx.xxx)
      expect(logStr).not.toMatch(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
      // Pastikan tidak ada password plaintext
      expect(logStr).not.toContain('password123');
    }
  });
});
