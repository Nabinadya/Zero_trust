# Zero Trust Grade System

Sistem Nilai Universitas dengan arsitektur **Zero Trust Security**.

## Arsitektur

```
┌─────────────────────────────────────────────────┐
│                   CLIENT                        │
│         (Postman / curl / Frontend)             │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│              API GATEWAY (Port 3000)            │
│  ┌─────────────────────────────────────────┐    │
│  │          POLICY ENGINE (PE/PA)          │    │
│  │  • Token verification                  │    │
│  │  • Role-based access control           │    │
│  │  • Device verification                 │    │
│  │  • Data ownership check                │    │
│  │  • Access hours enforcement            │    │
│  │  • Audit logging                       │    │
│  └─────────────────────────────────────────┘    │
│  ┌──────────┐    ┌──────────────────────┐       │
│  │ Auth     │    │ Proxy + Gateway      │       │
│  │ Module   │    │ Secret Injection     │       │
│  └──────────┘    └──────────────────────┘       │
└────────┬─────────────────────┬──────────────────┘
         │                     │
         ▼                     ▼
┌──────────────────┐  ┌──────────────────────┐
│ GRADE SERVICE    │  │ TRANSCRIPT SERVICE   │
│ (Port 3001)      │  │ (Port 3002)          │
│                  │  │                      │
│ • Verify gateway │  │ • Verify gateway     │
│   secret         │  │   secret             │
│ • Verify token   │  │ • Verify token       │
│ • Defense in     │  │ • Defense in depth   │
│   depth checks   │  │ • Accept only        │
│                  │  │   service token      │
│                  │  │   for sync           │
└────────┬─────────┘  └──────────┬───────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────────────┐
│              SQLite Database (Shared)           │
│  users, devices, classes, grades, transcripts,  │
│  refresh_tokens, service_clients, audit_logs    │
└─────────────────────────────────────────────────┘
```

## Prinsip Zero Trust

1. **Never Trust, Always Verify** — Setiap request diverifikasi oleh Policy Engine di gateway DAN diverifikasi ulang oleh service backend.
2. **Least Privilege** — Setiap role hanya mendapat akses sesuai kebutuhannya.
3. **Assume Breach** — Gateway secret + token verification di setiap layer. Service tidak percaya bahwa gateway sudah memverifikasi.

## Prasyarat

- **Node.js** v18+ (diuji dengan v22)
- **npm** v8+
- OS: Windows / macOS / Linux

## Instalasi

```bash
# Clone/extract proyek
cd "d:\KPT\zero trust"

# Install dependencies
npm install

# Salin dan sesuaikan environment
copy .env.example .env
# (Edit .env jika perlu mengubah secret)

# Buat database dan seed data demo
npm run seed
```

## Menjalankan Aplikasi

### Semua service sekaligus:
```bash
npm run start:all
```

### Atau jalankan terpisah (3 terminal):
```bash
# Terminal 1
node gateway/index.js

# Terminal 2
node grade-service/index.js

# Terminal 3
node transcript-service/index.js
```

## Port Aplikasi

| Service            | Port |
|--------------------|------|
| API Gateway        | 3000 |
| Grade Service      | 3001 |
| Transcript Service | 3002 |

## Environment Variables

| Variable               | Deskripsi                            |
|------------------------|--------------------------------------|
| JWT_SECRET             | Secret untuk access token            |
| JWT_REFRESH_SECRET     | Secret untuk refresh token           |
| JWT_SERVICE_SECRET     | Secret untuk service token           |
| GATEWAY_SECRET         | Secret header X-Gateway-Secret       |
| SERVICE_CLIENT_ID      | Client ID service                    |
| SERVICE_CLIENT_SECRET  | Client secret service                |
| ACCESS_START_HOUR      | Jam mulai akses (default: 7)         |
| ACCESS_END_HOUR        | Jam akhir akses eksklusif (default: 21) |
| APP_TIMEZONE           | Timezone (default: Asia/Jakarta)     |
| DB_PATH                | Path database SQLite                 |

## Akun Demo

Password semua akun: `password123` (disimpan sebagai hash bcrypt)

| Username | Role      | NIM/NIP | Device ID        |
|----------|-----------|---------|------------------|
| admin1   | admin     | NIP001  | DEVICE-ADMIN-001 |
| dosen1   | dosen     | NIP101  | DEVICE-DSN-101   |
| dosen2   | dosen     | NIP102  | DEVICE-DSN-102   |
| mhs1     | mahasiswa | MHS001  | DEVICE-MHS-001   |
| mhs2     | mahasiswa | MHS002  | DEVICE-MHS-002   |
| mhs3     | mahasiswa | MHS003  | DEVICE-MHS-003   |

### Kelas

| Kode  | Nama              | Dosen  | Mahasiswa     |
|-------|-------------------|--------|---------------|
| CS101 | Pemrograman Dasar | dosen1 | mhs1, mhs2    |
| CS202 | Basis Data Lanjut | dosen2 | mhs2, mhs3    |

## Daftar Endpoint

| Method | Endpoint                 | Deskripsi                    | Akses                  |
|--------|--------------------------|------------------------------|------------------------|
| POST   | /auth/login              | Login pengguna               | Semua (+ device check) |
| POST   | /auth/refresh            | Refresh access token         | Valid refresh token    |
| POST   | /auth/logout             | Logout (cabut refresh token) | Valid refresh token    |
| POST   | /auth/service            | Dapatkan service token       | Service credentials    |
| GET    | /nilai                   | Lihat nilai                  | Mahasiswa, Dosen       |
| PUT    | /nilai/:id               | Ubah nilai                   | Dosen pengampu         |
| POST   | /kelas/:id/finalisasi    | Finalisasi kelas             | Dosen pengampu         |
| GET    | /transkrip/:nim          | Lihat transkrip              | Mahasiswa (own), Admin |
| POST   | /transkrip/sinkron       | Sinkronisasi transkrip       | Service token only     |
| GET    | /admin/audit-logs        | Lihat audit log              | Admin only             |

## Contoh Request (curl)

### 1. Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEVICE-MHS-001" \
  -d '{"username":"mhs1","password":"password123"}'
```

### 2. Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

### 3. Logout
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

### 4. Lihat Nilai (Mahasiswa)
```bash
curl http://localhost:3000/nilai \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-MHS-001"
```

### 5. Lihat Nilai (Dosen)
```bash
curl http://localhost:3000/nilai \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-DSN-101"
```

### 6. Ubah Nilai (Dosen)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-DSN-101" \
  -d '{"nilai":90,"huruf":"A"}'
```

### 7. Finalisasi Kelas (Dosen)
```bash
curl -X POST http://localhost:3000/kelas/1/finalisasi \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-DSN-101"
```

### 8. Lihat Transkrip (Mahasiswa)
```bash
curl http://localhost:3000/transkrip/MHS001 \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-MHS-001"
```

### 9. Lihat Transkrip (Admin)
```bash
curl http://localhost:3000/transkrip/MHS001 \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-ADMIN-001"
```

### 10. Dapatkan Service Token
```bash
curl -X POST http://localhost:3000/auth/service \
  -H "Content-Type: application/json" \
  -d '{"clientId":"grade-service","clientSecret":"<SERVICE_CLIENT_SECRET>"}'
```

### 11. Lihat Audit Log (Admin)
```bash
curl http://localhost:3000/admin/audit-logs \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: DEVICE-ADMIN-001"
```

## Skenario Pengujian (Allow & Deny)

### ✅ Skenario Allow

1. Login dengan kredensial benar + device terdaftar
2. Mahasiswa melihat nilai miliknya
3. Dosen melihat nilai kelas yang diampunya
4. Dosen mengubah nilai di kelas sendiri (dalam jam akses)
5. Dosen finalisasi kelas sendiri → auto sinkronisasi transkrip
6. Mahasiswa melihat transkrip NIM sendiri
7. Admin melihat transkrip semua mahasiswa
8. Refresh token yang valid menghasilkan access token baru
9. Service token valid untuk endpoint sinkronisasi

### ❌ Skenario Deny

1. Login dengan password salah → 401
2. Login dengan device tidak terdaftar → 403
3. Request tanpa token → 401
4. JWT kedaluwarsa → 401
5. JWT signature tidak valid → 401
6. Refresh token yang sudah dicabut → 401
7. Mahasiswa mengakses transkrip mahasiswa lain → 403
8. Dosen mengakses kelas bukan miliknya → 403
9. Dosen mengubah nilai yang sudah final → 403
10. Perubahan/finalisasi di luar jam akses → 403
11. Request langsung ke service tanpa gateway secret → 403
12. Gateway secret valid tapi token tidak valid → 401
13. User (termasuk admin) memanggil /transkrip/sinkron → 403
14. Request tanpa X-Device-ID di luar /auth/* → 403

## Menjalankan Pengujian

```bash
npm test
# atau
npm run test:verbose
```

## Memeriksa Audit Log

### Via API (sebagai admin):
```bash
# Login sebagai admin
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEVICE-ADMIN-001" \
  -d '{"username":"admin1","password":"password123"}'

# Lihat audit logs (gunakan token dari hasil login)
curl "http://localhost:3000/admin/audit-logs?limit=20" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "X-Device-ID: DEVICE-ADMIN-001"
```

### Via Database:
```bash
sqlite3 database/zero-trust.db "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20;"
```

## Lokasi Kode Keamanan

| Persyaratan                        | Lokasi File                         |
|------------------------------------|-------------------------------------|
| Policy Engine (PE/PA)              | `gateway/policy-engine.js`          |
| Autentikasi (login, refresh, dll)  | `gateway/auth.js`                   |
| Audit logging                      | `gateway/audit.js`                  |
| JWT token management               | `shared/token.js`                   |
| Gateway secret verification        | `shared/service-auth.js`            |
| Token verification di service      | `shared/service-auth.js`            |
| Device verification                | `gateway/policy-engine.js` (L70-84) |
| Access hours check                 | `shared/clock.js`                   |
| Ownership verification (kelas)     | `gateway/policy-engine.js` (L96-145)|
| Refresh token revocation           | `gateway/auth.js` (logout route)    |
| Service token distinction          | `shared/token.js` + `policy-engine` |
| Database schema                    | `shared/schema.js`                  |
| Seed data                          | `scripts/seed.js`                   |
| Security tests                     | `tests/security.test.js`            |
| Config management                  | `shared/config.js`                  |

## Struktur Proyek

```
zero-trust/
├── gateway/
│   ├── index.js              # API Gateway (port 3000)
│   ├── auth.js               # Route autentikasi
│   ├── policy-engine.js      # Policy Engine / Policy Administrator
│   └── audit.js              # Audit logging module
├── grade-service/
│   └── index.js              # Service Nilai (port 3001)
├── transcript-service/
│   └── index.js              # Service Transkrip (port 3002)
├── shared/
│   ├── config.js             # Konfigurasi terpusat
│   ├── database.js           # Database SQLite module
│   ├── schema.js             # Skema database
│   ├── token.js              # JWT utilities
│   ├── clock.js              # Mockable clock
│   └── service-auth.js       # Middleware auth untuk services
├── database/
│   └── zero-trust.db         # Database SQLite (auto-generated)
├── scripts/
│   ├── seed.js               # Script seed database
│   └── start-all.js          # Script start semua service
├── tests/
│   ├── setup.js              # Test environment setup
│   └── security.test.js      # Security test suite
├── package.json
├── jest.config.js
├── .env                      # Environment variables (jangan commit)
├── .env.example              # Template environment
├── .gitignore
└── README.md
```

## Catatan Teknis

### Jam Akses
- Jam akhir (`ACCESS_END_HOUR`) bersifat **eksklusif**: akses diizinkan pada `[startHour, endHour)`.
- Contoh: `7-21` berarti akses diizinkan dari 07:00 sampai 20:59.
- Untuk testing, gunakan `shared/clock.js` yang mendukung override jam.

### Konsistensi Finalisasi + Sinkronisasi
- Jika sinkronisasi transkrip gagal setelah finalisasi, finalisasi akan di-rollback.
- Kedua operasi tidak sepenuhnya atomik karena melibatkan request HTTP antar-service.
- Strategi: finalisasi dulu → sinkronisasi → rollback jika gagal.

### Token Types
- **Access Token**: JWT dengan `type: 'access'`, berlaku 10 menit, untuk request pengguna.
- **Refresh Token**: JWT dengan `type: 'refresh'`, berlaku 1 hari, hash disimpan di database.
- **Service Token**: JWT dengan `type: 'service'` dan `role: 'service'`, berlaku 5 menit, untuk komunikasi antar-service.

### Alur Finalisasi → Sinkronisasi
1. Dosen kirim `POST /kelas/:id/finalisasi` via gateway.
2. Gateway verifikasi: token, role, device, ownership, jam akses.
3. Grade Service finalisasi kelas + nilai.
4. Grade Service minta service token via `POST /auth/service`.
5. Grade Service kirim `POST /transkrip/sinkron` via gateway (port 3000).
6. Gateway verifikasi service token, forward ke Transcript Service.
7. Transcript Service verifikasi gateway secret + service token, lalu simpan.
8. Jika langkah 5-7 gagal, finalisasi di-rollback.
