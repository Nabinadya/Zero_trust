/**
 * shared/database.js
 * Modul database SQLite terpusat.
 * Menggunakan better-sqlite3 dengan WAL mode untuk performa.
 * Semua query menggunakan prepared statements (parameter binding).
 */
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

let dbInstance = null;

/**
 * Mendapatkan instance database singleton.
 * @param {string} [dbPath] - Path ke file database. Default dari config.
 * @returns {import('better-sqlite3').Database}
 */
function getDatabase(dbPath) {
  if (dbInstance) return dbInstance;

  const config = require('./config');
  const resolvedPath = dbPath || path.resolve(__dirname, '..', config.dbPath);

  // Pastikan direktori database ada
  const dir = path.dirname(resolvedPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  dbInstance = new Database(resolvedPath);
  dbInstance.pragma('journal_mode = WAL');
  dbInstance.pragma('foreign_keys = ON');

  return dbInstance;
}

/**
 * Menutup koneksi database.
 */
function closeDatabase() {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}

/**
 * Mendapatkan instance database baru (bukan singleton).
 * Digunakan untuk testing agar setiap test mendapat koneksi terpisah.
 * @param {string} dbPath - Path ke file database.
 * @returns {import('better-sqlite3').Database}
 */
function createDatabase(dbPath) {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

module.exports = { getDatabase, closeDatabase, createDatabase };
