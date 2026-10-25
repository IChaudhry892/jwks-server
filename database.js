/**
 * @module database
 * @description SQLite storage for the JWKS server's RSA private keys.
 * Keys are persisted to totally_not_my_privateKeys.db so they survive server restarts.
 * Every query uses ? placeholders so values are always bound as data, never
 * concatenated into SQL, which prevents SQL injection.
 */

const Database = require('better-sqlite3');
const path = require('path');

/**
 * @typedef {Object} KeyRow
 * @property {number} kid - Key ID, auto-assigned by SQLite (1, 2, 3, ...).
 * @property {string} key - The RSA private key serialized as a PKCS#1 PEM string.
 * @property {number} exp - Unix timestamp (seconds) when this key expires.
 */

/** @type {import('better-sqlite3').Database} Shared database connection, set by initializeDatabase(). */
let db;

/**
 * Opens (or creates) the database file and creates the keys table if it doesn't exist.
 * Called automatically when this module is loaded.
 *
 * When NODE_ENV is 'test' (Jest sets this automatically), a throwaway in-memory
 * database is used instead, so tests never modify the real key file. Calling this
 * again in tests replaces the connection with a fresh, empty database.
 *
 * @returns {import('better-sqlite3').Database} The open database connection.
 */
function initializeDatabase() {
  const dbPath = process.env.NODE_ENV === 'test'
    ? ':memory:'
    : path.join(__dirname, 'totally_not_my_privateKeys.db');
  db = new Database(dbPath);

  // Schema required by the assignment
  db.exec(`
      CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    `);

  console.log('Database initialized successfully.');

  return db;
}

/**
 * Saves a private key and its expiry to the database.
 *
 * @param {string} pem - The RSA private key as a PKCS#1 PEM string.
 * @param {number} exp - Unix timestamp (seconds) when the key expires.
 * @returns {number} The kid SQLite assigned to the new row.
 */
function insertKey(pem, exp) {
  const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
  const info = stmt.run(pem, exp);

  return info.lastInsertRowid;
}

/**
 * Reads a single key from the database, either a valid (unexpired) one or an expired one.
 *
 * @param {boolean} expired - If true, return a key whose exp is now or in the past;
 *                            if false, return a key whose exp is in the future.
 * @returns {KeyRow|undefined} The matching row, or undefined if no such key exists.
 */
function getKey(expired) {
  const currentTime = Math.floor(Date.now() / 1000);

  const sql = expired
    ? 'SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1'
    : 'SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1';
  return db.prepare(sql).get(currentTime);
}

/**
 * Reads all valid (unexpired) keys from the database, used to build the JWKS response.
 *
 * @returns {KeyRow[]} All rows whose exp is in the future (empty if there are none).
 */
function getValidKeys() {
  const currentTime = Math.floor(Date.now() / 1000);
  const stmt = db.prepare('SELECT kid, key, exp FROM keys WHERE exp > ?');

  return stmt.all(currentTime);
}

// Open the database as soon as this module is required, so keyManager and server share one connection
initializeDatabase();

module.exports = {
  initializeDatabase,
  insertKey,
  getKey,
  getValidKeys
};
