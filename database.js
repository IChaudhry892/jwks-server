const Database = require('better-sqlite3');
const path = require('path');

let db; // Declare the database variable to be used across functions

function initializeDatabase() {
  const dbPath = path.join(__dirname, 'totally_not_my_privateKeys.db');
  db = new Database(dbPath);

  // Create the keys table if it doesn't exist
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

function insertKey(pem, exp) {
  const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
  const info = stmt.run(pem, exp);

  return info.lastInsertRowid; // Return the ID of the inserted key
}

function getKey(expired) {
  const currentTime = Math.floor(Date.now() / 1000);
  
  const sql = expired
    ? 'SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1'
    : 'SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1';
  return db.prepare(sql).get(currentTime);
}

function getValidKeys() {
  const currentTime = Math.floor(Date.now() / 1000);
  const stmt = db.prepare('SELECT kid, key, exp FROM keys WHERE exp > ?');
  const info = stmt.all(currentTime);

  return info;
}

initializeDatabase(); // Initialize the database when this module is loaded

module.exports = {
  initializeDatabase,
  insertKey,
  getKey,
  getValidKeys
};