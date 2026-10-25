const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

function initializeDatabase() {
  const dbPath = path.join(__dirname, 'totally_not_my_privateKeys.db');
  const db = new Database(dbPath);

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