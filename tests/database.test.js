/**
 * Unit tests for database.js: table schema, insertKey, getKey, getValidKeys,
 * and SQL injection safety of the parameterized queries.
 *
 * Tests run against an in-memory database (NODE_ENV=test), so the real key file is never touched.
 */

const { initializeDatabase, insertKey, getKey, getValidKeys } = require('../database');

/** @type {import('better-sqlite3').Database} Connection to the current test's fresh database. */
let db;

/** @returns {number} The current Unix timestamp in seconds. */
const now = () => Math.floor(Date.now() / 1000);

beforeAll(() => {
  // Silence the "Database initialized successfully." log from each fresh database
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
  console.log.mockRestore();
});

beforeEach(() => {
  // Each test starts with a fresh, empty in-memory database
  db = initializeDatabase();
});

describe('initializeDatabase()', () => {
  test('should create the keys table with kid, key, and exp columns', () => {
    const columns = db.prepare('PRAGMA table_info(keys)').all().map(col => col.name);
    expect(columns).toEqual(['kid', 'key', 'exp']);
  });

  test('should start with an empty keys table', () => {
    const { count } = db.prepare('SELECT COUNT(*) AS count FROM keys').get();
    expect(count).toBe(0);
  });
});

describe('insertKey()', () => {
  test('should return auto-incrementing kids starting at 1', () => {
    expect(insertKey('pem-1', now() + 3600)).toBe(1);
    expect(insertKey('pem-2', now() + 3600)).toBe(2);
  });

  test('should store the key and exp exactly as given', () => {
    const exp = now() + 3600;
    const kid = insertKey('my-pem-string', exp);

    const row = db.prepare('SELECT kid, key, exp FROM keys WHERE kid = ?').get(kid);
    expect(row).toEqual({ kid, key: 'my-pem-string', exp });
  });

  test('should store SQL injection attempts as plain data', () => {
    // With ? placeholders the driver treats this as a string, not as SQL to execute
    const malicious = "'); DROP TABLE keys; --";
    const kid = insertKey(malicious, now() + 3600);

    const row = db.prepare('SELECT key FROM keys WHERE kid = ?').get(kid);
    expect(row.key).toBe(malicious);

    // The table still exists
    const table = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'keys'").get();
    expect(table).toBeDefined();
  });
});

describe('getKey()', () => {
  test('should return undefined when the table is empty', () => {
    expect(getKey(false)).toBeUndefined();
    expect(getKey(true)).toBeUndefined();
  });

  test('should return a valid key when expired is false', () => {
    insertKey('expired-pem', now() - 3600);
    const validKid = insertKey('valid-pem', now() + 3600);

    const row = getKey(false);
    expect(row.kid).toBe(validKid);
    expect(row.key).toBe('valid-pem');
    expect(row.exp).toBeGreaterThan(now());
  });

  test('should return an expired key when expired is true', () => {
    insertKey('valid-pem', now() + 3600);
    const expiredKid = insertKey('expired-pem', now() - 3600);

    const row = getKey(true);
    expect(row.kid).toBe(expiredKid);
    expect(row.key).toBe('expired-pem');
    expect(row.exp).toBeLessThanOrEqual(now());
  });

  test('should return undefined if only the other kind of key exists', () => {
    insertKey('valid-pem', now() + 3600);
    expect(getKey(true)).toBeUndefined();

    db = initializeDatabase();
    insertKey('expired-pem', now() - 3600);
    expect(getKey(false)).toBeUndefined();
  });
});

describe('getValidKeys()', () => {
  test('should return an empty array when there are no valid keys', () => {
    insertKey('expired-pem', now() - 3600);
    expect(getValidKeys()).toEqual([]);
  });

  test('should return all valid keys and exclude expired ones', () => {
    const valid1 = insertKey('valid-1', now() + 3600);
    insertKey('expired', now() - 3600);
    const valid2 = insertKey('valid-2', now() + 7200);

    const kids = getValidKeys().map(row => row.kid);
    expect(kids).toEqual([valid1, valid2]);
  });

  test('should return rows with kid, key, and exp fields', () => {
    insertKey('valid-pem', now() + 3600);

    const [row] = getValidKeys();
    expect(row).toHaveProperty('kid');
    expect(row).toHaveProperty('key', 'valid-pem');
    expect(row).toHaveProperty('exp');
  });
});
