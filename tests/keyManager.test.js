/**
 * Unit tests for keyManager.js: generateKey, ensureKeys, and rowToJWK.
 *
 * Tests run against an in-memory database (NODE_ENV=test), so the real key file is never touched.
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { initializeDatabase, getKey, getValidKeys } = require('../database');
const { ensureKeys, generateKey, rowToJWK } = require('../keyManager');

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
  initializeDatabase();
});

describe('generateKey()', () => {
  test('should return the new kid and expiry', () => {
    const key = generateKey();
    expect(key).toEqual({ kid: 1, expiry: expect.any(Number) });
  });

  test('should generate a valid key expiring in about 1 hour by default', () => {
    const before = now();
    const { expiry } = generateKey();
    expect(expiry).toBeGreaterThanOrEqual(before + 3600);
    expect(expiry).toBeLessThanOrEqual(now() + 3600);
  });

  test('should generate a key that expired about 1 hour ago when expired=true', () => {
    const before = now();
    const { expiry } = generateKey(true);
    expect(expiry).toBeGreaterThanOrEqual(before - 3600);
    expect(expiry).toBeLessThanOrEqual(now() - 3600);
  });

  test('should assign a unique, incrementing kid to each key', () => {
    const key1 = generateKey();
    const key2 = generateKey();
    expect(key2.kid).toBe(key1.kid + 1);
  });

  test('should save the private key to the database in PKCS1 PEM format', () => {
    const { kid, expiry } = generateKey();
    const row = getKey(false);

    expect(row.kid).toBe(kid);
    expect(row.exp).toBe(expiry);
    expect(row.key).toMatch(/^-----BEGIN RSA PRIVATE KEY-----/);
    expect(row.key).toContain('-----END RSA PRIVATE KEY-----');
  });
});

describe('ensureKeys()', () => {
  test('should create one valid and one expired key in an empty database', () => {
    ensureKeys();
    expect(getKey(false)).toBeDefined();
    expect(getKey(true)).toBeDefined();
    expect(getValidKeys()).toHaveLength(1);
  });

  test('should not add keys when both a valid and an expired key exist', () => {
    ensureKeys(); // creates kids 1 and 2
    ensureKeys(); // should create nothing

    // The next key gets kid 3, so ensureKeys() didn't insert anything the second time
    expect(generateKey().kid).toBe(3);
  });

  test('should only add the missing expired key', () => {
    generateKey(); // kid 1, valid
    ensureKeys();

    expect(getKey(true).kid).toBe(2);
    expect(getValidKeys()).toHaveLength(1);
  });

  test('should only add the missing valid key', () => {
    generateKey(true); // kid 1, expired
    ensureKeys();

    expect(getKey(false).kid).toBe(2);
    expect(getKey(true).kid).toBe(1);
  });
});

describe('rowToJWK()', () => {
  let row;
  let jwk;

  beforeEach(() => {
    generateKey();
    row = getKey(false);
    jwk = rowToJWK(row);
  });

  test('should include the RSA public key fields', () => {
    expect(jwk).toHaveProperty('kty', 'RSA');
    expect(jwk).toHaveProperty('n');
    expect(jwk).toHaveProperty('e', 'AQAB');
  });

  test('should include JWKS metadata with kid as a string', () => {
    expect(jwk).toHaveProperty('kid', String(row.kid));
    expect(typeof jwk.kid).toBe('string');
    expect(jwk).toHaveProperty('alg', 'RS256');
    expect(jwk).toHaveProperty('use', 'sig');
  });

  test('should not leak any private key fields', () => {
    for (const privateField of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(jwk).not.toHaveProperty(privateField);
    }
  });

  test('should produce a public key that verifies tokens signed with the stored private key', () => {
    const token = jwt.sign({ user: 'test' }, row.key, { algorithm: 'RS256' });
    const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });

    expect(() => jwt.verify(token, publicKey, { algorithms: ['RS256'] })).not.toThrow();
  });
});
