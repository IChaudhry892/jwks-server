/**
 * Endpoint tests for server.js using Supertest: the JWKS endpoint, POST /auth
 * (valid and expired, with JSON and Basic auth credentials), HTTP method
 * enforcement, unknown routes, and 500 error handling.
 *
 * Tests run against an in-memory database (NODE_ENV=test); loading keyManager
 * adds one valid and one expired key.
 */

const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { app } = require('../server');
const { getKey } = require('../database');

/**
 * Verifies a JWT against the JWKS endpoint the same way the gradebot does:
 * find the JWK whose kid matches the token header, then check the signature with it.
 *
 * @param {string} token - The JWT returned by POST /auth.
 * @returns {Promise<Object>} The verified token payload.
 * @throws {Error} If no JWK matches the token's kid, or the signature or expiry check fails.
 */
async function verifyWithJwks(token) {
  const { header } = jwt.decode(token, { complete: true });
  const jwksRes = await request(app).get('/.well-known/jwks.json');
  const jwk = jwksRes.body.keys.find(key => key.kid === header.kid);

  if (!jwk) {
    throw new Error(`No JWK found for kid ${header.kid}`);
  }
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

describe('GET /.well-known/jwks.json', () => {
  test('should return 200 with a valid JWKS response', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('keys');
    expect(Array.isArray(res.body.keys)).toBe(true);
  });

  test('should return only keys with the required JWK fields', async () => {
    const res = await request(app).get('/.well-known/jwks.json');

    // Every key returned should have required JWK fields
    for (const key of res.body.keys) {
      expect(key).toHaveProperty('kid');
      expect(key).toHaveProperty('kty', 'RSA');
      expect(key).toHaveProperty('alg', 'RS256');
      expect(key).toHaveProperty('use', 'sig');
      expect(key).toHaveProperty('n');
      expect(key).toHaveProperty('e');
    }
  });

  test('should return keys with kid, alg, use, kty, n, and e fields', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.body.keys.length).toBeGreaterThanOrEqual(1);

    const key = res.body.keys[0];
    expect(key).toHaveProperty('kid');
    expect(key).toHaveProperty('kty', 'RSA');
    expect(key).toHaveProperty('alg', 'RS256');
    expect(key).toHaveProperty('use', 'sig');
    expect(key).toHaveProperty('n');
    expect(key).toHaveProperty('e');
  });

  test('should not include expired keys in JWKS', async () => {
    // Read an expired key straight from the database
    const expiredRow = getKey(true);
    expect(expiredRow).toBeDefined();

    const res = await request(app).get('/.well-known/jwks.json');
    const returnedKids = res.body.keys.map(key => key.kid);

    expect(returnedKids).not.toContain(String(expiredRow.kid));
  });

  test('should include the valid key from the database with kid as a string', async () => {
    const validRow = getKey(false);

    const res = await request(app).get('/.well-known/jwks.json');
    const returnedKids = res.body.keys.map(key => key.kid);

    expect(returnedKids).toContain(String(validRow.kid));
  });
});

describe('POST /auth', () => {
  test('should return 200 with a valid JWT', async () => {
    const res = await request(app).post('/auth');
    expect(res.status).toBe(200);
    expect(res.text).toBeTruthy();

    // JWT should have 3 dot-separated parts
    const parts = res.text.split('.');
    expect(parts.length).toBe(3);
  });

  test('should return a JWT with a kid in the header', async () => {
    const res = await request(app).post('/auth');
    const decoded = jwt.decode(res.text, { complete: true });

    expect(decoded).not.toBeNull();
    expect(decoded.header).toHaveProperty('kid');
    expect(decoded.header).toHaveProperty('alg', 'RS256');
  });

  test('should return a JWT with an unexpired exp claim', async () => {
    const res = await request(app).post('/auth');
    const decoded = jwt.decode(res.text, { complete: true });
    const currentTime = Math.floor(Date.now() / 1000);

    expect(decoded.payload.exp).toBeGreaterThan(currentTime);
  });

  test('should return a JWT whose kid exists in JWKS', async () => {
    const authRes = await request(app).post('/auth');
    const decoded = jwt.decode(authRes.text, { complete: true });
    const tokenKid = decoded.header.kid;

    const jwksRes = await request(app).get('/.well-known/jwks.json');
    const jwksKids = jwksRes.body.keys.map(key => key.kid);

    expect(jwksKids).toContain(tokenKid);
  });

  test('should return a JWT whose signature verifies against the JWKS', async () => {
    const res = await request(app).post('/auth');
    const payload = await verifyWithJwks(res.text);
    expect(payload).toHaveProperty('user', 'mock_user');
  });

  test('should sign with the valid key from the database and match its exp', async () => {
    const validRow = getKey(false);

    const res = await request(app).post('/auth');
    const decoded = jwt.decode(res.text, { complete: true });

    expect(decoded.header.kid).toBe(String(validRow.kid));
    expect(decoded.payload.exp).toBe(validRow.exp);
  });

  test('should accept a JSON body (as sent by the gradebot)', async () => {
    const res = await request(app)
      .post('/auth')
      .send({ username: 'userABC', password: 'password123' });

    expect(res.status).toBe(200);
    await expect(verifyWithJwks(res.text)).resolves.toBeDefined();
  });

  test('should accept HTTP Basic auth (as sent by the gradebot)', async () => {
    const res = await request(app)
      .post('/auth')
      .auth('userABC', 'password123');

    expect(res.status).toBe(200);
    await expect(verifyWithJwks(res.text)).resolves.toBeDefined();
  });
});

describe('POST /auth?expired=true', () => {
  test('should return 200 with a JWT signed by an expired key', async () => {
    const res = await request(app).post('/auth').query({ expired: 'true' });
    expect(res.status).toBe(200);
    expect(res.text).toBeTruthy();
  });

  test('should return a JWT with an expired exp claim', async () => {
    const res = await request(app).post('/auth').query({ expired: 'true' });
    const decoded = jwt.decode(res.text, { complete: true });
    const currentTime = Math.floor(Date.now() / 1000);

    expect(decoded.payload.exp).toBeLessThan(currentTime);
  });

  test('should return a JWT whose kid is NOT in JWKS', async () => {
    const authRes = await request(app).post('/auth').query({ expired: 'true' });
    const decoded = jwt.decode(authRes.text, { complete: true });
    const tokenKid = decoded.header.kid;

    const jwksRes = await request(app).get('/.well-known/jwks.json');
    const jwksKids = jwksRes.body.keys.map(key => key.kid);

    // Expired key's kid should not be in the JWKS response
    expect(jwksKids).not.toContain(tokenKid);
  });

  test('should sign with the expired key from the database and match its exp', async () => {
    const expiredRow = getKey(true);

    const res = await request(app).post('/auth').query({ expired: 'true' });
    const decoded = jwt.decode(res.text, { complete: true });

    expect(decoded.header.kid).toBe(String(expiredRow.kid));
    expect(decoded.payload.exp).toBe(expiredRow.exp);
  });

  test('should treat the expired parameter as present even without a value', async () => {
    const res = await request(app).post('/auth?expired');
    const decoded = jwt.decode(res.text, { complete: true });

    expect(decoded.header.kid).toBe(String(getKey(true).kid));
  });

  test('should fail verification against the JWKS', async () => {
    const res = await request(app).post('/auth').query({ expired: 'true' });
    await expect(verifyWithJwks(res.text)).rejects.toThrow();
  });
});

describe('HTTP method enforcement', () => {
  test('POST to /.well-known/jwks.json should return 405', async () => {
    const res = await request(app).post('/.well-known/jwks.json');
    expect(res.status).toBe(405);
  });

  test('PUT to /.well-known/jwks.json should return 405', async () => {
    const res = await request(app).put('/.well-known/jwks.json');
    expect(res.status).toBe(405);
  });

  test('DELETE to /.well-known/jwks.json should return 405', async () => {
    const res = await request(app).delete('/.well-known/jwks.json');
    expect(res.status).toBe(405);
  });

  test('PATCH to /.well-known/jwks.json should return 405', async () => {
    const res = await request(app).patch('/.well-known/jwks.json');
    expect(res.status).toBe(405);
  });

  test('GET to /auth should return 405', async () => {
    const res = await request(app).get('/auth');
    expect(res.status).toBe(405);
  });

  test('PUT to /auth should return 405', async () => {
    const res = await request(app).put('/auth');
    expect(res.status).toBe(405);
  });

  test('DELETE to /auth should return 405', async () => {
    const res = await request(app).delete('/auth');
    expect(res.status).toBe(405);
  });

  test('PATCH to /auth should return 405', async () => {
    const res = await request(app).patch('/auth');
    expect(res.status).toBe(405);
  });
});

describe('Unknown routes', () => {
  test('GET to unknown path should return 404', async () => {
    const res = await request(app).get('/nonexistent');
    expect(res.status).toBe(404);
  });

  test('POST to unknown path should return 404', async () => {
    const res = await request(app).post('/unknown');
    expect(res.status).toBe(404);
  });
});

describe('Error handling', () => {
  /**
   * Loads a separate copy of the server whose database module is replaced
   * with the given fake, so database failures can be simulated.
   *
   * @param {Object} fakeDatabase - Stand-in for database.js with getKey and getValidKeys.
   * @returns {import('express').Express} The isolated Express app.
   */
  function loadAppWithDatabase(fakeDatabase) {
    let isolatedApp;
    jest.isolateModules(() => {
      jest.doMock('../database', () => fakeDatabase);
      jest.doMock('../keyManager', () => ({ rowToJWK: jest.fn() }));
      isolatedApp = require('../server').app;
    });
    return isolatedApp;
  }

  beforeAll(() => {
    // Silence the expected error logs from the catch blocks
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterAll(() => {
    console.error.mockRestore();
    jest.dontMock('../database');
    jest.dontMock('../keyManager');
  });

  test('POST /auth should return 500 when no matching key exists', async () => {
    const brokenApp = loadAppWithDatabase({ getKey: () => undefined, getValidKeys: () => [] });

    const res = await request(brokenApp).post('/auth');
    expect(res.status).toBe(500);
    expect(res.body).toHaveProperty('error', 'Appropriate key not found.');
  });

  test('POST /auth should return 500 when signing fails', async () => {
    const now = Math.floor(Date.now() / 1000);
    const brokenApp = loadAppWithDatabase({
      getKey: () => ({ kid: 1, key: 'not-a-real-pem', exp: now + 3600 }),
      getValidKeys: () => [],
    });

    const res = await request(brokenApp).post('/auth');
    expect(res.status).toBe(500);
  });

  test('GET /.well-known/jwks.json should return 500 when the database query fails', async () => {
    const brokenApp = loadAppWithDatabase({
      getKey: () => undefined,
      getValidKeys: () => { throw new Error('database unavailable'); },
    });

    const res = await request(brokenApp).get('/.well-known/jwks.json');
    expect(res.status).toBe(500);
  });
});
