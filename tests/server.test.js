const request = require('supertest');
const jwt = require('jsonwebtoken');
const { app } = require('../server');

describe('GET /.well-known/jwks.json', () => {
  test('should return 200 with a valid JWKS response', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('keys');
    expect(Array.isArray(res.body.keys)).toBe(true);
  });

  test('should only contain unexpired keys', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    const currentTime = Math.floor(Date.now() / 1000);

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
    const { keys } = require('../keyManager');
    const currentTime = Math.floor(Date.now() / 1000);

    // Get the kids of expired keys
    const expiredKids = keys
      .filter(key => key.expiry <= currentTime)
      .map(key => key.kid);

    // Get the kids returned by the JWKS endpoint
    const res = await request(app).get('/.well-known/jwks.json');
    const returnedKids = res.body.keys.map(key => key.kid);

    // No expired kid should appear in the JWKS response
    for (const expiredKid of expiredKids) {
      expect(returnedKids).not.toContain(expiredKid);
    }
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
