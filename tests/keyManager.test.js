const { keys, generateKey } = require('../keyManager');

describe('keyManager', () => {
  describe('initial key generation', () => {
    test('should have at least 2 keys on module load', () => {
      expect(keys.length).toBeGreaterThanOrEqual(2);
    });

    test('should have at least one unexpired key', () => {
      const currentTime = Math.floor(Date.now() / 1000);
      const validKeys = keys.filter(key => key.expiry > currentTime);
      expect(validKeys.length).toBeGreaterThanOrEqual(1);
    });

    test('should have at least one expired key', () => {
      const currentTime = Math.floor(Date.now() / 1000);
      const expiredKeys = keys.filter(key => key.expiry <= currentTime);
      expect(expiredKeys.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('generateKey()', () => {
    test('should return a key object with kid, expiry, publicKey, and privateKey', () => {
      const key = generateKey();
      expect(key).toHaveProperty('kid');
      expect(key).toHaveProperty('expiry');
      expect(key).toHaveProperty('publicKey');
      expect(key).toHaveProperty('privateKey');
    });

    test('should generate a unique kid (UUID format)', () => {
      const key1 = generateKey();
      const key2 = generateKey();
      expect(key1.kid).not.toEqual(key2.kid);
      // UUID v4 format check
      expect(key1.kid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    test('should generate a valid (unexpired) key by default', () => {
      const currentTime = Math.floor(Date.now() / 1000);
      const key = generateKey();
      expect(key.expiry).toBeGreaterThan(currentTime);
    });

    test('should generate an expired key when expired=true', () => {
      const currentTime = Math.floor(Date.now() / 1000);
      const key = generateKey(true);
      expect(key.expiry).toBeLessThanOrEqual(currentTime);
    });

    test('should add the generated key to the keys array', () => {
      const lengthBefore = keys.length;
      generateKey();
      expect(keys.length).toBe(lengthBefore + 1);
    });

    test('should include RSA public key fields in JWK format', () => {
      const key = generateKey();
      expect(key.publicKey).toHaveProperty('kty', 'RSA');
      expect(key.publicKey).toHaveProperty('n');  // modulus
      expect(key.publicKey).toHaveProperty('e');  // exponent
    });

    test('should include JWKS metadata on the public key', () => {
      const key = generateKey();
      expect(key.publicKey).toHaveProperty('kid', key.kid);
      expect(key.publicKey).toHaveProperty('alg', 'RS256');
      expect(key.publicKey).toHaveProperty('use', 'sig');
    });

    test('should generate a PEM-formatted private key', () => {
      const key = generateKey();
      expect(key.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
      expect(key.privateKey).toContain('-----END RSA PRIVATE KEY-----');
    });
  });
});
