const crypto = require("crypto");

/**
 * @module keyManager
 * @description Manages RSA key pair generation, storage, and retrieval for the JWKS server.
 * Each key has an associated Key ID (kid) and expiry timestamp.
 */

/** @type {Array<KeyData>} Array to store all generated key pairs (both valid and expired). */
const keys = [];

/**
 * @typedef {Object} KeyData
 * @property {string} kid - Unique Key ID (UUID v4) for identifying this key pair.
 * @property {number} expiry - Unix timestamp (seconds) indicating when this key expires.
 * @property {Object} publicKey - The public key in JWK format with JWKS metadata fields.
 * @property {string} privateKey - The private key in PEM format (PKCS#1).
 */

/**
 * Generates an RSA key pair and stores it in the keys array.
 *
 * @param {boolean} [expired=false] - If true, the key is created with an expiry in the past (1 hour ago).
 *                                     If false, the key expires 1 hour from now.
 * @returns {KeyData} The generated key data object containing public/private keys, kid, and expiry.
 */
function generateKey(expired = false) {
  // Generate a 2048-bit RSA key pair; public key in JWK format for JWKS, private in PEM for signing
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'jwk',
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    }
  });

  // Create a unique Key ID (kid) using a UUID v4
  const kid = crypto.randomUUID();

  // Set expiry: 1 hour in the past for expired keys, 1 hour in the future for valid keys
  const expiryOffset = expired ? -3600 : 3600;
  const expiry = Math.floor(Date.now() / 1000) + expiryOffset;

  // Build the key data object with JWKS-required metadata on the public key
  const keyData = {
    kid: kid,
    expiry: expiry,
    publicKey: {
      ...publicKey,
      kid: kid,
      alg: 'RS256',
      use: 'sig',
    },
    privateKey: privateKey
  };

  // Store the key in the module-level array
  keys.push(keyData);
  return keyData;
}

// Generate initial keys on module load: one valid and one expired
generateKey();
generateKey(true);

module.exports = {
  keys,
  generateKey,
};