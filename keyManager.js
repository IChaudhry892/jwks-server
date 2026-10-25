const crypto = require("crypto");
const { insertKey, getKey } = require('./database');

/**
 * @module keyManager
 * @description Manages RSA key pair generation, storage, and retrieval for the JWKS server.
 * Each key has an associated Key ID (kid) and expiry timestamp.
 */

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
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    }
  });

  // Set expiry: 1 hour in the past for expired keys, 1 hour in the future for valid keys
  const expiryOffset = expired ? -3600 : 3600;
  const expiry = Math.floor(Date.now() / 1000) + expiryOffset;

  // Store the private key in the database and retrieve its auto-incremented ID as the kid
  const kid = insertKey(privateKey, expiry);

  return { kid, expiry };
}

// makes sure that there is always at least one valid and one expired key in the database
function ensureKeys() {
  if (getKey(false) === undefined) {
    generateKey();
  }
  if (getKey(true) === undefined) {
    generateKey(true);
  }
}

// uses the database row of a private key to create a JWK object for the public key, including the kid and other JWKS metadata
function rowToJWK(row) {
  const publicJWK = crypto.createPublicKey(row.key).export({ format: 'jwk' });
  
  return {
    ...publicJWK,
    kid: String(row.kid),
    alg: 'RS256',
    use: 'sig'
  };
}

ensureKeys(); // Generate initial keys on module load: one valid and one expired

module.exports = {
  ensureKeys,
  generateKey,
  rowToJWK
};