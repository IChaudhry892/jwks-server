/**
 * @module keyManager
 * @description Generates RSA key pairs, saves their private keys to the SQLite database,
 * and converts stored keys into public JWKs for the JWKS endpoint.
 * On load, ensures the database holds at least one valid and one expired key.
 */

const crypto = require("crypto");
const { insertKey, getKey } = require('./database');

/**
 * @typedef {Object} GeneratedKey
 * @property {number} kid - Key ID assigned by the database.
 * @property {number} expiry - Unix timestamp (seconds) when the key expires.
 */

/**
 * @typedef {Object} PublicJWK
 * @property {string} kty - Key type, always "RSA".
 * @property {string} n - RSA modulus (Base64URL).
 * @property {string} e - RSA public exponent (Base64URL).
 * @property {string} kid - Key ID as a string, matching the kid in JWT headers.
 * @property {string} alg - Signing algorithm, always "RS256".
 * @property {string} use - Key usage, always "sig" (signature).
 */

/**
 * Generates a 2048-bit RSA key pair and saves the private key to the database.
 * The public key isn't stored, since rowToJWK() derives it from the private key when needed.
 *
 * @param {boolean} [expired=false] - If true, the key is created with an expiry in the past (1 hour ago).
 *                                     If false, the key expires 1 hour from now.
 * @returns {GeneratedKey} The new key's kid and expiry.
 */
function generateKey(expired = false) {
  // Serialize the private key as a PKCS#1 PEM string, since SQLite can't store key objects
  const { privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    }
  });

  // Set expiry: 1 hour in the past for expired keys, 1 hour in the future for valid keys
  const expiryOffset = expired ? -3600 : 3600;
  const expiry = Math.floor(Date.now() / 1000) + expiryOffset;

  // Store the private key in the database; its auto-incremented row ID becomes the kid
  const kid = insertKey(privateKey, expiry);

  return { kid, expiry };
}

/**
 * Makes sure the database contains at least one valid and one expired key,
 * generating only the ones that are missing. This keeps POST /auth and
 * POST /auth?expired working without adding new rows on every restart.
 *
 * @returns {void}
 */
function ensureKeys() {
  if (getKey(false) === undefined) {
    generateKey();
  }
  if (getKey(true) === undefined) {
    generateKey(true);
  }
}

/**
 * Converts a database row into a public JWK for the JWKS endpoint.
 * The public key (n and e) is derived from the stored private key, so the
 * private key itself is never exposed.
 *
 * @param {import('./database').KeyRow} row - A row from the keys table.
 * @returns {PublicJWK} The public key in JWK format with JWKS metadata.
 */
function rowToJWK(row) {
  const publicJWK = crypto.createPublicKey(row.key).export({ format: 'jwk' });

  return {
    ...publicJWK,
    kid: String(row.kid), // JWT headers and JWKs use string kids
    alg: 'RS256',
    use: 'sig'
  };
}

// Ensure one valid and one expired key exist as soon as this module is loaded
ensureKeys();

module.exports = {
  ensureKeys,
  generateKey,
  rowToJWK
};
