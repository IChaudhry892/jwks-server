/**
 * @module server
 * @description RESTful JWKS server that serves public keys in JWKS format
 * and issues signed JWTs for authentication. Keys are read from the SQLite
 * database (see database.js). Implements proper HTTP method enforcement and
 * RESTful status codes.
 *
 * Endpoints:
 *   GET  /.well-known/jwks.json - Serves unexpired public keys in JWKS format
 *   POST /auth                  - Issues a signed JWT (supports the ?expired query param)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { getKey, getValidKeys } = require('./database');
const { rowToJWK } = require('./keyManager');

const app = express();
const PORT = 8080;

// Parse JSON request bodies, e.g. {"username": "userABC", "password": "password123"} from the test client
app.use(express.json());

/**
 * GET /.well-known/jwks.json
 *
 * Reads all unexpired keys from the database and returns their public keys
 * in standard JWKS format. Expired keys are excluded so verifiers only see
 * currently-valid keys.
 *
 * @returns {Object} 200 - A JWKS object containing an array of unexpired JWK public keys.
 * @returns {Object} 500 - Internal server error if key retrieval fails.
 */
app.get('/.well-known/jwks.json', (req, res) => {
  try {
    // Read valid keys from the database and derive a public JWK from each private key
    const validKeys = getValidKeys().map(rowToJWK);

    // Return all unexpired public keys in JWKS format
    return res.status(200).json({ keys: validKeys });
  } catch (error) {
    console.error("JWKS Error: ", error);
    return res.status(500).json({ error: "Internal Server Error while fetching JWKS." });
  }
});

/**
 * POST /auth
 *
 * Issues a JWT signed with a private key read from the database. By default,
 * the JWT is signed with an unexpired key. If the `expired` query parameter is
 * present (with any value), the JWT is signed with an expired key instead.
 * The token's exp claim always matches the signing key's expiry.
 *
 * Authentication is mocked for educational purposes: credentials sent as HTTP
 * Basic auth or a JSON body are accepted but not checked, and no body is required.
 *
 * @queryParam {string} [expired] - If present, issue a JWT signed with an expired key.
 * @returns {string} 200 - A signed JWT string.
 * @returns {Object} 500 - Internal server error if no appropriate key is found or signing fails.
 */
app.post('/auth', (req, res) => {
  try {
    // Check if the "expired" query parameter is present (regardless of its value)
    const isExpiredRequested = req.query.expired !== undefined;

    // Read an expired or unexpired key from the database based on the query parameter
    const targetKeyRow = getKey(isExpiredRequested);

    // Return 500 if no appropriate key is found in the database
    if (!targetKeyRow) {
      return res.status(500).json({ error: "Appropriate key not found." });
    }

    // Create a mock payload (no real user verification for this project)
    const payload = {
      user: 'mock_user',
      exp: targetKeyRow.exp // Set the token's expiration to match the key's expiry
    };

    // Sign with the stored PEM private key using RS256, and put the kid (as a string) in the header
    const token = jwt.sign(payload, targetKeyRow.key, {
      algorithm: 'RS256',
      keyid: String(targetKeyRow.kid),
    });

    return res.status(200).send(token);
  } catch (error) {
    console.error("Auth Error: ", error);
    return res.status(500).json({ error: "Internal Server Error while generating JWT." });
  }
});

/**
 * Method Not Allowed handlers.
 *
 * RESTful APIs must return 405 Method Not Allowed (not 404) when a valid
 * resource is accessed with an unsupported HTTP method. These app.all()
 * handlers catch any method not already handled by the specific route above.
 */
app.all('/.well-known/jwks.json', (req, res) => {
  res.set('Allow', 'GET');
  return res.status(405).json({ error: "Method Not Allowed." });
});

app.all('/auth', (req, res) => {
  res.set('Allow', 'POST');
  return res.status(405).json({ error: "Method Not Allowed." });
});

/**
 * Catch-all handler for undefined routes.
 * Returns 404 Not Found for any request that doesn't match a defined endpoint.
 */
app.all('*', (req, res) => {
  return res.status(404).json({ error: "Not Found." });
});

// Start the web server only when run directly (not when imported for testing)
let server;
if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`JWKS server running on http://localhost:${PORT}`);
  });
}

module.exports = { app, server };