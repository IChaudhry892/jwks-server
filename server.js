/**
 * @module server
 * @description RESTful JWKS server that serves public keys in JWKS format
 * and issues signed JWTs for authentication. Implements proper HTTP method
 * enforcement and RESTful status codes.
 *
 * Endpoints:
 *   GET  /.well-known/jwks.json - Serves unexpired public keys in JWKS format
 *   POST /auth                  - Issues a signed JWT (supports ?expired=true query param)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { getKey, getValidKeys } = require('./database');
const { rowToJWK } = require('./keyManager');

const app = express();
const PORT = 8080;

app.use(express.json()); // Middleware to parse JSON request bodies

/**
 * GET /.well-known/jwks.json
 *
 * Returns all unexpired public keys in standard JWKS format.
 * Expired keys are filtered out so verifiers only see currently-valid keys.
 *
 * @returns {Object} 200 - A JWKS object containing an array of unexpired JWK public keys.
 * @returns {Object} 500 - Internal server error if key retrieval fails.
 */
app.get('/.well-known/jwks.json', (req, res) => {
  try {
    // Filter for keys where the expiry is still in the future
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
 * Issues a signed JWT using an RSA key pair. By default, returns a JWT signed
 * with an unexpired key. If the query parameter `expired=true` is present,
 * returns a JWT signed with an expired key pair and an expired expiry claim.
 *
 * No request body is required — this endpoint mocks authentication for
 * educational purposes.
 *
 * @queryParam {string} [expired] - If "true", issue a JWT signed with an expired key.
 * @returns {string} 200 - A signed JWT string.
 * @returns {Object} 500 - Internal server error if no appropriate key is found or signing fails.
 */
app.post('/auth', (req, res) => {
  try {
    // Check if the "expired" query parameter is present (regardless of its value)
    const isExpiredRequested = req.query.expired !== undefined;

    // Select the appropriate key: expired or unexpired based on query parameter
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

    // Sign the token using the selected private key with RS256 and embed the kid in the header
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