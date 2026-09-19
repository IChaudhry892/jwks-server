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
const { keys } = require('./keyManager');

const app = express();
const PORT = 8080;

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
    const currentTime = Math.floor(Date.now() / 1000);

    // Filter for keys where the expiry is still in the future
    const validKeys = keys
      .filter(key => key.expiry > currentTime)
      .map(key => key.publicKey);

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
    // Check if the "?expired=true" query parameter is present
    const isExpiredRequested = req.query.expired === 'true';
    const currentTime = Math.floor(Date.now() / 1000);

    // Select the appropriate key: expired or unexpired based on query parameter
    let targetKey;
    if (isExpiredRequested) {
      targetKey = keys.find(key => key.expiry <= currentTime);
    } else {
      targetKey = keys.find(key => key.expiry > currentTime);
    }

    // Return 500 if no appropriate key is found in the keys array
    if (!targetKey) {
      return res.status(500).json({ error: "Appropriate key not found." });
    }

    // Create a mock payload (no real user verification for this project)
    const payload = {
      user: 'mock_user'
    };

    // Explicitly set the token's expiration to match the key's status
    if (isExpiredRequested) {
      payload.exp = currentTime - 3600; // Expired 1 hour ago
    } else {
      payload.exp = currentTime + 3600; // Expires in 1 hour
    }

    // Sign the token using the selected private key with RS256 and embed the kid in the header
    const token = jwt.sign(payload, targetKey.privateKey, {
      algorithm: 'RS256',
      keyid: targetKey.kid,
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

// Start the web server — export the app for testing
const server = app.listen(PORT, () => {
  console.log(`JWKS server running on http://localhost:${PORT}`);
});

module.exports = { app, server };