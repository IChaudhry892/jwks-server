/**
 * @module server
 * @description RESTful JWKS server that serves public keys in JWKS format
 * and issues signed JWTs for authentication. Implements proper HTTP method
 * enforcement and RESTful status codes.
 *
 * Built on Node.js's native http module for full control over HTTP method
 * handling and status code responses.
 *
 * Endpoints:
 *   GET  /.well-known/jwks.json - Serves unexpired public keys in JWKS format
 *   POST /auth                  - Issues a signed JWT (supports ?expired=true query param)
 */

const http = require('http');

const jwt = require('jsonwebtoken');
const { keys } = require('./keyManager');

const PORT = 8080;

/**
 * Sends a JSON response with the given status code and body.
 *
 * @param {http.ServerResponse} res - The HTTP response object.
 * @param {number} statusCode - The HTTP status code to send.
 * @param {Object|string} body - The response body (object will be JSON-serialized).
 * @param {Object} [extraHeaders={}] - Additional headers to include in the response.
 */
function sendJson(res, statusCode, body, extraHeaders = {}) {
  const jsonBody = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(jsonBody),
    ...extraHeaders,
  });
  res.end(jsonBody);
}

/**
 * Sends a plain text response with the given status code.
 *
 * @param {http.ServerResponse} res - The HTTP response object.
 * @param {number} statusCode - The HTTP status code to send.
 * @param {string} text - The plain text response body.
 */
function sendText(res, statusCode, text) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain',
    'Content-Length': Buffer.byteLength(text),
  });
  res.end(text);
}

/**
 * Handles GET requests to /.well-known/jwks.json
 *
 * Returns all unexpired public keys in standard JWKS format.
 * Expired keys are filtered out so verifiers only see currently-valid keys.
 *
 * @param {http.IncomingMessage} req - The HTTP request object.
 * @param {http.ServerResponse} res - The HTTP response object.
 */
function handleJWKS(req, res) {
  try {
    const currentTime = Math.floor(Date.now() / 1000);

    // Filter for keys where the expiry is still in the future
    const validKeys = keys
      .filter(key => key.expiry > currentTime)
      .map(key => key.publicKey);

    // Return all unexpired public keys in JWKS format
    sendJson(res, 200, { keys: validKeys });
  } catch (error) {
    console.error("JWKS Error: ", error);
    sendJson(res, 500, { error: "Internal Server Error while fetching JWKS." });
  }
}

/**
 * Handles POST requests to /auth
 *
 * Issues a signed JWT using an RSA key pair. By default, returns a JWT signed
 * with an unexpired key. If the query parameter `expired=true` is present,
 * returns a JWT signed with an expired key pair and an expired expiry claim.
 *
 * No request body is required — this endpoint mocks authentication for
 * educational purposes.
 *
 * @param {http.IncomingMessage} req - The HTTP request object.
 * @param {http.ServerResponse} res - The HTTP response object.
 * @param {Object} queryParams - Parsed query parameters from the request URL.
 */
function handleAuth(req, res, searchParams) {
  try {
    // Check if the "?expired=true" query parameter is present
    const isExpiredRequested = searchParams.get('expired') === 'true';
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
      return sendJson(res, 500, { error: "Appropriate key not found." });
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

    sendText(res, 200, token);
  } catch (error) {
    console.error("Auth Error: ", error);
    sendJson(res, 500, { error: "Internal Server Error while generating JWT." });
  }
}

/**
 * Main request router.
 *
 * Routes incoming HTTP requests to the appropriate handler based on the
 * request path and method. Enforces proper RESTful HTTP method/status code
 * semantics:
 *   - 200 for successful requests
 *   - 405 Method Not Allowed for valid paths with wrong HTTP methods
 *   - 404 Not Found for undefined paths
 *
 * @param {http.IncomingMessage} req - The HTTP request object.
 * @param {http.ServerResponse} res - The HTTP response object.
 */
function requestHandler(req, res) {
  // Parse the URL to extract the pathname and query parameters
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Route: /.well-known/jwks.json
  if (pathname === '/.well-known/jwks.json') {
    if (method === 'GET' || method === 'HEAD') {
      return handleJWKS(req, res);
    }
    // Any other method on this endpoint is not allowed
    return sendJson(res, 405, { error: "Method Not Allowed" }, { 'Allow': 'GET' });
  }

  // Route: /auth
  if (pathname === '/auth') {
    if (method === 'POST') {
      return handleAuth(req, res, parsedUrl.searchParams);
    }
    // Any other method on this endpoint is not allowed
    return sendJson(res, 405, { error: "Method Not Allowed" }, { 'Allow': 'POST' });
  }

  // No matching route — return 404 Not Found
  sendJson(res, 404, { error: "Not Found." });
}

// Create and start the HTTP server
const server = http.createServer(requestHandler);

server.listen(PORT, () => {
  console.log(`JWKS server running on http://localhost:${PORT}`);
});

module.exports = { server, requestHandler };