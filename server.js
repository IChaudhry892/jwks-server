const express = require('express');
const jwt = require('jsonwebtoken');
const { keys } = require('./keyManager');

const app = express();
const port = 8080;

// Endpoint 1: Serve unexpired public keys in JWKS format
app.get('/.well-known/jwks.json', (req, res) => {
  try {
    const currentTime = Math.floor(Date.now() / 1000);

    // Filter for keys where the expiry is still in the future
    const validKeys = keys
      .filter(key => key.expiry > currentTime)
      .map(key => key.publicKey);

    // Return all unexpired public keys in JWKS format
    res.status(200).json({ keys: validKeys });
  } catch (error) {
    console.error("JWKS Error: ", error);
    res.status(500).json({ error: "Internal Server Error while fetching JWKS." });
  }
});

// Endpoint 2: Issue an expired or unexpired JWT
app.post('/auth', (req, res) => {
  try {
    // Check if the "?expired=true" query parameter is present
    const isExpiredRequested = req.query.expired === 'true';
    const currentTime = Math.floor(Date.now() / 1000);

    // Select an appropriate (expired or unexpired) key from the keys array based on the query parameter
    let targetKey;
    if (isExpiredRequested) {
      targetKey = keys.find(key => key.expiry <= currentTime);
    } else {
      targetKey = keys.find(key => key.expiry > currentTime);
    }

    // Return 500 if no appropriate key is found in the keys array
    if (!targetKey) {
      return res.status(500).send("Appropriate key not found.");
    }

    // Create a mock payload (no real user verification)
    const payload = {
      user: 'mock_user'
    };

    // Explicitly set the token's expiration to match the requirement
    if (isExpiredRequested) {
      payload.exp = currentTime - 3600; // Expired 1 hour ago
    } else {
      payload.exp = currentTime + 3600; // Expires in 1 hour
    }

    // Sign the token using the selected private key
    const token = jwt.sign(payload, targetKey.privateKey, {
      algorithm: 'RS256',
      keyid: targetKey.kid, // Ensures the 'kid' is inserted into the JWT header
    });

    res.status(200).send(token);
  } catch (error) {
    console.error("Auth Error: ", error);
    res.status(500).send("Internal Server Error while generating JWT.");
  }
});

// Start the web server
app.listen(port, () => {
  console.log(`JWKS server running on http://localhost:${port}`);
});