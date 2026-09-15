const crypto = require("crypto");

// Array to store generated keys
const keys = [];

// Function to generate key data
function generateKey(expired = false) {
  // Generate an RSA key pair
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
  })

  // Create a unique Key ID (kid)
  const kid = crypto.randomUUID();

  // Set expiry timestamp (1 hour from now or 1 hour ago if expired)
  const expiryOffset = expired ? -3600 : 3600;
  const expiry = Math.floor(Date.now() / 1000) + expiryOffset;

  // Combine the data into a single object
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

  // Store the key in the array
  keys.push(keyData);
  return keyData;
}

// Generate initial keys, one valid and one expired
generateKey();
generateKey(true);

module.exports = {
  keys,
  generateKey,
};

// FOR TESTING PURPOSES ONLY
console.log(JSON.stringify(keys, null, 2));