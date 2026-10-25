const { rowToJWK } = require('./keyManager');   // loading the module runs ensureKeys()
const { getKey, getValidKeys } = require('./database');

console.log('valid row:', getKey(false));
console.log('expired row:', getKey(true));
console.log('JWKS:', JSON.stringify({ keys: getValidKeys().map(rowToJWK) }, null, 2));