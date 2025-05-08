const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SECRET_KEY = 'myjwtsecret'; // used for signing the JWT
const ENCRYPTION_KEY = crypto.randomBytes(32); // AES key (256-bit)
const IV = crypto.randomBytes(16); // AES initialization vector

const encrypt = (payload) => {
  // Step 1: Sign the payload to get a JWT
  const token = jwt.sign(payload, SECRET_KEY);

  // Step 2: Encrypt the token using AES
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return IV + encrypted string so IV can be used in decryption
  return IV.toString('hex') + ':' + encrypted;
};

const decrypt = (encryptedToken) => {
  const [ivHex, encrypted] = encryptedToken.split(':');
  const iv = Buffer.from(ivHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // Verify and decode the JWT
  return jwt.verify(decrypted, SECRET_KEY);
};

module.exports = {
  encrypt,
  decrypt
};
