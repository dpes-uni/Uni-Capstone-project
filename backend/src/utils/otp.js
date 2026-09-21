const crypto = require('crypto');

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
}

function hashOtp(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

module.exports = { generateOtp, hashOtp };
