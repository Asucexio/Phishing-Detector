const crypto = require('crypto');

function hashUrl(url) {
  return crypto.createHash('sha256').update(url).digest('hex');
}

module.exports = { hashUrl };