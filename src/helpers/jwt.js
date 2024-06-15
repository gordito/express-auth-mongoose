const jwt = require('jsonwebtoken');
const config = require('./config');

class JWT {
  constructor() {
  }

  encodeToken(payload) {
    return jwt.sign(payload, config.jwtSecret, { expiresIn: '30d' });
  }

  validateToken(token) {
    try {
      return jwt.verify(token, config.jwtSecret);
    } catch (error) {
      return null;
    }
  }

  decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      return null;
    }
  }
}

module.exports = new JWT();