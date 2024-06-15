module.exports = {
  cookieAuthName: process.env.EXPRESS_COOKIE_AUTH_NAME || 'express-auth-session',
  jwtSecret: process.env.EXPRESS_JWT_SECRET || 'donttellanyone',
};
