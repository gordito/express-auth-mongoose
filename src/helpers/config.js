module.exports = {
  mongodb: process.env.EXPRESS_AUTH_MONGODB || 'mongodb://127.0.0.1:27017/express-auth',
  cookieAuthName: process.env.EXPRESS_AUTH_COOKIE_NAME || 'express-auth-session',
  jwtSecret: process.env.EXPRESS_AUTH_JWT_SECRET || 'donttellanyone',
  debug: process.env.EXPRESS_AUTH_DEBUG === 'true' || false,
};
