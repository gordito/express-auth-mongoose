require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const { createHash, randomBytes } = require('crypto');
const {
  celebrate, Joi, errors,
} = require('celebrate');

const config = require('./helpers/config');
const JWT = require('./helpers/jwt');
const validateCookie = require('./middleware/validate.cookie');
const { HttpError } = require('./middleware/custom.error');

// Mongoose Models
const User = require('./model/user');;
const UserSession = require('./model/usersession');

// Postroutes
let PostLogin = null;
let PostLogout = null;
let PostCreateUser = null;
let PostUserStatus = null;
let PostForgotPassword = null;
let PostRestorePassword = null;
let PostError = null;

const onLogin = (fn) => {
  if (fn && typeof fn === 'function')  PostLogin = fn;
};
const onLogout = (fn) => {
  if (fn && typeof fn === 'function')  PostLogout = fn;
};
const onCreateUser = (fn) => {
  if (fn && typeof fn === 'function')  PostCreateUser = fn;
};
const onUserStatus = (fn) => {
  if (fn && typeof fn === 'function')  PostUserStatus = fn;
};
const onForgotPassword = (fn) => {
  if (fn && typeof fn === 'function')  PostForgotPassword = fn;
};
const onRestorePassword = (fn) => {
  if (fn && typeof fn === 'function')  PostRestorePassword = fn;
};
const onError = (fn) => {
  if (fn && typeof fn === 'function')  PostError = fn;
};

const Connect = async () => {
  try {
    await mongoose.connect(config.mongodb);
    if (config.debug) console.log('Express Auth - MongoDB Connected');
  } catch (e) {
    if (config.debug) console.log('Express Auth - MongoDB Connection Error', e);
    throw new Error('Express Auth - MongoDB Connection Error');
  }
};
Connect();

const router = express.Router({ mergeParams: true });

if (config.debug) console.log('Express Auth - Debug Mode');

router.post(
  '/login',
  express.json(),
  celebrate({
    query: {
      jwtonly: Joi.boolean().default(false),
    },
    body: {
      username: Joi.string().required(),
      password: Joi.string().required(),
    },
  }),
  async (req, res, next) => {
    try {
      if (mongoose.connection.readyState === 0) throw new HttpError(500, 'Express Auth - MongoDB Connection Not Ready');
      const authCookie = req.cookies[config.cookieAuthName];
      if (authCookie) throw new HttpError(500, 'Already logged in');

      const { username, password } = req.body;
      const { jwtonly } = req.query;
      const u = await User.findOne({ username });
      if (!u) throw new HttpError(401, 'Username or password not correct');
      const hashedPassword = createHash('sha512').update(`${u._id.toString()}${u.salt}${password}`).digest('hex');
      if (u.password !== hashedPassword) throw new HttpError(401, 'Username or password not correct');
      if (u.deleted) throw new HttpError(401, 'User not found');

      const userObj = u.toObject();
      delete userObj.password;
      delete userObj.salt;
      delete userObj.__v;

      const session = await new UserSession({
        userid: u._id,
      }).save();
      const jwt = JWT.encodeToken({
        ...userObj,
        session: session._id.toString(),
      });
      session.jwt = jwt;
      session.save();

      userObj.jwt = jwt;

      const cookieOptions = {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      };
      if (process.env.COOKIE_SECURE !== 'false') {
        cookieOptions.secure = true
      }
      if (process.env.COOKIE_SAMESITE === 'None') {
        cookieOptions.sameSite = 'None';
      }
      if (process.env.COOKIE_SAMESITE === 'Lax') {
        cookieOptions.sameSite = 'Lax';
      }
      if (process.env.COOKIE_SAMESITE === 'Strict') {
        cookieOptions.sameSite = 'Strict';
      }
      res.cookie(config.cookieAuthName, jwt, cookieOptions);

      if (jwtonly) {
        res.status(200).send(jwt);
      } else {
        res.status(200).json(userObj);
      }
      if (PostLogin && typeof PostLogin === 'function') PostLogin(req, userObj);
    } catch (e) {
      if (config.debug) console.log('Express Auth /login Exception', e);
      if (PostError && typeof PostError === 'function') PostError(req, e);
      next(e);
    }
  },
);

router.post(
  '/create-user',
  express.json(),
  celebrate({
    body: {
      username: Joi.string().required(),
      password: Joi.string().min(8).required(),
      usertype: Joi.string().default('email'),
    },
  }),
  async (req, res, next) => {
    try {
      if (mongoose.connection.readyState === 0) throw new HttpError(500, 'Express Auth - MongoDB Connection Not Ready');
      const {
        username,
        password,
        usertype,
      } = req.body;
      const user = await User.findOne({ username, usertype });
      if (user) throw new HttpError(409, 'User already exists');
      const newUser = await new User({
        username,
        usertype,
      }).save();
      if (!newUser) throw new HttpError(503, 'Could not create user');
      newUser.salt = randomBytes(128).toString('hex');
      newUser.password = createHash('sha512').update(`${newUser._id.toString()}${newUser.salt}${password}`).digest('hex');
      newUser.save();

      const userObj = newUser.toObject();
      delete userObj.password;
      delete userObj.salt;
      delete userObj.__v;

      res.status(200).json(userObj);
      if (PostCreateUser && typeof PostCreateUser === 'function') PostCreateUser(req, userObj);
    } catch (e) {
      if (config.debug) console.log('Express Auth /create-user Exception', e);
      if (PostError && typeof PostError === 'function') PostError(req, e);
      next(e);
    }
  },
);

router.get(
  '/status',
  express.json(),
  validateCookie,
  async (req, res, next) => {
    try {
      if (!req.auth) throw new HttpError(401, 'No user found');
      res.status(200).json(req.auth);
      if (PostUserStatus && typeof PostUserStatus === 'function') PostUserStatus(req, req.auth);
    } catch (e) {
      if (config.debug) console.log('Express Auth /status Exception', e);
      if (PostError && typeof PostError === 'function') PostError(req, e);
      next(e);
    }
  },
);

router.get(
  '/logout',
  express.json(),
  cookieParser(),
  validateCookie,
  celebrate({
    query: {
      sessionId: Joi.string(),
      all: Joi.boolean(),
    },
  }),
  async (req, res, next) => {
    try {
      if (mongoose.connection.readyState === 0) throw new HttpError(500, 'Express Auth - MongoDB Connection Not Ready');
      if (!req.auth) throw new HttpError(401, 'No user found');
      const { sessionId, all } = req.query;

      if (all) {
        const sessions = await UserSession.find({ userid: new mongoose.Types.ObjectId(req.auth._id), deleted: null });
        for (const s of sessions) {
          s.deleted = Date.now();
          s.save();
        }
      }

      if (sessionId) {
        const session = await UserSession.findOne({ _id: new mongoose.Types.ObjectId(sessionId), userid: new mongoose.Types.ObjectId(req.auth._id), deleted: null });
        if (!session) throw new HttpError(404, 'Provided sessionId Not Found');
        // await session.deleteOne();
        session.deleted = Date.now();
        session.save();
      } else {
        const session = await UserSession.findOne({ _id: new mongoose.Types.ObjectId(req.auth.session), deleted: null });
        if (!session) throw new HttpError(401, 'No User Session Found');
        // await session.deleteOne();
        session.deleted = Date.now();
        session.save();
      }

      res.clearCookie(config.cookieAuthName);

      res.status(200).json({});
      if (PostLogout && typeof PostLogout === 'function') PostLogout(req, req.auth);
    } catch (e) {
      if (config.debug) console.log('Express Auth /logout Exception', e);
      if (PostError && typeof PostError === 'function') PostError(req, e);
      next(e);
    }
  },
);


router.post(
  '/forgot-password',
  express.json(),
  celebrate({
    body: {
      username: Joi.string().required(),
    },
  }),
  async (req, res, next) => {
    try {
      if (mongoose.connection.readyState === 0) throw new HttpError(500, 'Express Auth - MongoDB Connection Not Ready');
      const {
        username,
      } = req.body;
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(200).json({});
      }

      user.token = randomBytes(128).toString('hex');
      user.tokenCreated = Date.now();
      user.save();

      const userObj = user.toObject();
      delete userObj.password;
      delete userObj.salt;
      delete userObj.__v;

      res.status(200).json({});
      if (PostForgotPassword && typeof PostForgotPassword === 'function') PostForgotPassword(req, userObj);
    } catch (e) {
      if (config.debug) console.log('Express Auth /forgot-password Exception', e);
      if (PostError && typeof PostError === 'function') PostError(req, e);
      next(e);
    }
  },
);


router.post(
  '/restore-password',
  express.json(),
  celebrate({
    body: {
      username: Joi.string().required(),
      token: Joi.string().required(),
      newpassword: Joi.string().min(8).required(),
    },
  }),
  async (req, res, next) => {
    try {
      if (mongoose.connection.readyState === 0) throw new HttpError(500, 'Express Auth - MongoDB Connection Not Ready');
      const {
        username,
        token,
        newpassword,
      } = req.body;
      const user = await User.findOne({ username, token });
      if (!user) throw new HttpError(401, 'Could not restore password');
      if (user.tokenCreated < Date.now() - 24 * 60 * 60 * 1000) throw new HttpError(401, 'Token expired');
      user.salt = randomBytes(128).toString('hex');
      user.password = createHash('sha512').update(`${user._id.toString()}${user.salt}${newpassword}`).digest('hex');
      user.token = null;
      user.tokenCreated = null;
      user.save();

      const userObj = user.toObject();
      delete userObj.password;
      delete userObj.salt;
      delete userObj.__v;

      res.status(200).json(userObj);
      if (PostRestorePassword && typeof PostRestorePassword === 'function') PostRestorePassword(req, userObj);
    } catch (e) {
      if (config.debug) console.log('Express Auth /create-user Exception', e);
      if (PostError && typeof PostError === 'function') PostError(req, e);
      next(e);
    }
  },
);

router.use(errors());

module.exports = {
  AuthConnect: Connect,
  AuthRouter: router,
  AuthMiddleware: validateCookie,
  CustomError: HttpError,
  UserModel: User,
  UserSessionModel: UserSession,

  onLogin,
  onLogout,
  onCreateUser,
  onUserStatus,
  onForgotPassword,
  onRestorePassword,
  onError,
};
