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
const UserModel = require('./model/user');
const UserSessionModel = require('./model/usersession');


const router = express.Router({ mergeParams: true });

router.post(
  '/login',
  express.json(),
  celebrate({
    body: {
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    },
  }),
  async (req, res, next) => {
    try {
      const authCookie = req.cookies[config.cookieAuthName];
      if (authCookie) throw new HttpError(500, 'Already logged in');

      const { email, password } = req.body;
      const u = await User.findOne({ email });
      if (!u) throw new HttpError(401, 'Username or password not correct');
      const hashedPassword = createHash('sha512').update(`${u._id?.toString()}${u.salt}${password}`).digest('hex');
      if (u.password !== hashedPassword) throw new HttpError(401, 'Username or password not correct');

      const userObj = u.toObject();
      delete userObj.password;
      delete userObj.salt;
      delete userObj.__v;

      const session = await new UserSession({
        user: userObj._id,
      }).save();
      const jwt = JWT.encodeToken({
        ...userObj,
        session: session._id.toString(),
      });
      session.jwt = jwt;
      session.save();

      res.cookie(config.cookieAuthName, jwt, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV !== 'local',
      });

      res.status(200).json(u);
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  '/create-user',
  express.json(),
  celebrate({
    body: {
      email: Joi.string().email().required(),
      name: Joi.string().required(),
      password: Joi.string().min(8).required(),
    },
  }),
  async (req, res, next) => {
    try {
      const {
        email,
        name,
        password,
      } = req.body;
      const user = await User.findOne({ email });
      if (user) throw new HttpError(500, 'User already exists');
      const newUser = await new User({
        email,
        name,
      }).save();
      if (!newUser) throw new HttpError(500, 'Could not create user');
      newUser.salt = randomBytes(128).toString('hex');
      newUser.password = createHash('sha512').update(`${newUser._id.toString()}${newUser.salt}${password}`).digest('hex');
      newUser.save();
      res.status(200).json(newUser);
    } catch (e) {
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
    } catch (e) {
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
      if (!req.auth) throw new HttpError(401, 'No user found');
      const { sessionId, all } = req.query;

      if (all) {
        const sessions = await UserSession.find({ user: new mongoose.Types.ObjectId(req.auth._id) });
        for (const s of sessions) {
          s.deleted = Date.now();
          s.save();
        }
        // await UserSession.deleteMany({ user: new mongoose.Types.ObjectId(req.auth._id) });
        // res.clearCookie(config.cookieAuthName);
        // return res.status(200).json({});
      }

      if (sessionId) {
        const session = await UserSession.findOne({ _id: new mongoose.Types.ObjectId(sessionId), user: new mongoose.Types.ObjectId(req.auth._id) });
        if (!session) throw new HttpError(404, 'Provided sessionId Not Found');
        // await session.deleteOne();
        session.deleted = Date.now();
        session.save();
      } else {
        const session = await UserSession.findOne({ _id: new mongoose.Types.ObjectId(req.auth.session) });
        if (!session) throw new HttpError(401, 'No User Session Found');
        // await session.deleteOne();
        session.deleted = Date.now();
        session.save();
      }

      res.clearCookie(config.cookieAuthName);

      res.status(200).json({});
    } catch (e) {
      next(e);
    }
  },
);

router.use(errors());

module.exports = {
  AuthRouter: router,
  UserModel,
  UserSessionModel,
};
