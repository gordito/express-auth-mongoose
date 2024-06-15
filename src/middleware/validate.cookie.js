// const mongoose = require('mongoose');
const mongoose = require('mongoose');
const { HttpError } = require('./custom.error');
const JWT = require('../helpers/jwt');
const config = require('../helpers/config');
const UserSession = require('../model/usersession');

const validateCookie = async (req, res, next) => {
  try {
    const authCookie = req.cookies[config.cookieAuthName];
    if (!authCookie) throw new HttpError(401, 'Unauthorized');

    if (!JWT.validateToken(authCookie)) {
      res.clearCookie(config.cookieAuthName);
      throw new HttpError(401, 'Cookie not valid');
    }

    req.auth = JWT.decodeToken(authCookie);

    const session = await UserSession.findOne({ _id: new mongoose.Types.ObjectId(req.auth.session) });
    if (!session || session.deleted) {
      res.clearCookie(config.cookieAuthName);
      throw new HttpError(401, 'No User Session Found');
    }
    // TODO: Regeerate JWT token, update session in db and set new cookie

    next();
  } catch (e) {
    if (config.debug) console.log('Validate Cookie Error', e);
    next(e);
  }
};

module.exports = validateCookie;
