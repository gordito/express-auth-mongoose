const mongoose = require('mongoose');

module.exports = mongoose.model(
  'UserSession',
  new mongoose.Schema({
    userid: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    jwt: { type: String },
    created: { type: Date, default: Date.now },
    updated: { type: Date, default: Date.now },
    deleted: { type: Date },
  }),
);
