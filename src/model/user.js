const mongoose = require('mongoose');

module.exports = mongoose.model(
  'User',
  new mongoose.Schema({
    username: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    usertype: { type: String, default: 'email' },
    password: { type: String },
    salt: { type: String },
    token: { type: String },
    tokenCreated: { type: Date },
    created: { type: Date, default: Date.now },
    updated: { type: Date, default: Date.now },
    deleted: { type: Date },
  }),
);
