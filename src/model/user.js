const mongoose = require('mongoose');

module.exports = mongoose.model(
  'User',
  new mongoose.Schema({
    email: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    usertype: { type: String, default: 'email' },
    name: { type: String },
    password: { type: String },
    salt: { type: String },
    token: { type: String },
    tokenCreated: { type: Date },
    created: { type: Date, default: Date.now },
    updated: { type: Date, default: Date.now },
    deleted: { type: Date },
  }),
);
