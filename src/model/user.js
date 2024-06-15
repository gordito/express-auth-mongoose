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
    name: { type: String },
    password: { type: String },
    salt: { type: String },
    created: { type: Date, default: Date.now },
    updated: { type: Date, default: Date.now },
    deleted: { type: Date },
  }),
);
