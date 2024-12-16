const mongoose = require('mongoose');

const VerificationTokenSchema = new mongoose.Schema({
  name: { type: String },
  gender: { type: String},
  password: { type: String },
  role: { type: String},
  dob: { type: Date },
  email: { type: String, required: true },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);
module.exports = VerificationToken;
