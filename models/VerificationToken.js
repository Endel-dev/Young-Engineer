const mongoose = require('mongoose');

const VerificationTokenSchema = new mongoose.Schema({
  name: { type: String, required: true },
  gender: { type: String, required: true},
  password: { type: String, required: true },
  role: { type: String, required: true},
  dob: { type: Date, required: true },
  email: { type: String, required: true },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  verified: { type: Boolean, default: false },
});

const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);
module.exports = VerificationToken;
