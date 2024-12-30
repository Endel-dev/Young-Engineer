const mongoose = require('mongoose');

const VerificationTokenSchema = new mongoose.Schema({
  name: { type: String },
  firstName:{type:String},
  lastName:{type:String},
  gender: { type: String},
  password: { type: String },
  role: { type: String},
  dob: { type: Date },
  email: { type: String, required: true },
  token: { type: String, required: true },
  phoneNumber: { type: String },
  address1: { type: String },
  address2: { type: String },
  address3: { type: String },
  city: { type: String },
  state: { type: String },
  pinCode: { type: String},
  numberOfKids: { type: Number },
  kidsNames: [{ type: String }],
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);
module.exports = VerificationToken;
