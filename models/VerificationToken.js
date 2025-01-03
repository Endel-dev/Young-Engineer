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

userSchema.pre("save", async function (next) {
  if (typeof this.dob === 'string') {
    const dobParts = this.dob.split('-');
    if (dobParts.length === 3) {
      const day = dobParts[0];
      const month = dobParts[1] - 1; // Month is 0-indexed in JavaScript Date
      const year = dobParts[2];

      // Create a Date object from the string
      this.dob = new Date(year, month, day);

      if (isNaN(this.dob)) {
        return next(new Error("Invalid date format. Expected dd-mm-yyyy."));
      }
    } else {
      return next(new Error("Invalid date format. Expected dd-mm-yyyy."));
    }
  }
});


const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);
module.exports = VerificationToken;


