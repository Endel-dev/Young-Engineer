const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Define the user schema
const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true, default: uuidv4 },
  name: { type: String, required: true ,unique:true},
  gender: { type: String, enum: ['male', 'female', 'other'] },
  image: { type: String }, // URL or base64 of the image
  region: { type: String },
  currency: { type: String, default: 'INR' }, // Default to USD
  email: { type: String, 
    unique: true,
    required: function() {
      return this.role === 'parent' || this.role === 'guardian';
    } },
  password: { type: String, required: true },
  role: { type: String, enum: ['parent', 'child', 'guardian'], default: 'parent' }, // Default role
  dob: { type: Date, required: true },
  balance: { type: Number, default: 0 },
  dateOfJoining: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  parentId: { 
    type: String,   // Refers to the User model itself
    required: function() {
      return this.role === 'child';  // Only required if the role is 'child'
    },
    default: null
  },

  deviceId:{
    type: String 
  },
  //deviceToken: {
  //  type: String, // Array of device tokens
   // default: null
  //},
  Totalpoints:{ type: Number, default: 0},
  familyId:[{ 
    type: String, 
    ref: 'Family',  
  }],
  guardian: [{ type : String,
  ref:'User',
}]
});

// Hash password before saving (bcryptjs for hashing)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  
 // Only hash if password is modified
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Password validation method
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;
