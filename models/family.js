const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Define the user schema
const familySchema = new mongoose.Schema({
  familyId: { type: String, required: true, unique: true },
  familyName: { type: String, required: true },
  region: { type: String },
  currency: { type: String, default: 'INR' },
  budgetlimit: { type: Number, default: 0 },
  //budgetType: { type: Number, default:0},
  dateOfCreation: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  parentId: { 
    type: String, 
    ref: 'User',  // Refers to the User model itself
    required: function() {
      return this.role === 'child';  // Only required if the role is 'child'
    },
    default: null
  },
  family_members:[{type:String}],

});

const Family = mongoose.model('Family', familySchema);

module.exports = Family;
