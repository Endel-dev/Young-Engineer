const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Define the user schema
const familySchema = new mongoose.Schema({
  familyId: { type: String, required: true, unique: true ,default: uuidv4},
  familyName: { type: String, required: true },
  region: { type: String },
  currency: { type: String, default: 'INR' },
  budgetlimit: { type: Number, default: 0 },
  budgetType: { type: String, enum: ['cash', 'points'], default: 'cash'},
  dateOfCreation: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  parentId: { 
    type: String,   // Refers to the User model itself
    required: function() {
      return this.role === 'child';  // Only required if the role is 'child'
    },
    default: null
  },

});

const Family = mongoose.model('Family', familySchema);

module.exports = Family;
