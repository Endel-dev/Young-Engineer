const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Define the user schema
const familySchema = new mongoose.Schema({
  familyId: [{ type: String}],
  familyName: { type: String, required: true },
  region: { type: String },
  currency: { type: String, default: 'INR' },
  budgetlimit: { type: Number, default: 0 },
  budgetType: { type: String, enum: ['cash', 'points'], default: 'cash'},
  dateOfCreation: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  parentId: { 
    type: String
  },
  guardianIds: [{ 
    type: String,  // Array of User IDs (secondary family members)
    default: []
  }],
  children: [{ 
    type: String,   // Array of User IDs for the children in this family
    default: []
  }]

});

const Family = mongoose.model('Family', familySchema);

module.exports = Family;
