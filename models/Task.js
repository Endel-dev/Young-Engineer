const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

// Define the task schema
const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  taskId: {  type: String, unique: true, default: uuidv4 },
  assignedTo: { type: String, required: true },  // This could refer to a userId
  associates: { type: [String] },  // Array of user IDs
  expectedCompletionDate: { type: Date, required:true 
},
  rewardType: { type: String, enum: ['cash', 'points'], default: 'cash' },
  fairType: { type: String },
  fairAmount: { type: Number },
  taskStatus: { type: String, enum: ['not-started', 'in-progress', 'completed','pending'], default: 'pending' },
  associatedInterestsChild: { type: [String] },  // Array of interests related to child
  createdBy: { 
   type: String, required:true  },  // Creator's user ID
  fairDistribution: { type: String },
  penaltyAmount: { type: Number },
  taskPriority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'unpaid'], default: 'pending' },
  schedule: { type: String },
  taskType: { type: String, enum: ['weekly', 'daily','monthly','one-time'], default: 'one-time' },
  guardians: { type: [String] }, 
  completionDate: { type: Date },
  completionTime: { type: Date },
}, {
  timestamps: true,  // This will automatically add createdAt and updatedAt fields
});

// Virtual field to check if the task is expired
taskSchema.virtual('isExpired').get(function () {
  // Compare the current date with the expected completion date
  return this.expectedCompletionDate < new Date();
});

// To make sure the virtual field shows up in JSON responses
taskSchema.set('toJSON', {
  virtuals: true,
  transform: (doc, ret) => {
    delete ret._id; 
    delete ret.id; // Optionally remove _id if you want it removed
    return ret;
  }

});


const Task = mongoose.model('Task', taskSchema);

module.exports = Task;




