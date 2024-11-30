const mongoose = require('mongoose');
const {v4: uuidv4 } = require('uuid');


// Define the Redemption Details sub-schema
const redemptionDetailSchema = new mongoose.Schema({
  redemptionId:{ type:String, required:true,unique:true},
  userId: { type: String, ref: 'User', required: true },  // Referencing User model
  rewardId: { type: String, ref: 'Reward', required: true },  // The associated reward
  dateClaimed: { type: Date, default: Date.now },  // Date when the reward was claimed
  method: { type: String, enum: ['cash', 'points', 'voucher'], required: true },  // Payment method (cash, points, voucher, etc.)
  rewardPaymentStatus: { 
    type: String, 
    enum: ['pending', 'complete'], 
    default: 'pending',  // Payment status for the reward (pending or complete)
  },
}, { timestamps: true });

 
// Reward Schema to define rewards (tablet, phone, etc.)
const rewardSchema = new mongoose.Schema({
  rewardId: { type:String, required:true, unique:true},
  rewardName: { type: String, required: true },
  rewardType: { type: String, enum: ['tablet', 'phone', 'cash','voucher','other'], required: true },  // Type of reward
  requiredPoints: { type: Number, default: 0 },  // Points required for this reward
  //requiredCash: { type: Number, default: 0 },    // Cash required for this reward
  startDate: {type:Date, required:true},
  expiryDate: { type: Date, required: true },  // Expiry date of the reward
  category: { type: String, required: true },  // Category of the reward (e.g., electronics, fashion, etc.)
  claimedBy: [{ type: String, ref: 'User', default: null }],  // User who claimed the reward
  //dateClaimed: { type: Date, default: null },  // Date when the reward was claimed
  expirationGracePeriod: { type: Number, default: 0 },  // Grace period (in days) after the reward expires
  duration: { type: Number },  // Duration for which the reward is available (in days),
  createdBy:{ type:String, ref:'User',},
  expirationStatus: { 
    type: String, 
    enum: ['expired', 'valid', 'graceperiod'], 
    default: 'valid',  // Expiration status of the reward
  },
  isApproved: { 
    type: Boolean, 
    default: false,  // Whether the reward is approved (admin approval)
  },
  claimStatus: { 
    type: String, 
    enum: ['claimed', 'unclaimed', 'pending'], 
    default: 'unclaimed',  // Status of whether the reward is claimed or not
  },
  redemptionDetails: [redemptionDetailSchema],  // Array of redemption details for each claim

  //: { type: String, enum: ['active', 'inactive'], default: 'active' },  // Reward status
}, {
  timestamps: true,
});

// Reward Schema
rewardSchema.virtual('daysLeft').get(function () {
  const currentDate = new Date();
  const expiryDate = new Date(this.expiryDate);

  // Calculate the difference between current date and expiry date in days
  const timeDifference = expiryDate - currentDate;
  if (timeDifference < 0) {
    return 0; // No days left, reward has expired
  }

  const daysLeft = Math.ceil(timeDifference / (1000 * 60 * 60 * 24)); // Convert milliseconds to days
  
  return daysLeft;
});

// Ensure virtuals are included in JSON responses
rewardSchema.set('toJSON', { virtuals: true });


function calculateDuration(startDate, expiryDate) {
  // Convert startDate and expiryDate to JavaScript Date objects if they are not already
  const start = new Date(startDate);
  const expiry = new Date(expiryDate);

  // Check if the expiryDate is after startDate
  if (expiry < start) {
    throw new Error("Expiry date cannot be earlier than start date.");
  }

  // Calculate the difference in time (in milliseconds)
  const timeDifference = expiry - start;

  // Calculate the duration in days (milliseconds in a day = 86400000)
  const durationInDays = timeDifference / (1000 * 60 * 60 * 24);
  // Round the duration to the nearest whole number
  const roundedDuration = Math.round(durationInDays);

  return roundedDuration;

  
}

// Function to calculate expiration status based on current date and expiry date
function calculateExpirationStatus(expiryDate, gracePeriod) {
  const currentDate = new Date();
  const expiry = new Date(expiryDate);
  let timeDifference;
  
  
  // Calculate the difference in milliseconds between current date and expiry date
  if (gracePeriod ===0){
      timeDifference = expiry - currentDate;
      if (timeDifference<0){
        return 'expired';
      }
      else{
        return 'valid';
      }
  }

  if (gracePeriod >0){
    const gracePeriodEnd = expiry.getTime() + gracePeriod * 24 * 60 * 60 * 1000;
    //timeDifference = (expiry+gracePeriod) - currentDate;
    timeDifference = currentDate - expiry;
    if (timeDifference<0){
      return 'valid';
    }
    else if (timeDifference >= 0 && currentDate <= gracePeriodEnd) {
      return 'gracePeriod';  
    }
    else{
      return 'expired';
    }
    
  }
  // If expiry date is in the past, the reward is expired
  

  // Check if the expiry date is within the grace period (e.g., a few days after expiry)
  // const gracePeriodMillis = gracePeriod * 24 * 60 * 60 * 1000; // Convert grace period to milliseconds
  // if (timeDifference <= gracePeriodMillis) {
  //   return 'graceperiod';
  // }
  


  // If the expiry date is in the future, the reward is still valid
  //return 'valid';
}



// Pre-save hook to calculate duration
rewardSchema.pre('save', function (next) {
  if (this.expiryDate && this.startDate) {
    // Calculate the duration using the function
    const duration = calculateDuration(this.startDate, this.expiryDate);
    this.duration = duration;
  }

  next(); // Continue to save the document
});

// Pre-save hook to automatically calculate and set expirationStatus
rewardSchema.pre('save', function (next) {
  // Check if the expiry date is set and calculate the expiration status
  if (this.expiryDate) {
    this.expirationStatus = calculateExpirationStatus(this.expiryDate, this.expirationGracePeriod);
  }

  next(); // Proceed with saving the document
});



 
const Reward = mongoose.model('Reward', rewardSchema);
 
module.exports = Reward;