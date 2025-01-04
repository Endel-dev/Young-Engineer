const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
//const moment = require("moment");
const { parse, isValid, format } = require('date-fns'); 

// Define the user schema
const userSchema = new mongoose.Schema(
  {
    userId: { type: String, unique: true, default: uuidv4 },
    name: { type: String },
    gender: { type: String, enum: ["male", "female", "other"] },
    image: { type: String }, // URL or base64 of the image
    region: { type: String },
    currency: { type: String, default: "INR" }, // Default to USD
    email: {
      type: String,
      sparse: true,
      // required: function () {
      //   return this.role === "parent" || this.role === "guardian";
      // },
      // validate: {
      //   validator: async function (value) {
      //     if (this.role === "parent" || this.role === "guardian") {
      //       const existingUser = await mongoose
      //         .model("User")
      //         .findOne({ email: value });
      //       return !existingUser;
      //     }
      //     return true;
      //   },
      //   message: "Email must be unique for parent and guardian roles",
      // },
    },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["parent", "child", "guardian"],
      default: "parent",
    }, // Default role
    dob: { type: Date, required: true },
    balance: { type: Number, default: 0 },
    dateOfJoining: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },

    parentId: [
      {
        type: String, // Refers to the User model itself
        required: function () {
          return this.role === "child"; // Only required if the role is 'child'
        },
        default: null,
      },
    ],
    guardianId: [{ type: String }],

    deviceId: {
      type: String,
    },
    //deviceToken: {
    //  type: String, // Array of device tokens
    // default: null
    //},
    Totalpoints: { type: Number, default: 0 },
    familyId: [
      {
        type: String,
        ref: "Family",
      },
    ],
    guardian: [
      {
        type: String,
        ref: "User",
      },
    ],
    //Fields specific to 'parent' role
    phoneNumber: { type: String },
    address1: { type: String },
    address2: { type: String },
    address3: { type: String },
    city: { type: String },
    state: { type: String },
    pinCode: { type: String },
    numberOfKids: { type: Number },
    kidsNames: [{ type: String }],

    // Fields specific to 'child' role
    firstName: { type: String },
    lastName: { type: String },
    school: { type: String },
    hobby1: { type: String },
    hobby2: { type: String },
    hobby3: { type: String },
  },
  {
    autoIndex: false,
  }
);

userSchema.pre("save", function (next) {
  if (this.firstName && this.lastName) {
    this.name = `${this.firstName} ${this.lastName}`;
  }
  next();
});

// Hash password before saving (bcryptjs for hashing)
// userSchema.pre("save", async function (next) {
//     if (typeof this.dob === 'string') {
//       const dobParts = this.dob.split('-');
//       if (dobParts.length === 3) {
//         const day = dobParts[0];
//         const month = dobParts[1] - 1; // Month is 0-indexed in JavaScript Date
//         const year = dobParts[2];
  
//         // Create a Date object from the string
//         this.dob = new Date(year, month, day);
  
//         if (isNaN(this.dob)) {
//           return next(new Error("Invalid date format. Expected dd-mm-yyyy."));
//         }
//       } else {
//         return next(new Error("Invalid date format. Expected dd-mm-yyyy."));
//       }
//     }
    

    
//   if (!this.isModified("password")) return next();

//   // Only hash if password is modified
//   try {
//     const salt = await bcrypt.genSalt(10);
//     this.password = await bcrypt.hash(this.password, salt);
//     next();
//   } catch (err) {
//     next(err);
//   }
// });

userSchema.pre("save", function (next) {
  if (typeof this.dob === "string") {
    // Parse the date string 'dd-mm-yyyy' format into a Date object
    const parsedDob = parse(this.dob, "dd-MM-yyyy", new Date());

    // Check if the parsed date is valid
    if (!isValid(parsedDob)) {
      return next(new Error("Invalid date format. Expected dd-mm-yyyy."));
    }

    // Set the dob field to the parsed Date object
    this.dob = parsedDob;
  }
});

userSchema.pre("save", async function (next) {
  // Ensure that the password is hashed before saving
  if (this.isModified("password")) {
    try {
      const salt = await bcrypt.genSalt(10); // Generate salt
      this.password = await bcrypt.hash(this.password, salt); // Hash the password
    } catch (error) {
      return next(error);
    }
  }
});


// userSchema.pre("save", async function (next) {
//   if (typeof this.dob === "string") {
//     // Validate the format before proceeding
//     const validDate = moment(this.dob, "DD-MM-YYYY", true); // 'true' enforces strict parsing
//     if (!validDate.isValid()) {
//       return next(new Error("Invalid date format. Expected dd-mm-yyyy."));
//     }

//     // Now that it's valid, convert to a Date object
//     this.dob = validDate.toDate(); // Convert the moment object to a native Date
//   }
// });



// Password validation method
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model("User", userSchema);

module.exports = User;
