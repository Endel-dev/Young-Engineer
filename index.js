const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const User = require("./models/User");
const Family = require("./models/family");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const app = express();
// const { authenticate, checkParentRole } = require('./middleware/auth');
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const router = express.Router();
const multer = require("multer");
const path = require("path");
//router.put('/update', protect, updateUserDetails);
const axios = require("axios");
const admin = require("firebase-admin");
//const sendNotificationToDevice = require('./notificationService');
const Reward = require("./models/reward");
const rateLimit = require("express-rate-limit");
const compression = require("compression"); // Import compression
const VerificationToken = require("./models/VerificationToken");
const FRONTEND_URL = "templates/sample.html";
const app_versions = require("./models/app_versions");
//const moment = require("moment");
//const { parse, format } = require('date-fns');
const moment = require('moment');

//const Redemption = require('./models/Redemption');

//const { sendNotification } = require('./notifications/sendNotification');

app.use(express.json());
//app.use(express.static(path.join(__dirname,'public')));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 500,
  message: "Too many requests, please try again later.",
});

app.use(limiter);
app.use(compression());

app.get("/large-data", (req, res) => {
  const largeData = res.json(largeData); // large data payload // // The response will be compressed before being sent to the client
});
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});
app.get("/sample", (req, res) => {
  res.sendFile(path.join(__dirname, "sample.html"));
});
app.get("/demo", (req, res) => {
  res.sendFile(path.join(__dirname, "demo.html"));
});
app.get("/verify-email1", (req, res) => {
  res.sendFile(path.join(__dirname, "sample.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});
app.get("/verify", (req, res) => {
  res.sendFile(path.join(__dirname, "verify.html"));
});
app.get("/verify-parent", (req, res) => {
  res.sendFile(path.join(__dirname, "verify-parent.html"));
});
app.get("/second-parent-verify", (req, res) => {
  res.sendFile(path.join(__dirname, "second-parent-verify.html"));
});
app.get("/second-parent", (req, res) => {
  res.sendFile(path.join(__dirname, "second-parent.html"));
});
app.get("/guardian-verify", (req, res) => {
  res.sendFile(path.join(__dirname, "guardian-verify.html"));
});

app.get("/register-form", (req, res) => {
  res.sendFile(path.join(__dirname, "create-guardian.html"));
});
app.get("/send-invite", (req, res) => {
  res.sendFile(path.join(__dirname, "send-invite.html"));
});
app.get("/register-form-parent", (req, res) => {
  res.sendFile(path.join(__dirname, "register-form-parent.html"));
});
app.get("/reset-password", (req,res) => {
  res.sendFile(path.join(__dirname,"reset-password.html"));
});
app.get("/reset-successfull", (req,res) => {
  res.sendFile(path.join(__dirname,"reset-successfull.html"));
});


// app.get('/verify-email', (req, res) => {
//   res.sendFile(path.join(__dirname, 'verify-email.html'));
// });
// app.get('/verify-Email.js', (req, res) => {
//   res.sendFile(path.join(__dirname, 'verify-Email.js'));
// });

//const serviceAccount = require('C:/Users/admin/Downloads/react-native-app-8b283-firebase-adminsdk-5jj6x-e268f24026.json'); // Your Firebase service account JSON file
//admin.initializeApp({
//credential: admin.credential.cert(serviceAccount),
//});

// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount)
// });

// In-memory storage of user-device tokens (you should use a database in production)
// let usersDeviceTokens = {
//   // Example: "userId123": "deviceToken123"
//   // Store device tokens associated with user IDs
//   "P203":"dGVzdC10b2tlbi1mb3ItYXBwLXVzZXItY29tLXJlYWwtY2VydC1zdHJpbmc"
// };

const upload = multer({
  dest: "uploads/images/", // Store uploaded files in this directory
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
  fileFilter: (req, file, cb) => {
    // Allow only image files (JPEG, PNG, GIF)
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only image files are allowed."));
    }
  },
});
module.exports = upload;

dotenv.config(); // Load environment variables from .env file

const port = process.env.PORT || 5001;

// Middleware
require("dotenv").config();
//app.use(express.json()); // for parsing application/json
app.use(express.json({ limit: "10mb" }));

app.use(cors()); // Enable cross-origin requests

// MongoDB connection
mongoose
  .connect("mongodb://localhost:27017/react-native-app")
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB connection error:", err));

// User registration route
// POST /register (For Parent User)

// app.post('/registers', async (req, res) => {
//   const { name, gender, email, password, role, dob } = req.body;
//   const normalizedRole = role ? role.toLowerCase() : '';
//   const normalizedgender = gender ? gender.toLowerCase() : '';

//   if (normalizedRole !== 'parent' && normalizedRole !== 'guardian') {
//     return res.status(400).json({ status: 0, message: 'Only parent and guardian role is allowed to register' });
//   }

//   // Validate required fields
//   if (!name || !email || !password || !dob || !gender) {
//     return res.status(400).json({ status: 0, message: 'Please provide all required fields' });
//   }

//   try {
//     const existingUser = await User.findOne({ $or: [{ email }, { name }] }).where('deleted').equals(false);
//     if (existingUser) {
//       return res.status(200).json({ status: 0, message: 'Email or Name already exists' });
//     }
//     // const salt = await bcrypt.genSalt(10);
//     // const hashedPassword = await bcrypt.hash(password, salt);
//     // const newUser = new User({
//     //   name,
//     //   gender: normalizedgender,
//     //   email,
//     //   password:hashedPassword,  // Make sure to hash the password before saving
//     //   role: normalizedRole,
//     //   dob,
//     // });

//     //Create the new user
//     // const newUser = new User({
//     //   name,
//     //   gender: normalizedgender,
//     //   email,
//     //   password,
//     //   role: normalizedRole,
//     //   dob,
//     // });

//     // // Save the new user to the database
//     // await newUser.save();

//     // Create a unique email verification token with 24 hours expiration
//     //const token = crypto.randomBytes(32).toString('hex');  // 32 bytes token

//     // Save the token in the database (or cache it for 24 hours expiration)

//     const token = jwt.sign(
//       {email  }, //userId: newUser.userId, role: newUser.role
//       process.env.JWT_SECRET,
//       { expiresIn: '24h' } // Token will expire in 15 days
//     );
//     const verificationLink = `http://93.127.172.167:5001/verify-email?token=${token}&email=${email}`;

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);
//     const verificationToken = new VerificationToken({
//       email,
//       token:token,
//       name,
//       role:normalizedRole,
//       gender:normalizedgender,
//       dob,
//       password:hashedPassword,
//       expiresAt: Date.now() + 24 * 60 * 60 * 1000, // expires in 24 hours
//     });
//     await verificationToken.save();

//     // Send the verification link to the user's email
//     const transporter = nodemailer.createTransport({
//       host: 'mail.weighingworld.com',
//       port: 465,
//       secure: true,
//       auth: {
//         user: 'no-reply@weighingworld.com',
//         pass: '$]IIWt4blS^_',
//       },
//     });

//     const mailOptions = {
//       from: 'no-reply@weighingworld.com',
//       to: email,
//       subject: 'Email Verification',
//       text: `Please verify your email by clicking on the following link: ${verificationLink}`,
//     };

//     transporter.sendMail(mailOptions, (error, info) => {
//       if (error) {
//         return res.status(500).json({ status: 0, message: 'Error sending verification email' });
//       }

//       res.status(200).json({
//         status: 1,
//         message: 'Registration successful. A verification email has been sent.',
//       });
//     });

//   } catch (err) {
//     console.error('Error registering user:', err);
//     res.status(500).json({ status: 0, message: 'Server error' });
//   }
// });

// POST /register

app.post("/registers", async (req, res) => {
  const {
    name,
    gender,
    firstName,
    lastName,
    email,
    password,
    role,
    dob,
    city,
    phoneNumber,
    address1,
    address2,
    address3,
    state,
    pinCode,
    numberOfKids,
    kidsNames,
  } = req.body; 

  const normalizedRole = role ? role.toLowerCase() : "";
  const normalizedGender = gender ? gender.toLowerCase() : "";

  // Validate role
  if (normalizedRole !== "parent" && normalizedRole !== "guardian") {
    return res.status(400).json({
      status: 0,
      message: "Only parent and guardian roles are allowed to register",
    });
  }

  // Validate required fields
  if (!name || !email || !password || !dob || !gender ||!firstName ||!lastName) {
    return res
      .status(400)
      .json({ status: 0, message: "Please provide all required fields" });
  }

  try {
    // Check if the email already exists in the User model
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ status: 0, message: "User already verified" });
    }

    // Check if the email exists in the VerificationToken model and is expired
    const existingVerificationToken = await VerificationToken.findOne({
      email,
      expiresAt: { $gt: Date.now() }, // Check if the token is still valid (not expired)
    });

    if (existingVerificationToken) {
      // If verification token exists and is not expired, don't send mail
      return res.status(400).json({
        status: 0,
        message:
          "Mail already sent for email verification and token is still valid",
      });
    }

    // If no valid verification token exists, proceed with sending the verification email
    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });
    const verificationLink = `http://93.127.172.167:5001/sample?token=${token}&email=${email}`;

    // Create a new verification token
    const verificationToken = new VerificationToken({
      email,
      token,
      name,
      firstName,
      lastName,
      role: normalizedRole,
      gender: normalizedGender,
      dob,
      password,
      city,
      phoneNumber,
      address1,
      address2,
      address3,
      state,
      pinCode,
      numberOfKids,
      kidsNames,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // expires in 24 hours
    });

    // Save the verification token to the database
    await verificationToken.save();

    console.log("Verification Token:", verificationToken);

    // Send verification email
    const transporter = nodemailer.createTransport({
      host: "mail.weighingworld.com",
      port: 465,
      secure: true,
      auth: {
        user: "no-reply@weighingworld.com",
        pass: "$]IIWt4blS^_",
      },
    });

    const mailOptions = {
      from: "no-reply@weighingworld.com",
      to: email,
      subject: "Email Verification",
      text: `Please verify your email by clicking on the following link: ${verificationLink}`,
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res
          .status(500)
          .json({ status: 0, message: "Error sending verification email" });
      }

      // Respond with success message if email is sent
      res.status(200).json({
        status: 1,
        message: "Registration successful. A verification email has been sent.",
      });
    });
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});

app.post("/register", async (req, res) => {
  const {
    name,
    gender,
    firstName,
    lastName,
    email,
    password,
    role,
    dob,
    city,
    country,
    phoneNumber,
    address1,
    address2,
    address3,
    state,
    pinCode,
    numberOfKids,
    kidsNames,
  } = req.body; 

  const normalizedRole = role ? role.toLowerCase() : "";
  const normalizedGender = gender ? gender.toLowerCase() : "";

  // Validate role
  if (normalizedRole !== "parent" && normalizedRole !== "guardian") {
    return res.status(400).json({
      status: 0,
      message: "Only parent and guardian roles are allowed to register",
    });
  }

  // Validate required fields
  if (!name || !email || !password || !dob || !gender || !firstName || !lastName) {
    return res
      .status(400)
      .json({ status: 0, message: "Please provide all required fields" });
  }

  try {
    // Check if the email already exists in the User model
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ status: 0, message: "User already verified" });
    }

    // Check if the email exists in the VerificationToken model and is expired
    const existingVerificationToken = await VerificationToken.findOne({
      email,
      expiresAt: { $gt: Date.now() }, // Check if the token is still valid (not expired)
    });

    if (existingVerificationToken) {
      // If verification token exists and is not expired, don't send mail
      return res.status(400).json({
        status: 0,
        message:
          "Mail already sent for email verification and token is still valid",
      });
    }

    const parsedDob = moment(dob, 'DD-MM-YYYY').format('YYYY-MM-DD');

    // If no valid verification token exists, proceed with generating the verification token
    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });
    const verificationLink = `http://93.127.172.167:5001/sample?token=${token}&email=${email}`;

    // Create a new verification token
    const verificationToken = new VerificationToken({
      email,
      token,
      name,
      firstName,
      lastName,
      role: normalizedRole,
      gender: normalizedGender,
      dob: parsedDob,
      password,
      city,
      country,
      phoneNumber,
      address1,
      address2,
      address3,
      state,
      pinCode,
      numberOfKids,
      kidsNames,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // expires in 24 hours
    });

    // Save the verification token to the database
    await verificationToken.save();

    console.log("Verification Token:", verificationToken);

    // Respond with a 202 Accepted status indicating the request was accepted and is being processed
    res.status(202).json({
      status: 1,
      message: "Registration successful. A verification email will be sent shortly.",
    });

    // Send the email asynchronously after the response has been sent
    const transporter = nodemailer.createTransport({
      host: "mail.weighingworld.com",
      port: 465,
      secure: true,
      auth: {
        user: "no-reply@weighingworld.com",
        pass: "$]IIWt4blS^_",
      },
    });

    const mailOptions = {
      from: "no-reply@weighingworld.com",
      to: email,
      subject: "Email Verification",
      text: `Please verify your email by clicking on the following link: ${verificationLink}`,
    };

    // Send the verification email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending verification email:", error);
      } else {
        console.log("Verification email sent successfully:", info.response);
      }
    });

  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});


// app.post('/registers', async (req, res) => {
//   const { name, gender, email, password, role, dob } = req.body;

//   // Normalize role and gender to lowercase
//   const normalizedRole = role ? role.toLowerCase() : '';
//   const normalizedGender = gender ? gender.toLowerCase() : '';

//   // Check if role is either 'parent' or 'guardian'
//   if (normalizedRole !== 'parent' && normalizedRole !== 'guardian') {
//     return res.status(400).json({ status: 0, message: 'Only parent and guardian roles are allowed to register' });
//   }

//   // Check if all required fields are present
//   if (!name || !email || !password || !dob || !gender) {
//     return res.status(400).json({ status: 0, message: 'Please provide all required fields' });
//   }

//   try {
//     // 1. Check if user already exists in the User model (they are verified)
//     const existingUser = await User.findOne({ email }).where('deleted').equals(false);
//     console.log('Existing User:', existingUser);
//     if (existingUser) {
//       return res.status(400).json({ status: 0, message: 'User already verified' });
//     }

//     // 2. Check if there's already a verification token sent for this email (prevents duplicate requests)
//     const existingVerificationToken = await VerificationToken.findOne({ email });
//     if (existingVerificationToken) {
//       return res.status(400).json({ status: 0, message: 'Mail already sent for email verification' });
//     }

//     // 3. Proceed with registration if no existing user or verification token
//     const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
//     const verificationLink = `http://93.127.172.167:5001/sample?token=${token}&email=${email}`;

//     // Save verification token to the database
//     const verificationToken = new VerificationToken({
//       email,
//       token,
//       name,
//       role: normalizedRole,
//       gender: normalizedGender,
//       dob,
//       password,
//       expiresAt: Date.now() + 24 * 60 * 60 * 1000, // expires in 24 hours
//     });
//     await verificationToken.save();
//     console.log('Verification Token:', verificationToken);

//     // Send verification email
//     const transporter = nodemailer.createTransport({
//       host: 'mail.weighingworld.com',
//       port: 465,
//       secure: true,
//       auth: {
//         user: 'no-reply@weighingworld.com',
//         pass: '$]IIWt4blS^_',
//       },
//     });

//     const mailOptions = {
//       from: 'no-reply@weighingworld.com',
//       to: email,
//       subject: 'Email Verification',
//       text: `Please verify your email by clicking on the following link: ${verificationLink}`,
//     };

//     // Send the email
//     transporter.sendMail(mailOptions, (error, info) => {
//       if (error) {
//         return res.status(500).json({ status: 0, message: 'Error sending verification email' });
//       }

//       // Respond with success message if email is sent
//       res.status(200).json({
//         status: 1,
//         message: 'Registration successful. A verification email has been sent.',
//       });
//     });
//   } catch (err) {
//     console.error('Error registering user:', err);
//     res.status(500).json({ status: 0, message: 'Server error', err });
//   }
// });

// router.post('/verify-email', async (req, res) => {
//   const { token, email } = req.query;

//   // Check if token and email are provided
//   if (!token || !email) {
//     return res.status(400).json({ status: 0, message: 'Token and email are required' });
//   }

//   try {
//     // Find the verification token in the database
//     const verificationToken = await VerificationToken.findOne({ email, token });
//     if (!verificationToken) {
//       return res.status(400).json({ status: 0, message: 'Invalid or expired token' });
//     }

//     // Check if the token has expired
//     if (verificationToken.expiresAt < Date.now()) {
//       return res.status(400).json({ status: 0, message: 'Token has expired' });
//     }

//     // Check if user already exists (optional)
//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({ status: 0, message: 'User already exists' });
//     }

//     // Create a new user based on the verification token details
//     const newUser = new User({
//       name: verificationToken.name,
//       gender: verificationToken.gender,
//       email: verificationToken.email,
//       password: verificationToken.password, // It is assumed the password is hashed when saving the token
//       role: verificationToken.role,
//       dob: verificationToken.dob,
//     });

//     // Hash the password before saving the user (if not already done)
//     const salt = await bcrypt.genSalt(10);
//     newUser.password = await bcrypt.hash(newUser.password, salt);

//     // Save the new user to the database
//     await newUser.save();

//     // Mark the verification token as verified
//     verificationToken.verified = true;
//     await verificationToken.save();

//     res.status(200).json({ status: 1, message: 'Email successfully verified and user added' });
//   } catch (err) {
//     console.error('Error verifying email:', err);
//     res.status(500).json({ status: 0, message: 'Server error' });
//   }
// });

//module.exports = router;

app.post("/verify-email", async (req, res) => {
  const { token, email } = req.body;

  // Check if token and email are provided
  if (!token || !email) {
    return res
      .status(400)
      .json({ status: 0, message: "Token and email are required" });
  }

  try {
    // Find the verification token in the database
    const verificationToken = await VerificationToken.findOne({ email, token });

    // if (!verificationToken) {
    //   return res.status(400).json({ status: 0, message: 'Invalid or expired token' });
    // }

    // Check if the token has expired
    if (verificationToken.expiresAt < Date.now()) {
      return res.status(400).json({ status: 0, message: "Token has expired" });
    }

    // Mark user as verified in the User model (or update `isActive` field)
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ status: 0, message: "User not found" });
    }

    // Mark user as active/verified
    //user.isActive = true; // You can add an `isActive` field in the User schema to track verification status
    const newUser = new User({
      email: verificationToken.email,
      name: verificationToken.name,
      role: verificationToken.role,
      gender: verificationToken.gender,
      dob: verificationToken.dob,
      password: verificationToken.password,
    });

    await newUser.save();
    console.log(newUser);

    // Delete the verification token (optional)
    verificationToken.verified = true;
    await verificationToken.save();
    //await VerificationToken.deleteOne({ email, token });

    res.status(200).json({ status: 1, message: "Email successfully verified" });
  } catch (err) {
    console.error("Error verifying email:", err);
    res.status(500).json({ status: 0, message: "Server error " + err });
  }
});

// POST /verify-email
app.post("/verify-email1", async (req, res) => {
  const { token, email } = req.body;

  if (!token || !email) {
    return res
      .status(400)
      .json({ status: 0, message: "Token and email are required" });
  }

  try {
    console.log(req.body);
    const verificationToken = await VerificationToken.findOne({ email, token });
    console.log(verificationToken);

    if (!verificationToken) {
      return res
        .status(400)
        .json({ status: 0, message: "Invalid or expired token" });
    }

    if (verificationToken.expiresAt < Date.now()) {
      return res.status(400).json({ status: 0, message: "Token has expired" });
    }

    if (VerificationToken.verified == true) {
      return res
        .status(200)
        .json({ status: 0, message: "Email already verified" });
    }

    const userUuid = uuidv4(); // This generates a unique UUID for the user
    const familyId = userUuid.slice(-4); // Extract the last 4 characters for the family ID

    const newUser = new User({
      email: verificationToken.email,
      name: verificationToken.name,
      firstName:verificationToken.firstName,
      lastName:verificationToken.lastName,
      role: verificationToken.role,
      gender: verificationToken.gender,
      dob: verificationToken.dob,
      password: verificationToken.password,
      familyId: familyId,
      city: verificationToken.city,
      country:verificationToken.country,
      phoneNumber: verificationToken.phoneNumber,
      address1: verificationToken.address1,
      address2: verificationToken.address2,
      address3: verificationToken.address3,
      state: verificationToken.state,
      pinCode: verificationToken.pinCode,
      numberOfKids: verificationToken.numberOfKids,
      kidsNames: verificationToken.kidsNames,
    });

    await newUser.save();
    const family = new Family({
      familyName: `${newUser.name}'s Family`, // Family name based on the parent's name
      parentId: [newUser.userId], // Add the parent user ID
      familyId: newUser.familyId, // Generate a unique family ID (if necessary)
    });
    await family.save();

    await VerificationToken.deleteOne({ email, token });

    res.status(200).json({ status: 1, message: "Email successfully verified" });
  } catch (err) {
    console.error("Error verifying email:", err);
    res.status(500).json({ status: 0, message: "Server error" + err });
  }
});

app.post("/verify-guardians", async (req, res) => {
  const { email, token,parentId } = req.body;

  console.log(req.body);

  if (!email || !token) {
    return res
      .status(400)
      .json({ status: 0, message: "Email and token are required" });
  }

  try {
    // Step 1: Verify the token from the URL
    // Assuming the token is a JWT and it's already verified when sent in the URL
    // Normally, you would verify the token here, but as per your request we are just using it directly

    // Step 2: Find the guardian using the email
    const guardian = await User.findOne({ email: email, role: "guardian" });
    if (!guardian) {
      return res.status(404).json({
        status: 0,
        message: "Guardian not found",
      });
    }

    // Step 3: Find the parent using the familyId
    // The guardian's family ID is mapped to the parent's family ID
    // const parent = await User.findOne({ userId: guardian.parentId });
    // if (!parent) {
    //   return res.status(404).json({
    //     status: 0,
    //     message: "Parent not found",
    //   });
    // }
    console.log(parentId);

    const parent = await User.findOne({ userId:parentId });
    if (!parent) {
      return res.status(404).json({
        status: 0,
        message: "Parent not found",
      });
    }

    // Step 4: Find the family by familyId
    const family = await Family.findOne({ familyId: parent.familyId[0] });
    if (!family) {
      return res.status(404).json({
        status: 0,
        message: "Family not found",
      });
    }

    

    // Step 5: Check if the guardian is already part of the family
    if (family.guardianIds && family.guardianIds.includes(guardian.userId)) {
      return res.status(400).json({
        status: 0,
        message: "You are already a guardian of this family",
      });
    }

    // Step 5: Add the guardian to the family's guardians array
    if (!family.guardianIds) {
      family.guardianIds = [];
    }
    family.guardianIds.push(guardian.userId); // Add the guardian's userId to the family's guardians array
    await family.save();

    // Step 7: Update the guardian's document to reflect the added familyId
    // if (!guardian.guardianId) {
    //   guardian.guardianId = [];
    // }
    //guardian.guardianId.push(family.familyId);  // Add the familyId to the guardian's guardianIds array
   guardian.guardianId.push(String(family.familyId)); // Ensure it's a string.

    await guardian.save();

    // Step 6: Respond with success
    res.status(200).json({
      status: 1,
      message: "Email Verified Successfully",
    });
  } catch (err) {
    console.error("Error verifying email:", err);
    res.status(500).json({ status: 0, message: "Server error" + err });
  }
});

const verifyParentRole = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1]; // Get token from header

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    // Verify token and extract user role
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    console.log(req.user.role);
    //const normalizedRole = role ? role.toLowerCase() : '';
    //Only allow if the role is parent
    if (req.user.role !== "parent" && req.user.role !== "guardian") {
      //   //&& req.user.role !== 'parent'
      return res.status(403).json({
        message:
          "Access denied. Only parents and guardians  are allowed to do perform this action .",
      });
    }

    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    return res
      .status(400)
      .json({ message: "Invalid token", error: err.message });
  }
};

// const verifyParentOrGuardianRole = (req, res, next) => {
//   const token = req.header("Authorization")?.split(" ")[1]; // Get token from header

//   if (!token) {
//     return res
//       .status(401)
//       .json({ message: "Access denied. No token provided." });
//   }

//   try {
//     // Verify token and extract user role
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = decoded;

//     // Check if the role is either 'parent' or 'guardian'
//     if (req.user.role !== "parent" && req.user.role !== "guardian") {
//       return res.status(403).json({
//         message:
//           "Access denied. Only parents and guardians are allowed to perform this action.",
//       });
//     }

//     next(); // Proceed to the next middleware or route handler
//   } catch (err) {
//     return res
//       .status(400)
//       .json({ message: "Invalid token", error: err.message });
//   }
// };

const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1]; // Extract token from Authorization header

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    // Verify the token and extract the user information
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user info (including userId) to request object
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    return res
      .status(400)
      .json({ message: "Invalid token", error: err.message });
  }
};

app.put(
  "/upload-image",
  verifyToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const userId = req.user.userId; // Get userId from the decoded token
      const user = await User.findOne({ userId });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Get the image filename and store it in the database
      const imageFilename = req.file.filename; // This is the autogenerated filename from multer

      // Optionally, you can store the full path
      const imagePath = `/uploads/images/${imageFilename}`;

      // Update the user image field with the image file path
      user.image = imagePath; // Save the path in the user document

      await user.save();

      res.status(200).json({
        message: "User image uploaded successfully",
        //imagePath
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Error uploading image" });
    }
  }
);

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).send("File is too large");
    }
  }
  next(err);
});

//Login API
// app.post('/login', async (req, res) => {
//   const { email, password } = req.body;

//   if (!email || !password) {
//     return res.status(400).json({ status: 0, message: 'Please provide email and password' });
//   }

//   try {
//     // Check if user exists by email
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(401).json({ status: 0, message: 'Not User' });
//     }

//     // Compare the provided password with the stored password
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(401).json({
//         status: 0, message: 'Invalid email or password'
//       });
//     }

//     // Generate a 4-digit OTP (after successful password verification)
//     const otp = Math.floor(1000 + Math.random() * 9000); // Generate a 4-digit number

//     // Set up SMTP transporter using provided credentials
//     const transporter = nodemailer.createTransport({
//       host: 'mail.weighingworld.com',  // SMTP server
//       port: 465,  // SSL port
//       secure: true,  // Use SSL (true for port 465)
//       auth: {
//         user: 'no-reply@weighingworld.com',  // Email address (username)
//         pass: '$]IIWt4blS^_'  // Email password or app password
//       }
//     });

//     const mailOptions = {
//       from: 'no-reply@weighingworld.com',  // Sender address
//       to: email,  // Receiver address (change this to your recipient email)
//       subject: 'Test Email',  // Subject line
//       text: `Your OTP is: ${otp}`,  // Plain text body
//       //html: '<p>This is a <strong>test email</strong> sent from Node.js!</p>'
//     };

//     // Send OTP email
//     transporter.sendMail(mailOptions, async (error, info) => {
//       if (error) {
//         console.error('Error sending OTP email:', error);
//         return res.status(500).json({ status: 0, message: 'Error sending OTP email' });
//       }
//       console.log('OTP email sent: ' + info.response);

//       // After OTP is sent, create JWT token and send response
//       const token = jwt.sign(
//         { userId: user.userId, role: user.role },
//         process.env.JWT_SECRET,
//         { expiresIn: '15d' } // Token will expire in 15 days
//       );

//       // Fetch family details if familyId exists
//       //  let familyName;
//       //    if (user.familyId) {
//       //      // Use findOne to fetch family by familyId as string
//       //      Family.findOne({ familyId: user.familyId }).then(family => {
//       //        familyName = family ? family.familyName : null;
//       //        console.log(familyName);
//       //      })
//       //    }

//       let familyName = null;
//       if (user.familyId) {
//         try {
//           const family = await Family.findOne({ familyId: user.familyId });
//           familyName = family ? family.familyName : null; // Fetch the familyName
//         }catch(err) {
//           console.error('Error fetching family details:', err);
//         }
//       }

//       // Send response with token
//       res.status(200).json({
//         status: 1,
//         message: 'Login successful',
//         otpstatus: 'OTP sent successfully',
//         otp: otp, // In real cases, do not return OTP in response
//         token: token,
//         userId: user.userId,
//         role: user.role,
//         name: user.name,
//         familyId:user.familyId || null ,
//         familyName:familyName || null,
//       });
//     });
//   } catch (err) {
//     console.error('Error logging in user:', err);
//     res.status(500).json({ status: 0, message: 'Server error' });
//   }
// });

// app.post('/login', async (req, res) => {
//   const { email, name, password } = req.body;

//   // Check if email or name is provided along with the password
//   if (!password) {
//     return res.status(400).json({ status: 0, message: 'Please provide password' });
//   }

//   try {
//     let user;

//     // If email is provided, search for user by email
//     if (email) {
//       user = await User.findOne({ email });
//     } else if (name) {
//       // If no email, check if it's a child and search by name
//       user = await User.findOne({ name });

//       // Ensure user is found and the role is 'child' if name is provided
//       if (!user || user.role !== 'child') {
//         return res.status(401).json({ status: 0, message: 'User not found or not a child user' });
//       }
//     } else {
//       return res.status(400).json({ status: 0, message: 'Please provide either email or name' });
//     }

//     if (!user) {
//       return res.status(401).json({ status: 0, message: 'User not found' });
//     }

//     // Compare the provided password with the stored password
//     const isMatch = await bcrypt.compare(password, user.password);
//     console.log(user.password);
//     console.log('Password match result:', isMatch);
//     console.log("Password entered: ", password);

//     if (!isMatch) {
//       return res.status(401).json({
//         status: 0,
//         message: 'Invalid email/name or password',
//       });
//     }

//     // Generate a 4-digit OTP (after successful password verification)
//     const otp = Math.floor(1000 + Math.random() * 9000); // Generate a 4-digit number

//     // Set up SMTP transporter using provided credentials
//     const transporter = nodemailer.createTransport({
//       host: 'mail.weighingworld.com', // SMTP server
//       port: 465, // SSL port
//       secure: true, // Use SSL (true for port 465)
//       auth: {
//         user: 'no-reply@weighingworld.com', // Email address (username)
//         pass: '$]IIWt4blS^_', // Email password or app password
//       },
//     });

//     const mailOptions = {
//       from: 'no-reply@weighingworld.com', // Sender address
//       to: user.email, // Receiver address (only if email exists)
//       subject: 'Test Email', // Subject line
//       text: `Your OTP is: ${otp}`, // Plain text body
//     };

//     // Send OTP email if email is provided
//     if (user.email) {
//       transporter.sendMail(mailOptions, async (error, info) => {
//         if (error) {
//           console.error('Error sending OTP email:', error);
//           return res.status(500).json({ status: 0, message: 'Error sending OTP email' });
//         }
//         console.log('OTP email sent: ' + info.response);

//         // After OTP is sent, create JWT token and send response
//         const token = jwt.sign(
//           { userId: user.userId, role: user.role },
//           process.env.JWT_SECRET,
//           { expiresIn: '15d' } // Token will expire in 15 days
//         );

//         // Send response with token
//         return res.status(200).json({
//           status: 1,
//           message: 'Login successful',
//           otpstatus: 'OTP sent successfully',
//           otp: otp, // In real cases, do not return OTP in response
//           token: token,
//           userId: user.userId,
//           role: user.role,
//           name: user.name,
//           familyId: user.familyId || null,
//           familyName: user.familyId ? await Family.findOne({ familyId: user.familyId }).familyName : null,
//         });
//       });
//     } else {
//       // If no email is provided for the child, skip sending OTP and directly issue the token
//       const token = jwt.sign(
//         { userId: user.userId, role: user.role },
//         process.env.JWT_SECRET,
//         { expiresIn: '15d' } // Token will expire in 15 days
//       );

//       // Send response with token for child (no OTP sent)
//       return res.status(200).json({
//         status: 1,
//         message: 'Login successful',
//         token: token,
//         userId: user.userId,
//         role: user.role,
//         name: user.name,
//         familyId: user.familyId || null,
//         familyName: user.familyId ? await Family.findOne({ familyId: user.familyId }).familyName : null,
//       });
//     }
//   } catch (err) {
//     console.error('Error logging in user:', err);
//     res.status(500).json({ status: 0, message: 'Server error'+err});
//   }
// });

// app.post("/login", async (req, res) => {
//   const { email, name, password } = req.body;

//   // Check if password is provided
//   if (!password) {
//     return res
//       .status(400)
//       .json({ status: 0, message: "Please provide password" });
//   }

//   try {
//     let user;

//     // Check if the user is a 'child' first
//     if (name) {
//       // If it's a child user, search for the user by name
//       user = await User.findOne({ name });

//       // Ensure the user exists and is a child
//       if (user && user.role === "child") {
//         // Compare the provided password with the stored password
//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) {
//           return res
//             .status(401)
//             .json({ status: 0, message: "Invalid name or password" });
//         }

//         // Generate JWT token for child user (no OTP)
//         const token = jwt.sign(
//           { userId: user.userId, role: user.role },
//           process.env.JWT_SECRET,
//           { expiresIn: "15d" }
//         );

//         return res.status(200).json({
//           status: 1,
//           message: "Login successful",
//           token: token,
//           userId: user.userId,
//           role: user.role,
//           name: user.name,
//           familyId: user.familyId || null,
//           familyName: user.familyId
//             ? await Family.findOne({ familyId: user.familyId }).familyName
//             : null,
//         });
//       }
//     }

//     // If the user is not a 'child', check for parent login (by email or name)
//     if (!user || user.role !== "child") {
//       // If parent is trying to log in, we check by email or name
//       if (email) {
//         user = await User.findOne({ email });
//       } else if (name) {
//         user = await User.findOne({ name });
//       }

//       // Ensure user exists for parent
//       if (!user) {
//         return res.status(401).json({ status: 0, message: "User not found" });
//       }

//       // Compare the provided password with the stored password
//       const isMatch = await bcrypt.compare(password, user.password);
//       if (!isMatch) {
//         return res
//           .status(401)
//           .json({ status: 0, message: "Invalid name/email or password" });
//       }

//       // If email exists for the parent, send OTP email
//       if (user.email) {
//         const otp = Math.floor(1000 + Math.random() * 9000); // Generate 4-digit OTP

//         // Set up SMTP transporter
//         const transporter = nodemailer.createTransport({
//           host: "mail.weighingworld.com",
//           port: 465,
//           secure: true,
//           auth: {
//             user: "no-reply@weighingworld.com",
//             pass: "$]IIWt4blS^_",
//           },
//         });

//         const mailOptions = {
//           from: "no-reply@weighingworld.com",
//           to: user.email,
//           subject: "Test Email",
//           text: `Your OTP is: ${otp}`,
//         };

//         transporter.sendMail(mailOptions, async (error, info) => {
//           if (error) {
//             console.error("Error sending OTP email:", error);
//             return res
//               .status(500)
//               .json({ status: 0, message: "Error sending OTP email" });
//           }

//           console.log("OTP email sent: " + info.response);

//           // After OTP is sent, create JWT token
//           const token = jwt.sign(
//             { userId: user.userId, role: user.role },
//             process.env.JWT_SECRET,
//             { expiresIn: "15d" }
//           );

//           // Send response with token
//           return res.status(200).json({
//             status: 1,
//             message: "Login successful",
//             otpstatus: "OTP sent successfully",
//             otp: otp, // In real cases, do not return OTP in response
//             token: token,
//             userId: user.userId,
//             role: user.role,
//             name: user.name,
//             familyId: user.familyId || null,
//             familyName: user.familyId
//               ? await Family.findOne({ familyId: user.familyId }).familyName
//               : null,
//           });
//         });
//       } else {
//         // If no email exists, return token without OTP (for parents who don't need OTP)
//         const token = jwt.sign(
//           { userId: user.userId, role: user.role },
//           process.env.JWT_SECRET,
//           { expiresIn: "15d" }
//         );

//         return res.status(200).json({
//           status: 1,
//           message: "Login successful",
//           token: token,
//           userId: user.userId,
//           role: user.role,
//           name: user.name,
//           familyId: user.familyId || null,
//           familyName: user.familyId
//             ? await Family.findOne({ familyId: user.familyId }).familyName
//             : null,
//         });
//       }
//     }
//   } catch (err) {
//     console.error("Error logging in user:", err);
//     res.status(500).json({ status: 0, message: "Server error" + err });
//   }
// });

app.post("/login", async (req, res) => {
  const { email, username, password,name } = req.body;

  // Check if password is provided
  if (!password) {
    return res
      .status(400)
      .json({ status: 0, message: "Please provide password" });
  }

  try {
    let user;

    // Check if the user is a 'child' first
    if (username) {
      // If it's a child user, search for the user by name
      user = await User.findOne({ username });
      //console.log(user.hobby1);

      // Ensure the user exists and is a child
      if (user && user.role === "child") {
        // Compare the provided password with the stored password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res
            .status(401)
            .json({ status: 0, message: "Invalid name or password" });
        }

        // Generate JWT token for child user (no OTP)
        const token = jwt.sign(
          { userId: user.userId, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: "15d" }
        );

        const family = user.familyId ? await Family.findOne({ familyId: user.familyId }) : null;
        const familyName = family ? family.familyName : null;

        return res.status(200).json({
          status: 1,
          message: "Login successful",
          token: token,
          userId: user.userId,
          familyName,
          name: user.name,
          role:user.role,
          firstName:user.firstName,
          lastName: user.lastName,
          school: user.school,
          hobby1: user.hobby1,
          hobby2: user.hobby2,
          hobby3: user.hobby3,
          //address1: user.address1,
          //address2: user.address2,
          //address3: user.address3,
          //city: user.city,
          //state: user.state,
          //pinCode: user.pinCode,
          //phoneNumber: user.phoneNumber,
          //role: user.role,
          name: user.name,
          familyId: user.familyId || null,
          // familyName: user.familyId
          //   ? await Family.findOne({ familyId: user.familyId }).familyName
          //   : null,
        });
      }
    }

    // If the user is not a 'child', check for parent login (by email or name)
    if (!user || user.role !== "child") {
      // If parent is trying to log in, we check by email or name
      if (email) {
        user = await User.findOne({ email });
      } else if (name) {
        user = await User.findOne({ name });
      }

      // Ensure user exists for parent
      if (!user) {
        return res.status(400).json({ status: 0, message: "User not found" });
      }

      // Compare the provided password with the stored password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(401)
          .json({ status: 0, message: "Invalid name/email or password" });
      }

     
      // Fetch children's names if the user is a parent
      // Fetch children's names if the user is a parent
      // let kidsNames = [];
      // if (user.role === "parent") {
      //   // Find all children where the parentId matches the logged-in parent's userId
      //   const children = await User.find({ parentId: user.userId });
      //   kidsNames = children.map(child => child.name);
      // }

      // Generate JWT token for parent user (no OTP)
      const token = jwt.sign(
        { userId: user.userId, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "15d" }
      );
      console.log("Logged in user:", user.name, user.userId, user.role);

      //console.log("Login is working.")

      const family = user.familyId ? await Family.findOne({ familyId: user.familyId }) : null;
      const familyName = family ? family.familyName : null;


      return res.status(200).json({
        status: 1,
        message: "Login successful",
        token: token,
        userId: user.userId,
        role: user.role,
        name: user.name,
        firstName:user.firstName,
        lastName:user.lastName,
        familyId: user.familyId || null,
        // familyName: user.familyId
        //   ? await Family.findOne({ familyId: user.familyId }).familyName
        //   : null,
        familyName:familyName,
        email: user.email,
        dob: user.dob,
        phoneNumber: user.phoneNumber,
        gender: user.gender,
        address1: user.address1,
        address2: user.address2,
        address3: user.address3,
        city: user.city,
        state: user.state,
        pinCode: user.pinCode,
        numberOfKids: user.numberOfKids,
        password: user.password,
        kidsNames: user.kidsNames,
      });
      console.log(name);
    }
    
  } catch (err) {
    console.error("Error logging in user:", err);
    res
      .status(500)
      .json({ status: 0, message: "Server error: " + err.message });
  }
});

app.post("/create-families", verifyToken, async (req, res) => {
  const { familyId, familyName, region, currency, budgetlimit } = req.body;
  const userId = req.user.userId;
  //const normalizedRole = role ? role.toLowerCase() : '';
  console.log(userId);
  const user = await User.findOne({ userId: userId });
  console.log(user.familyId);

  // Validate required fields
  if (!familyName) {
    return res.status(400).json({
      status: 0,
      message: "Family Name is required",
    });
  }

  // Ensure only parents can create a family
  // if (req.user.role!== "parent") {
  //   return res.status(401).json({
  //     status: 0,
  //     message: 'Only parents can create a family',
  //   });
  // }

  try {
    // First, check if the parent already has a family
    const user = await User.findOne({ userId: userId });
    console.log(user.familyId[0]);
    if (user.familyId && user.familyId.length > 1) {
      return res.status(400).json({
        status: 0,
        message: "You already have a family!!", // Prevent parent from creating multiple families
      });
    }

    // Also, check if any children associated with the parent already have a family
    const children = await User.find({ parentId: user.userId, role: "child" });
    for (let child of children) {
      if (child.familyId && child.familyId.length > 1) {
        return res.status(400).json({
          status: 0,
          message: `One of your children (User ID: ${child.userId}) already has a family!`,
        });
      }
    }

    // Now, create the new family as no one is currently in a family
    const newFamily = new Family({
      familyName,
      region,
      currency,
      budgetlimit: budgetlimit || 0,
      parentId: req.user.userId,
    });
    // user.familyId.push(newFamily.familyId[0]);
    // Save the new family to the database
    // await newFamily.save();

    // Add the new familyId to the parent user
    user.familyId.push(newFamily.familyId);
    await user.save();

    // Assign the new familyId to each child of the parent
    for (let child of children) {
      child.familyId.push(newFamily.familyId);
      await child.save();
    }

    // Respond with the created family data
    res.status(200).json({
      status: 1,
      message: "Family created successfully",
      family: newFamily,
    });
  } catch (err) {
    console.error("Error creating family:", err);
    res.status(500).json({ status: 0, message: "Internal server error" });
  }
});

// API to create family by parent
// app.post("/create-families", async (req, res) => {
//   const { familyName, region, currency, budgetlimit } = req.body;
//   const parentId = req.user.userId; // Parent's userId from the JWT token
//   const parent = await User.findOne({ userId: parentId });

//   // if (parent.role !== 'parent') {
//   //   return res.status(400).json({ status: 0, message: 'Only a parent can create a family' });
//   // }

//   if (!parent.familyId || parent.familyId.length === 0) {
//     return res.status(400).json({
//       status: 0,
//       message: "Parent must have a familyId to create a family",
//     });
//   }

//   try {
//     // Create the family document with the parent's familyId
//     const newFamily = new Family({
//       familyId: parent.familyId[0], // Use the parent's familyId
//       familyName,
//       region,
//       currency: currency || "INR",
//       budgetlimit: budgetlimit || 0,
//       parentId: parentId, // Link the parentId to the family
//     });

//     // Save the family to the database
//     await newFamily.save();

//     // Add the familyId to the parent and children
//     // parent.familyId.push(newFamily.familyId);
//     // await parent.save();

//     // Now update the children and guardians with the familyId
//     // const children = await User.find({ parentId: parent.userId });
//     // for (let child of children) {
//     //   child.familyId.push(newFamily.familyId);
//     //   await child.save();
//     // }

//     // const guardians = await User.find({ guardianId: parent.userId });
//     // for (let guardian of guardians) {
//     //   guardian.familyId.push(newFamily.familyId);
//     //   await guardian.save();
//     // }

//     // Respond with the created family data
//     res.status(200).json({
//       status: 1,
//       message: "Family created successfully",
//       family: newFamily,
//     });
//   } catch (err) {
//     console.error("Error creating family:", err);
//     res.status(500).json({ status: 0, message: "Internal server error" });
//   }
// });

app.post("/create-family", verifyToken, async (req, res) => {
  const { familyName, region, currency, budgetlimit } = req.body;
  const userId = req.user.userId;

  console.log(userId);

  try {
    // Find the parent user
    const user = await User.findOne({ userId: userId });
    if (!user) {
      return res.status(404).json({
        status: 0,
        message: "User not found",
      });
    }

    // Log the parent's current familyId
    console.log(user.familyId);
    const parentFamilyId = user.familyId[0];

    // Validate required fields
    if (!familyName) {
      return res.status(400).json({
        status: 0,
        message: "Family Name is required",
      });
    }

    // Ensure the parent user doesn't already have a family
    // if (user.familyId && user.familyId.length > 0) {
    //   return res.status(400).json({
    //     status: 0,
    //     message: "You already have a family!",
    //   });
    // }

    // Find children associated with the parent (using parentId field)
    const children = await User.find({ parentId: userId, role: "child" });
    for (let child of children) {
      if (child.familyId && child.familyId.length > 1) {
        return res.status(400).json({
          status: 0,
          message: `One of your children (User ID: ${child.userId}) already has a family!`,
        });
      }
    }

    // Now, create the new family
    const newFamily = new Family({
      familyId: [user.familyId[0]], // If parent has a familyId, use it; otherwise, create a new one.
      familyName,
      region,
      currency,
      budgetlimit: budgetlimit || 0,
      parentId: userId,
      children: [],
      guardianId: [],
    });

    // Save the new family to the database
    await newFamily.save();
    // Assign the new familyId to each child, set the guardianId and add the child to the family's children array
    for (let child of children) {
      // Add the child's userId to the family's children array
      newFamily.children.push(child.userId);
    }

    const guardians = await User.find({ role: "guardian" });
    console.log(guardians);

    // Filter guardians based on familyId matching the parent's familyId
    const validGuardians = guardians.filter((guardian) =>
      guardian.familyId.includes(parentFamilyId)
    );
    console.log(validGuardians);

    // Add the valid guardians' userId to the family’s guardianId array
    for (let guardian of validGuardians) {
      newFamily.guardianId.push(guardian.userId); // Add guardian's userId to the family
    }

    // Assign the new familyId to each child of the parent
    //for (let child of children) {
    //child.familyId.push(newFamily.familyId[0]); // Assign the familyId to each child
    //await child.save();
    //}
    await newFamily.save();
    // Respond with the created family data
    res.status(200).json({
      status: 1,
      message: "Family created successfully",
      family: newFamily,
    });
  } catch (err) {
    console.error("Error creating family:", err);
    res.status(500).json({ status: 0, message: "Internal server error" });
  }
});

// logic is create family, then create guardian, inside guardian - family [family Id1, familyId2], inside child user- family [familyId] and guardian[guardian2,guardian2]
app.post("/create-guardian", verifyParentRole, async (req, res) => {
  const { name, gender, email, password, role, dob,firstName,lastName,phoneNumber } = req.body;
  const normalizedRole = role ? role.toLowerCase() : "";
  const normalizedgender = gender ? gender.toLowerCase() : "";
  const parentId = req.user.userId;
  const userRole = req.user.role;
  //const user = await User.findOne({ userId:parentId });
  const parent = await User.findOne({ userId: parentId });
  console.log(parent);

  console.log(parentId);
  console.log(userRole);
  //console.log(parentFamily);

  if (userRole !== "parent") {
    return res
      .status(400)
      .json({ status: 0, message: "Only a parent user can create guardians" });
  }
  // Only allow 'child' or 'guardian' roles
  if (normalizedRole !== "guardian") {
    return res
      .status(400)
      .json({ status: 0, message: 'Role must be "guardian"' });
  }

  // Validate required fields
  if ( !email || !password || !dob || !firstName || !lastName ||!gender ||!phoneNumber) {
    return res
      .status(400)
      .json({ status: 0, message: "Please provide all required fields" });
  }

  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({ $or: [{ email }, { name }] });
    if (existingUser) {
      return res
        .status(200)
        .json({ status: 0, message: "Email or Name already exists" });

    }

    const parsedDob = moment(dob, 'DD-MM-YYYY').format('YYYY-MM-DD');
    
    // If parsing fails, it will return an invalid date
    // if (!moment(parsedDob, 'YYYY-MM-DD', true).isValid()) {
    //   return res.status(400).json({ status: 0, message: "Invalid date format. Please use dd-mm-yyyy." });
    // }

    //const parsedDob = parse(dob, 'dd-MM-yyyy', new Date()); // parse dd-mm-yyyy to Date object
    // formattedDob = format(parsedDob, 'yyyy-MM-dd'); 

    const userUuid = uuidv4(); // This generates a unique UUID for the user
    const familyId = userUuid.slice(-4); // Extract the last 4 characters for the family ID

    // Create the new user
    const newUser = new User({
      name,
      gender: normalizedgender,
      email,
      password,
      role: normalizedRole,
      dob:parsedDob,
      firstName,
      lastName,
      familyId: [familyId],
      //guardianId: parent.familyId,
      parentId: parentId,
      phoneNumber
    });

    // Save the new user to the database
    await newUser.save();

    const family = new Family({
      familyName: `${newUser.name}'s Family`, // Family name based on the parent's name
      parentId: [newUser.userId], // Add the parent user ID
      familyId: [familyId], // Generate a unique family ID (if necessary)
    });
    await family.save();
    console.log("User created successfully!",newUser);
    const userResponse = await User.findById(newUser._id).select("-parentId");
    res.status(200).json({
      status: 1,
      message: "User created successfully",
      user: userResponse,
    });
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});

// Create a route to handle the creation of the guardian user
app.post("/create-guardian-form", async (req, res) => {
  const {  email, password, gender, dob, parentId,firstName,lastName,phoneNumber } = req.body;
  console.log(req.body);

  // Validate required fields
  if (!firstName ||!lastName || !email || !password || !dob || !parentId) {
    return res.status(400).json({
      status: 0,
      message: "Please provide all required fields",
    });
  }

  // Normalize the gender field (optional)
  const normalizedGender = gender ? gender.toLowerCase() : "";

  try {
    // Check if the email already exists in the system
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 0,
        message: "Email already exists",
      });
    }

    // Hash the password before storing it
    //const hashedPassword = await bcrypt.hash(password, 10); // Use 10 rounds for bcrypt hashing

    // Create a new user with the guardian role
    const newUser = new User({
      firstName,
      lastName,
      email,
      password,
      role: "guardian", // Set the role to 'guardian'
      gender: normalizedGender,
      dob,
      parentId, // Parent ID from request body
      phoneNumber
    });

    // Save the new user to the database
    await newUser.save();

    const family = await Family.findOne({
      parentId: parentId,
      familyId: { $exists: true, $not: { $size: 0 } },
    });
    if (family) {
      // Push the new user's userId into the parentId array
      family.guardianIds.push(newUser.userId);
      await family.save(); // Save the updated family document
    } else {
      return res.status(404).json({
        status: 0,
        message: "Family not found",
      });
    }

    // Return success response
    res.status(200).json({
      status: 1,
      message: "Guardian account created successfully!",
      user: {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        dob: newUser.dob,
        gender: newUser.gender,
      },
    });
  } catch (err) {
    console.error("Error creating guardian:", err);
    res.status(500).json({
      status: 0,
      message: "Server error",
      error: err.message,
    });
  }
});

// app.post("/invite-guardian", async (req, res) => {
//   const { guardianEmail, guardianName, parentId } = req.body;

//   // Validate required fields
//   if (!guardianEmail || !guardianName) {
//     return res.status(400).json({
//       status: 0,
//       message: "Please provide guardian name and email",
//     });
//   }

//   try {
//     // Find the family by familyId
//     const family = await Family.findOne({
//       parentId: parentId,
//       // familyId should exist in the array familyId
//       "familyId": { $exists: true, $not: { $size: 0 } },
//     });

//     // Check if the family exists
//     if (!family) {
//       return res.status(404).json({
//         status: 0,
//         message: "Family not found",
//       });
//     }

//     // Check if the guardian email is already in the guardianIds array
//     // const existingGuardian = family.guardianIds.find(guardianId => guardianId === guardianEmail);
//     // if (existingGuardian) {
//     //   return res.status(400).json({
//     //     status: 0,
//     //     message: "You are already a guardian of this family",
//     //   });
//     //}
//     // Check if the guardian email already exists in the User model
//     const existingUser = await User.findOne({ email: guardianEmail });
//     const existingGuardianId = existingUser.userId;
//     const isGuardianInFamily = family.guardianIds.includes(existingGuardianId);

//     if (isGuardianInFamily) {
//       return res.status(400).json({
//         status: 0,
//         message: "You are already a guardian of this family",
//       });
//     }

//     // Create a JWT token with the guardian's email and role
//     const token = jwt.sign({ email: guardianEmail }, process.env.JWT_SECRET, {
//       expiresIn: "24h",
//     });

//     // If the user exists
//     if (existingUser) {

//       // Generate a verification link for the existing user
//       const verificationLink = `http://93.127.172.167:5001/verify?token=${token}&email=${guardianEmail}`;

//       // Send verification email
//       const transporter = nodemailer.createTransport({
//         host: "mail.weighingworld.com",
//         port: 465,
//         secure: true,
//         auth: {
//           user: "no-reply@weighingworld.com",
//           pass: "$]IIWt4blS^_",
//         },
//       });

//       const mailOptions = {
//         from: "no-reply@weighingworld.com",
//         to: guardianEmail,
//         subject: "Guardian Invitation - Email Verification",
//         text: `Hello ${guardianName},\n\nPlease verify your email by clicking on the following link: ${verificationLink}`,
//       };

//       // Send the verification email
//       transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//           return res.status(500).json({
//             status: 0,
//             message: "Error sending verification email",
//           });
//         }

//         // Respond with success message if email is sent
//         res.status(200).json({
//           status: 1,
//           message: "Verification email sent successfully. Please check your email to verify your account.",
//         });
//       });
//     } else {
//       // If user does not exist, generate a registration link
//       const registrationLink = `http://93.127.172.167:5001/register-form?token=${token}&email=${guardianEmail}`;

//       // Send registration email with link to registration form
//       const transporter = nodemailer.createTransport({
//         host: "mail.weighingworld.com",
//         port: 465,
//         secure: true,
//         auth: {
//           user: "no-reply@weighingworld.com",
//           pass: "$]IIWt4blS^_",
//         },
//       });

//       const mailOptions = {
//         from: "no-reply@weighingworld.com",
//         to: guardianEmail,
//         subject: "Guardian Invitation - Registration",
//         text: `Hello ${guardianName},\n\nIt seems like you are not registered. Please complete your registration by clicking on the following link: ${registrationLink}`,
//       };

//       // Send the registration email
//       transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//           return res.status(500).json({
//             status: 0,
//             message: "Error sending registration email",
//           });
//         }

//         // Respond with success message if email is sent
//         res.status(200).json({
//           status: 1,
//           message: "Registration email sent successfully. Please complete your registration.",
//         });
//       });
//     }
//   } catch (err) {
//     console.error("Error sending email:", err);
//     res.status(500).json({ status: 0, message: "Server error", err });
//   }
// });

app.post("/invite-guardian", async (req, res) => {
  const { guardianEmail, guardianfirstName,guardianlastName, parentId } = req.body;

  // Validate required fields
  if (!guardianEmail || !guardianfirstName ||!guardianlastName) {
    return res.status(400).json({
      status: 0,
      message: "Please provide guardian name and email",
    });
  }

  try {
    // Find the family by parentId
    const family = await Family.findOne({
      parentId: parentId,
      familyId: { $exists: true, $not: { $size: 0 } },
    });
    console.log(family);

    // Check if the family exists
    if (!family) {
      return res.status(404).json({
        status: 0,
        message: "Family not found",
      });
    }

    // Check if the guardian email is already associated with this family
    const existingUser = await User.findOne({ email: guardianEmail });

    if (existingUser) {
      const existingGuardianId = existingUser.userId;
      const isGuardianInFamily =
        family.guardianIds.includes(existingGuardianId);

      if (isGuardianInFamily) {
        return res.status(400).json({
          status: 0,
          message: `${guardianfirstName} is already a guardian of this family.`, //"You are already a guardian of this family",
        });
      }

      // If the user exists, create a JWT token with the guardian's email
      const token = jwt.sign({ email: guardianEmail }, process.env.JWT_SECRET, {
        expiresIn: "24h",
      });

      // Send the verification email to the guardian
      const verificationLink = `http://93.127.172.167:5001/verify?token=${token}&email=${guardianEmail}&parentId=${parentId}`;

      const transporter = nodemailer.createTransport({
        host: "mail.weighingworld.com",
        port: 465,
        secure: true,
        auth: {
          user: "no-reply@weighingworld.com",
          pass: "$]IIWt4blS^_",
        },
      });

      const mailOptions = {
        from: "no-reply@weighingworld.com",
        to: guardianEmail,
        subject: "Guardian Invitation - Email Verification",
        text: `Hello ${guardianfirstName},\n\nPlease verify your email by clicking on the following link: ${verificationLink}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return res.status(500).json({
            status: 0,
            message: "Error sending verification email",
          });
        }

        // Respond with success message if email is sent
        res.status(200).json({
          status: 1,
          message:
            "Verification email sent successfully. Please check your email to verify your account.",
        });
      });
    } else {
      // If the user does not exist, create a JWT token for registration
      const token = jwt.sign({ email: guardianEmail }, process.env.JWT_SECRET, {
        expiresIn: "24h",
      });

      const registrationLink = `http://93.127.172.167:5001/register-form?token=${token}&email=${guardianEmail}&parentId=${parentId}`;

      // Send the registration email with the registration link
      const transporter = nodemailer.createTransport({
        host: "mail.weighingworld.com",
        port: 465,
        secure: true,
        auth: {
          user: "no-reply@weighingworld.com",
          pass: "$]IIWt4blS^_",
        },
      });

      const mailOptions = {
        from: "no-reply@weighingworld.com",
        to: guardianEmail,
        subject: "Guardian Invitation - Registration",
        text: `Hello ${guardianfirstName},\n\nIt seems like you are not registered. Please complete your registration by clicking on the following link: ${registrationLink}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return res.status(500).json({
            status: 0,
            message: "Error sending registration email",
          });
        }

        // Respond with success message if email is sent
        res.status(200).json({
          status: 1,
          message:
            "Registration email sent successfully. Please complete your registration.",
        });
      });
    }
  } catch (err) {
    console.error("Error sending email:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});

app.post("/invite-second-parent", async (req, res) => {
  const { secondParentEmail, secondParentfirstName, secondParentlastName, firstParentId } = req.body;
  console.log(req.body);

  // Validate required fields
  if (!secondParentEmail || !secondParentfirstName ||!secondParentlastName || !firstParentId) {
    return res.status(400).json({
      status: 0,
      message: "Please provide second parent name, email, and first parent ID",
    });
  }

  try {
    // Find the family by firstParentId
    const family = await Family.findOne({
      parentId: firstParentId,
      familyId: { $exists: true, $not: { $size: 0 } },
    });

    // Check if the family exists
    if (!family) {
      return res.status(404).json({
        status: 0,
        message: "Family not found",
      });
    }

    // Check if the family already has two parents
    if (family.parentId && family.parentId.length >= 2) {
      return res.status(400).json({
        status: 0,
        message: "This family already has a second parent",
      });
    }

    // Check if the second parent email is already associated with this family
    const existingUser = await User.findOne({ email: secondParentEmail });

    if (existingUser) {
      const existingParentId = existingUser.userId;
      const isSecondParentInFamily = family.parentId.includes(existingParentId);

      if (isSecondParentInFamily) {
        return res.status(400).json({
          status: 0,
          message: `${secondParentfirstName} is already a second parent of this family.`,
        });
      }

      // If the user exists, create a JWT token with the second parent's email
      const token = jwt.sign(
        { email: secondParentEmail },
        process.env.JWT_SECRET,
        {
          expiresIn: "24h",
        }
      );

      // Send the verification email to the second parent
      const verificationLink = `http://93.127.172.167:5001/verify-parent?token=${token}&email=${secondParentEmail}&firstParentId=${firstParentId}`;

      const transporter = nodemailer.createTransport({
        host: "mail.weighingworld.com",
        port: 465,
        secure: true,
        auth: {
          user: "no-reply@weighingworld.com",
          pass: "$]IIWt4blS^_",
        },
      });

      const mailOptions = {
        from: "no-reply@weighingworld.com",
        to: secondParentEmail,
        subject: "Second Parent Invitation - Email Verification",
        text: `Hello ${secondParentfirstName},\n\nPlease verify your email by clicking on the following link: ${verificationLink}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Error sending verification email:", error);
          return res.status(500).json({
            status: 0,
            message: "Error sending verification email",
          });
        }
        console.log('Email sent:', error); 


        // Respond with success message if email is sent
        res.status(200).json({
          status: 1,
          message:
            "Verification email sent successfully. Please check your email to verify your account.",
        });
      });
    } else {
      // If the user does not exist, create a JWT token for registration
      const token = jwt.sign(
        { email: secondParentEmail },
        process.env.JWT_SECRET,
        {
          expiresIn: "24h",
        }
      );

      const registrationLink = `http://93.127.172.167:5001/register-form-parent?token=${token}&email=${secondParentEmail}&firstParentId=${firstParentId}`;

      // Send the registration email with the registration link
      const transporter = nodemailer.createTransport({
        host: "mail.weighingworld.com",
        port: 465,
        secure: true,
        auth: {
          user: "no-reply@weighingworld.com",
          pass: "$]IIWt4blS^_",
        },
      });

      const mailOptions = {
        from: "no-reply@weighingworld.com",
        to: secondParentEmail,
        subject: "Second Parent Invitation - Registration",
        text: `Hello ${secondParentfirstName},\n\nIt seems like you are not registered. Please complete your registration by clicking on the following link: ${registrationLink}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return res.status(500).json({
            status: 0,
            message: "Error sending registration email",
          });
        }
        console.log('Verification email sent:', info); 

        // Respond with success message if email is sent
        res.status(200).json({
          status: 1,
          message:
            "Registration email sent successfully. Please complete your registration.",
        });
      });
    }
  } catch (err) {
    console.error("Error sending email:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});

app.post("/verify-second-parent", async (req, res) => {
  const { email, token, firstParentId } = req.body;

  if (!email || !token || !firstParentId) {
    return res.status(400).json({
      status: 0,
      message: "Email, token, and first parent ID are required",
    });
  }

  try {
    // Step 1: Verify the token (Normally, you would use JWT verify here to decode and validate the token)
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userEmail = decodedToken.email;

    // Step 2: Find the second parent using the provided email
    const secondParent = await User.findOne({ email: userEmail }); //role: "parent"
    if (!secondParent) {
      return res.status(404).json({
        status: 0,
        message: "Second parent not found",
      });
    }

    // Step 3: Find the family linked to the first parent
    const family = await Family.findOne({
      parentId: firstParentId,
      familyId: { $exists: true, $not: { $size: 0 } },
    });

    if (!family) {
      return res.status(404).json({
        status: 0,
        message: "Family not found",
      });
    }

    // Step 4: Check if the family already has two parents
    if (family.parentId && family.parentId.length >= 2) {
      return res.status(400).json({
        status: 0,
        message: "This family already has a second parent",
      });
    }

    // Step 5: Add the second parent to the family's parentIds array
    if (!family.parentId) {
      family.parentId = [];
    }

    family.parentId.push(secondParent.userId);
    await family.save(); // Save the updated family document

    //secondParent.familyId = secondParent.familyId || []; // Initialize if undefined
    //secondParent.familyId.push(family.familyId); // Add the familyId from the family document
    //await secondParent.save(); // Save the second parent document

    // Step 6: Find all children linked to the first parent
    const children = await User.find({
      parentId: firstParentId,
      role: "child",
    });

    // Step 7: Update each child with the new second parent in their parentIds array
    for (let child of children) {
      if (!child.parentId.includes(secondParent.userId)) {
        child.parentId.push(secondParent.userId);
        console.log("Saving child:", child.userId);
        await child.save(); // Save the updated child document
      }
    }

    // Step 8: Respond with success
    res.status(200).json({
      status: 1,
      message:
        "Second parent has been successfully added to the family, and children have been updated.",
    });
  } catch (err) {
    console.error("Error adding second parent:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});

app.post("/create-parent-form", async (req, res) => {
  const { firstName,lastName,phone,address1,city,state,pincode, email,country, password, gender, dob, firstParentId } = req.body;
  console.log(req.body);

  // Validate required fields
  if (!firstName || !email || !password || !dob) {
    return res.status(400).json({
      status: 0,
      message: "Please provide all required fields",
    });
  }

  // Normalize the gender field (optional)
  const normalizedGender = gender ? gender.toLowerCase() : "";

  try {
    // Check if the email already exists in the system
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: 0,
        message: "Email already exists",
      });
    }
    console.log("First Parent ID:", firstParentId);

    const firstParent = await User.findOne({ userId: firstParentId });
    console.log(firstParent);
    if (!firstParent) {
      return res.status(404).json({
        status: 0,
        message: "First parent not found",
      });
    }

    // Hash the password before storing it
    //const hashedPassword = await bcrypt.hash(password, 10); // Use 10 rounds for bcrypt hashing
    const familyId = firstParent.familyId[0];
    //console.log(family);

    // Create a new user with the guardian role
    const newUser = new User({
      firstName,
      lastName,
      country,
      phone,
      address1,
      city,
      state,
      pincode,
      email,
      password,
      role: "parent", // Set the role to 'guardian'
      gender: normalizedGender,
      dob,
      familyId: [familyId], // Parent ID from request body
    });

    // Save the new user to the database
    await newUser.save();
    const family = await Family.findOne({
      parentId: firstParentId,
      familyId: { $exists: true, $not: { $size: 0 } },
    });
    if (family) {
      // Push the new user's userId into the parentId array
      family.parentId.push(newUser.userId);
      await family.save(); // Save the updated family document
    } else {
      return res.status(404).json({
        status: 0,
        message: "Family not found",
      });
    }

    // Return success response
    res.status(200).json({
      status: 1,
      message: "Parent account created successfully!",
      user: {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        dob: newUser.dob,
        gender: newUser.gender,
      },
    });
  } catch (err) {
    console.error("Error creating guardian:", err);
    res.status(500).json({
      status: 0,
      message: "Server error",
      error: err.message,
    });
  }
});

// API to invite a guardian and map familyId
// app.post("/invites1-guardian", async (req, res) => {
//   const { guardianEmail, guardianName, parentId } = req.body;

//   // Validate required fields
//   if (!guardianEmail || !guardianName || !parentId) {
//     return res.status(400).json({
//       status: 0,
//       message: "Please provide guardian name, email, and parentId",
//     });
//   }

//   try {
//     // Find the parent using parentId
//     const parent = await User.findOne({ userId: parentId });
//     if (!parent) {
//       return res.status(404).json({
//         status: 0,
//         message: "Parent user not found",
//       });
//     }
//     const family = await Family.findOne({ familyId: parent.familyId[0] });
//     if (!family) {
//       return res.status(404).json({
//         status: 0,
//         message: "Family not found for the parent",
//       });
//     }
//     // Check if the guardian already exists in the family's guardians field
//     if (family.guardianIds && family.guardianIds.includes(guardianEmail)) {
//       return res.status(400).json({
//         status: 0,
//         message: "You are already a guardian of this family.",
//       });
//     }

//     const parentFamilyId = parent.familyId[0]; // Assuming a parent has only one familyId

//     // Check if the guardian email already exists in the User model
//     const existingGuardian = await User.findOne({ email: guardianEmail });

//     if (existingGuardian) {
//       if (family.guardianIds && family.guardianIds.includes(existingGuardian.userId)) {
//         return res.status(400).json({
//           status: 0,
//           message: "You are already a guardian of this family.",
//         });
//       }

//       // If the guardian is not already in the family's guardianIds, add the guardian's ID to the family
//       family.guardianIds.push(existingGuardian.userId);
//       await family.save();

//     // Create a JWT token for the guardian's email
//     const token = jwt.sign({ email: guardianEmail, parentId }, process.env.JWT_SECRET, {
//       expiresIn: "24h",
//     });

//     // If the guardian exists, add the parent familyId to the guardian's guardianId array
//     // if (existingGuardian) {
//     //   // Check if guardian is already linked to the parent familyId
//     //   if (!existingGuardian.guardianId.includes(parentFamilyId)) {
//     //     existingGuardian.guardianId.push(parentFamilyId);
//     //     await existingGuardian.save();
//     //   }

//       // Send a verification email
//       const verificationLink = `http://93.127.172.167:5001/verify?token=${token}&email=${guardianEmail}`;
//       const transporter = nodemailer.createTransport({
//         host: "mail.weighingworld.com",
//         port: 465,
//         secure: true,
//         auth: {
//           user: "no-reply@weighingworld.com",
//           pass: "$]IIWt4blS^_",
//         },
//       });

//       const mailOptions = {
//         from: "no-reply@weighingworld.com",
//         to: guardianEmail,
//         subject: "Guardian Invitation - Email Verification",
//         text: `Hello ${guardianName},\n\nPlease verify your email by clicking on the following link: ${verificationLink}`,
//       };

//       // Send the verification email
//       transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//           return res.status(500).json({
//             status: 0,
//             message: "Error sending verification email",
//           });
//         }

//         // Respond with success message if email is sent
//         res.status(200).json({
//           status: 1,
//           message: "Verification email sent successfully. Please check your email to verify your account.",
//         });
//       });
//     } else {
//       // If the guardian does not exist, send a registration link
//       const registrationLink = `http://93.127.172.167:5001/register-form?token=${token}&email=${guardianEmail}`;

//       const transporter = nodemailer.createTransport({
//         host: "mail.weighingworld.com",
//         port: 465,
//         secure: true,
//         auth: {
//           user: "no-reply@weighingworld.com",
//           pass: "$]IIWt4blS^_",
//         },
//       });

//       const mailOptions = {
//         from: "no-reply@weighingworld.com",
//         to: guardianEmail,
//         subject: "Guardian Invitation - Registration",
//         text: `Hello ${guardianName},\n\nIt seems like you are not registered. Please complete your registration by clicking on the following link: ${registrationLink}`,
//       };

//       // Send the registration email
//       transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//           return res.status(500).json({
//             status: 0,
//             message: "Error sending registration email",
//           });
//         }

//         // Respond with success message if email is sent
//         res.status(200).json({
//           status: 1,
//           message: "Registration email sent successfully. Please complete your registration.",
//         });
//       });
//     }
//   } catch (err) {
//     console.error("Error sending email:", err);
//     res.status(500).json({ status: 0, message: "Server error", err });
//   }
// });

// app.post("/invites-guardian", async (req, res) => {
//   const { guardianEmail, guardianName, parentId } = req.body;

//   // Validate required fields
//   if (!guardianEmail || !guardianName || !parentId) {
//     return res.status(400).json({
//       status: 0,
//       message: "Please provide guardian name, email, and parentId",
//     });
//   }

//   try {
//     // Find the parent using parentId
//     const parent = await User.findOne({ userId: parentId });
//     if (!parent) {
//       return res.status(404).json({
//         status: 0,
//         message: "Parent user not found",
//       });
//     }

//     // Find the family associated with the parent
//     const family = await Family.findOne({ familyId: parent.familyId[0] });
//     if (!family) {
//       return res.status(404).json({
//         status: 0,
//         message: "Family not found for the parent",
//       });
//     }

//     const parentFamilyId = parent.familyId[0]; // Assuming a parent has only one familyId

//     // Check if the guardian already exists in the User model
//     const existingGuardian = await User.findOne({ email: guardianEmail });

//     // If the guardian exists, check if they are already a guardian in the family's record
//     if (existingGuardian) {
//       if (family.guardianIds && family.guardianIds.includes(existingGuardian.userId)) {
//         return res.status(400).json({
//           status: 0,
//           message: "You are already a guardian of this family.",
//         });
//       }

//       // If the guardian is not already in the family's guardianIds, add the guardian's ID to the family
//       family.guardianIds.push(existingGuardian.userId);
//       await family.save();

//       // Create a JWT token for the guardian's email
//       const token = jwt.sign({ email: guardianEmail, parentId }, process.env.JWT_SECRET, {
//         expiresIn: "24h",
//       });

//       // Send the verification email
//       const verificationLink = `http://93.127.172.167:5001/verify?token=${token}&email=${guardianEmail}`;
//       const transporter = nodemailer.createTransport({
//         host: "mail.weighingworld.com",
//         port: 465,
//         secure: true,
//         auth: {
//           user: "no-reply@weighingworld.com",
//           pass: "$]IIWt4blS^_",
//         },
//       });

//       const mailOptions = {
//         from: "no-reply@weighingworld.com",
//         to: guardianEmail,
//         subject: "Guardian Invitation - Email Verification",
//         text: `Hello ${guardianName},\n\nPlease verify your email by clicking on the following link: ${verificationLink}`,
//       };

//       // Send the verification email
//       transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//           return res.status(500).json({
//             status: 0,
//             message: "Error sending verification email",
//           });
//         }

//         // Respond with success message if email is sent
//         res.status(200).json({
//           status: 1,
//           message: "Verification email sent successfully. Please check your email to verify your account.",
//         });
//       });
//     } else {
//       // If the guardian does not exist, send a registration link
//       const token = jwt.sign({ email: guardianEmail, parentId }, process.env.JWT_SECRET, {
//         expiresIn: "24h",
//       });
//       const registrationLink = `http://93.127.172.167:5001/register-form?token=${token}&email=${guardianEmail}`;

//       const transporter = nodemailer.createTransport({
//         host: "mail.weighingworld.com",
//         port: 465,
//         secure: true,
//         auth: {
//           user: "no-reply@weighingworld.com",
//           pass: "$]IIWt4blS^_",
//         },
//       });

//       const mailOptions = {
//         from: "no-reply@weighingworld.com",
//         to: guardianEmail,
//         subject: "Guardian Invitation - Registration",
//         text: `Hello ${guardianName},\n\nIt seems like you are not registered. Please complete your registration by clicking on the following link: ${registrationLink}`,
//       };

//       // Send the registration email
//       transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//           return res.status(500).json({
//             status: 0,
//             message: "Error sending registration email",
//           });
//         }

//         // Respond with success message if email is sent
//         res.status(200).json({
//           status: 1,
//           message: "Registration email sent successfully. Please complete your registration.",
//         });
//       });
//     }
//   } catch (err) {
//     console.error("Error sending email:", err);
//     res.status(500).json({ status: 0, message: "Server error", err });
//   }
// });

app.post("/assign-guardians", verifyParentRole, async (req, res) => {
  const { childId, guardian, familyId } = req.body;

  // Validate required fields
  if (!childId || !guardian || !familyId) {
    return res
      .status(400)
      .json({ message: "Please provide childId, guardianIds, and familyId" });
  }

  if (!Array.isArray(guardian)) {
    return res.status(400).json({ message: "guardian should be an array" });
  }

  try {
    // Validate that the childId belongs to a 'child' user
    const child = await User.findOne({ userId: childId });
    if (!child || child.role.toLowerCase() !== "child") {
      return res
        .status(400)
        .json({ message: "Invalid childId or the user is not a child" });
    }

    // Validate that the familyId exists and is associated with a valid family
    const family = await Family.findOne({ familyId: familyId });
    if (!family) {
      return res
        .status(400)
        .json({ message: "Invalid familyId or the family does not exist" });
    }

    // Validate guardian user roles
    //const guardians = await User.find({ 'userId': { $in: guardian }, role: 'guardian'&&'Guardian' }).select('userId role');
    const guardians = await User.find({
      userId: { $in: guardian },
      role: { $in: ["guardian", "Guardian"].map((r) => r.toLowerCase()) },
    }).select("userId role");
    console.log(guardians);
    if (guardians.length !== guardian.length) {
      return res.status(400).json({
        message: "Some guardianIds are invalid or the users are not guardians",
        guardiansFound: guardians, // Send back the found guardians for debugging
        guardianIdsReceived: guardian,
      });
    }
    const existingGuardians = child.guardian.filter((guardianId) =>
      guardian.includes(guardianId)
    );
    if (existingGuardians.length > 0) {
      return res
        .status(400)
        .json({ message: "This guardians are already assigned to this child" });
    }

    // Step 2: Add guardians to the child's list using $addToSet to avoid duplicates
    const updateChild = await User.updateOne(
      { userId: childId, role: { $regex: "^child$", $options: "i" } },
      { $addToSet: { guardian: { $each: guardian } } }
    );

    if (updateChild.modifiedCount === 0) {
      return res
        .status(400)
        .json({ message: "Failed to update child guardian list." });
    }

    // Step 3: Add the child to each guardian's list using $addToSet to avoid duplicates
    const guardianUpdates = await Promise.all(
      guardian.map(async (guardianId) => {
        const guardian = await User.findOne({
          userId: guardianId,
          role: { $regex: "^guardian$", $options: "i" },
        });
        if (!guardian) {
          return { error: `Guardian with userId ${guardian} not found.` };
        }

        const updateGuardian = await User.updateOne(
          { userId: guardianId, role: { $regex: "^guardian$", $options: "i" } },
          { $addToSet: { familyId: familyId } }
        );

        if (updateGuardian.modifiedCount === 0) {
          return { error: `Failed to add child to guardian ${guardianId}` };
        }

        return {
          success: `Child successfully added to guardian ${guardianId}`,
        };
      })
    );

    // Check if any guardian update failed
    const errors = guardianUpdates.filter((update) => update.error);
    if (errors.length > 0) {
      return res
        .status(400)
        .json({ message: "Some guardian updates failed", errors });
    }

    // Success response
    res.status(200).json({
      message: "Guardians assigned successfully",
      //child: child,
      guardians: guardians,
    });

    // Add the existing familyId to the child and all guardians
    //await User.updateOne({ userId: guardian }, { $push: { familyId: familyId } });

    // Update all guardians to add this familyId to their record
    //await User.updateMany({ 'userId': { $in: guardian } }, { $push: { familyId: familyId } });

    // Optionally: update the child’s `guardian` field to include the assigned guardians
    //await User.updateOne({ userId: childId }, { $push: { guardian: { $each: guardian } } });

    // Respond with success message
    //res.status(200).json({ message: 'Guardians assigned successfully and child added to family' });
  } catch (err) {
    console.error("Error assigning guardians:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/create-child", verifyParentRole, async (req, res) => {
  const parentId = req.user.userId; // Get the parentId from the decoded token
  console.log("Parent ID:", parentId);

  const {
    name,
    firstName,
    lastName,
    username,
    gender,
    email,
    password,
    role,
    dob,
    Totalpoints,
    school,
    hobby1,
    hobby2,
    hobby3,
  } = req.body;
  const normalizedRole = role ? role.toLowerCase() : "";
  const normalizedGender = gender ? gender.toLowerCase() : "";

  // Only allow 'child' role
  if (normalizedRole !== "child") {
    return res.status(400).json({ status: 0, message: 'Role must be "child"' });
  }

  // Validate required fields
  if ( !password || !dob ) {
    return res
      .status(400)
      .json({ status: 0, message: "Please provide all required fields" });
  }

  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({
      $or: [{ name }, { email: email || null }],
    });
    if (existingUser) {
      return res
        .status(200)
        .json({ status: 0, message: "Username or Name already exists" });
    }
    // Find the parent user
    const parent = await User.findOne({ userId: parentId });
    if (!parent) {
      return res.status(400).json({ status: 0, message: "Parent not found" });
    }

    const parsedDob = moment(dob, 'DD-MM-YYYY').format('YYYY-MM-DD');
    
    // If parsing fails, it will return an invalid date
    // if (!moment(parsedDob, 'YYYY-MM-DD', true).isValid()) {
    //   return res.status(400).json({ status: 0, message: "Invalid date format. Please use dd-mm-yyyy." });
    // }
    //console.log(parent);
    //const parentNameParts = parent.name.split(" ");
    //const parentNameParts = parent.lastName;
    //console.log(parentNameParts);

    //const childFirstName = name || parent.firstName;
    // Check if the name exists in the parent's kidsNames
    //const childFirstName = parent.kidsNames.includes(name) ? name : null;
    //const childLastName =parent.lastName;
    //console.log(childLastName);

    // if (!childFirstName) {
    //   // If the name isn't found in parent's kidsNames, return an error or set default
    //   return res.status(400).json({ status: 0, message: "The child's name is not listed in the parent's kidsNames" });
    // }

    // Create the new user (child)
    const newUser = new User({
      name,
      firstName,
      lastName,
      username,
      gender: normalizedGender,
      email: email || null,
      password,
      role: "child",
      dob:parsedDob,
      parentId,
      Totalpoints,
      familyId: parent.familyId,
      school,
      hobby1,
      hobby2,
      hobby3,
    });

    // Save the new user to the database
    await newUser.save();
    console.log(newUser);
    const family = await Family.findOne({ familyId: parent.familyId });
    if (!family) {
      return res.status(400).json({ status: 0, message: "Family not found" });
    }

    // Add the child's userId to the family's children array
    family.children.push(newUser.userId); // Assuming the child is assigned a userId on creation

    // Save the updated family document
    await family.save();

    res
      .status(200)
      .json({ status: 1, message: "Child created successfully", user: newUser });
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).json({ message: "Server error", err });
  }
});

app.get("/points", verifyToken, async (req, res) => {
  try {
    // user = req.user; // The user object is set by the authenticate middleware
    //console.log(user);
    const userId = req.user.userId;
    const user = await User.findOne({ userId: userId });
    const task = await Task.findOne({});

    // Ensure the user is a child before allowing access to points
    if (user.role !== "child") {
      return res
        .status(403)
        .json({ message: "Access denied, only children can view points" });
    }

    // Return the child's points
    return res.status(200).json({
      status: 1,
      message: "Points fetched successfully",
      points: user.Totalpoints, // Points stored in the Totalpoints field
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      status: 0,
      message: "An error occurred while fetching points",
    });
  }
});
app.put("/update", verifyToken, async (req, res) => {
  try {
    // Extract the userId from the decoded token
    const { userId } = req.user; // req.user is populated by verifyToken middleware
    const { name, email, password } = req.body;

    // Check if the request body is empty (no fields provided)
    if (!name && !email && !password) {
      return res.status(400).json({
        message: "name , email or password or fields not provided for update",
      });
    }

    // Check if any other fields are present in the payload (not allowed to be updated)
    const allowedFields = ["name", "email", "password"];
    const invalidFields = Object.keys(req.body).filter(
      (field) => !allowedFields.includes(field)
    );

    if (invalidFields.length > 0) {
      return res.status(400).json({
        message: "Only Email, name, password are allowed to be updated",
      });
    }

    // Validate that fields are not empty
    if (email && email.trim() === "") {
      return res.status(400).json({ message: "Email cannot be empty" });
    }
    if (name && name.trim() === "") {
      return res.status(400).json({ message: "Name cannot be empty" });
    }
    if (password && password.trim() === "") {
      return res.status(400).json({ message: "Password cannot be empty" });
    }

    // Find the user by userId extracted from token
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update the fields if they are provided
    if (email) user.email = email;
    if (name) user.name = name;
    if (password) user.password = password;

    // Save the updated user document
    await user.save();

    // Respond with success and the updated user data (exclude password for security)
    res.status(200).json({
      message: "User updated successfully",
      user: {
        userId: user.userId,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

const verifyParentOrGuardianRole = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1]; // Extract token from Authorization header

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    // Verify token and decode it
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Check if the user's role is 'parent' or 'guardian'
    if (req.user.role !== "parent" && req.user.role !== "guardian") {
      return res.status(403).json({
        message: "Access denied. Only parents and guardians can create tasks.",
      });
    }

    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    return res
      .status(400)
      .json({ message: "Invalid token.", error: err.message });
  }
};

const token = jwt.sign(
  { userId: User.userId, role: User.role },
  process.env.JWT_SECRET,
  { expiresIn: "1h" }
);

//Tasks

const Task = require("./models/Task");
// app.post("/create-task", verifyParentOrGuardianRole, async (req, res) => {
//   const {
//     title,
//     description,
//     taskId,
//     assignedTo,
//     associates,
//     expectedCompletionDate,
//     rewardType,
//     fairType,
//     fairAmount,
//     taskStatus,
//     associatedInterestsChild,
//     // createdBy,
//     fairDistribution,
//     penaltyAmount,
//     taskPriority,
//     paymentStatus,
//     schedule,
//     taskType,
//     completionDate,
//     completionTime,
//     parentId,
//   } = req.body;

//   if (!title || !assignedTo) {
//     return res
//       .status(400)
//       .json({ status: 0, message: "Please provide all required fields" });
//   }

//   const currentDate = new Date();
//   const expectedDate = new Date(expectedCompletionDate);

//   if (expectedDate < currentDate) {
//     return res.status(400).json({
//       status: 0,
//       message: "Expected completion date must be in the future",
//     });
//   }

//   try {
//     // Check if taskId already exists
//     console.log("User ID from token:", req.user.userId);
//     console.log(token);

//     const existingTask = await Task.findOne({ taskId });
//     if (existingTask) {
//       return res
//         .status(400)
//         .json({ status: 0, message: "Task ID already exists" });
//     }
//     const userIdFromToken = req.user.userId;

//     // Create the new task
//     const newTask = new Task({
//       title,
//       description,
//       taskId,
//       assignedTo,
//       associates,
//       expectedCompletionDate,
//       rewardType,
//       fairType,
//       fairAmount,
//       taskStatus,
//       associatedInterestsChild,
//       createdBy: userIdFromToken, //req.user.userId ,
//       fairDistribution,
//       penaltyAmount,
//       taskPriority,
//       paymentStatus,
//       schedule,
//       taskType,
//       completionDate,
//       completionTime,
//     });

//     // Save the new task to the database
//     await newTask.save();
//     res
//       .status(201)
//       .json({ status: 1, message: "Task created successfully", task: newTask });
//   } catch (err) {
//     console.error("Error creating task:", err);
//     res.status(500).json({ status: 0, message: "Server error", err });
//   }
// });

// Middleware to verify token

app.post("/create-task", verifyToken, async (req, res) => {
  const {
    title,
    description,
    taskId,
    createdBy,
    assignedTo,
    associates,
    expectedCompletionDate,
    rewardType,
    fairType,
    fairAmount,
    taskStatus,
    associatedInterestsChild,
    fairDistribution,
    penaltyAmount,
    taskPriority,
    paymentStatus,
    schedule,
    taskType,
    completionDate,
    completionTime,
  } = req.body;

  if (!title || !assignedTo || !expectedCompletionDate) {
    return res.status(400).json({
      status: 0,
      message: "Please title,assignedTo and expectedCompletionDate",
    });
  }

  // Parse and reformat the expectedCompletionDate
  const formattedExpectedCompletionDate = moment(expectedCompletionDate, "DD-MM-YYYY").format("YYYY-MM-DD");

  // Ensure the formatted date is valid
  if (!moment(formattedExpectedCompletionDate, "YYYY-MM-DD", true).isValid()) {
    return res.status(400).json({
      status: 0,
      message: "Invalid expected completion date format. Please use dd-mm-yyyy.",
    });
  }

  const currentDate = new Date();
  const expectedDate = new Date(formattedExpectedCompletionDate);

  if (expectedDate < currentDate) {
    return res.status(400).json({
      status: 0,
      message: "Expected completion date must be in the future",
    });
  }

  try {
    // Check if taskId already exists
    const existingTask = await Task.findOne({ taskId });
    if (existingTask) {
      return res
        .status(400)
        .json({ status: 0, message: "Task ID already exists" });
    }

    // Use userId from the token to set the creator of the task
    const userIdFromToken = req.user.userId;

    // Create the new task
    const newTask = new Task({
      title,
      description,
      taskId,
      assignedTo,
      associates,
      expectedCompletionDate:formattedExpectedCompletionDate,
      rewardType,
      fairType,
      fairAmount,
      taskStatus,
      associatedInterestsChild,
      createdBy: userIdFromToken, // User who is creating the task
      fairDistribution,
      penaltyAmount,
      taskPriority,
      paymentStatus,
      schedule,
      taskType,
      createdBy,
      completionDate,
      completionTime,
    });

    // Save the new task to the database
    await newTask.save();
    res
      .status(201)
      .json({ status: 1, message: "Task created successfully", task: newTask });
  } catch (err) {
    console.error("Error creating task:", err);
    res.status(500).json({ status: 0, message: "Server error", err });
  }
});

const verifyTaskCreatorOrAssigned = (req, res, next) => {
  const { taskId } = req.params; // Get taskId from URL parameters

  // Find the task by taskId
  Task.findOne({ taskId })
    .then((task) => {
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      // Check if the user is the creator of the task or is assigned to the task
      if (
        task.createdBy.toString() === req.user.userId ||
        task.assignedTo.toString() === req.user.userId
      ) {
        next(); // User is authorized, proceed to the next middleware or handler
      } else {
        return res.status(403).json({
          message: "Access denied. You are not authorized to view this task.",
        });
      }
    })
    .catch((err) => {
      return res
        .status(500)
        .json({ message: "Error fetching task", error: err.message });
    });
};

app.get("/tasks", async (req, res) => {
  try {
    // Fetch all tasks from the database
    const tasks = await Task.find(); // You can also add query parameters for filtering or pagination

    if (!tasks.length) {
      return res.status(404).json({
        status: 0,
        message: "No tasks found",
      });
    }

    // Respond with the tasks in JSON format
    res.status(200).json({
      status: 1,
      message: "Tasks retrieved successfully",
      tasks: tasks,
    });
  } catch (err) {
    console.error("Error fetching tasks:", err);
    res.status(500).json({
      status: 0,
      message: "Server error while fetching tasks",
    });
  }
});

app.get("/categorize-tasks", verifyToken, async (req, res) => {
  try {
    const user = req.user; // Get user info from the token

    // Ensure the user has tasks to view
    if (!user) {
      return res
        .status(400)
        .json({ message: "User not found or invalid token" });
    }

    // Fetch tasks based on user role (parent or child)
    let tasks = [];
    if (user.role === "parent") {
      tasks = await Task.find({
        createdBy: user.userId,
        assignedTo: { $exists: true },
      })
        .select(
          "taskId title expectedCompletionDate taskStatus createdBy fairAmount taskId -_id"
        ) // Only include specific fields
        .lean();
    } else if (user.role === "child") {
      tasks = await Task.find({ assignedTo: user.userId })
        .select(
          "description title expectedCompletionDate taskStatus assignedTo fairAmount taskId -_id"
        ) // Only include specific fields
        .lean(); //
    } else {
      return res.status(403).json({ message: "Access denied. Invalid role" });
    }

    // Categorize tasks into active, completed, and expired
    const categorizedTasks = {
      active: [],
      completed: [],
      expired: [],
    };

    const currentDate = new Date();

    tasks.forEach((task) => {
      if (task.taskStatus === "completed") {
        // If task is marked as completed, add it to 'completed' list
        categorizedTasks.completed.push(task);
      } else if (task.expectedCompletionDate < currentDate) {
        // If the task is expired and not completed
        categorizedTasks.expired.push(task);
      } else {
        // If the task is still active
        categorizedTasks.active.push(task);
      }
    });

    // If no tasks are found, return an appropriate message
    if (tasks.length === 0) {
      return res.status(404).json({ message: "No tasks found for this user" });
    }

    // Return categorized tasks
    res.status(200).json({
      status: 1,
      message: "Tasks categorized successfully.",
      categorizedTasks: categorizedTasks,
    });
  } catch (err) {
    console.error("Error categorizing tasks:", err);
    res
      .status(500)
      .json({ message: "Server error while categorizing tasks", err });
  }
});

// Route to view a task (only creator or assigned user can view it)
app.get(
  "/view-task/:taskId",
  verifyToken,
  verifyTaskCreatorOrAssigned,
  async (req, res) => {
    const { taskId } = req.params;

    try {
      // Find the task by taskId
      const task = await Task.findOne({ taskId });

      // If no task is found, return an error message
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      // Return the task details
      res.status(200).json({ task });
    } catch (err) {
      console.error("Error fetching task:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

//To view all tasks assigned to specific user
app.get(
  "/view-task/:taskId",
  verifyToken,
  verifyTaskCreatorOrAssigned,
  async (req, res) => {
    const { taskId } = req.params;

    try {
      // Find the task by taskId
      const task = await Task.findOne({ taskId });

      // If no task is found, return an error message
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      // Return the task details
      res.status(200).json({ task });
    } catch (err) {
      console.error("Error fetching task:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Middleware to check if the logged-in user is the creator of the task
const verifyTaskCreator = (req, res, next) => {
  const { taskId } = req.params; // Get taskId from URL parameters

  // Find the task by taskId
  Task.findOne({ taskId })
    .then((task) => {
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      // Check if the logged-in user is the creator of the task
      if (task.createdBy.toString() === req.user.userId) {
        next(); // User is the creator, proceed to the next middleware or handler
      } else {
        return res.status(403).json({
          message: "Access denied. You are not authorized to update this task.",
        });
      }
    })
    .catch((err) => {
      return res
        .status(500)
        .json({ message: "Error fetching task", error: err.message });
    });
};

//To view child Details

//To view user details
app.get("/user-details/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params; // Extract the userId from the request parameters

  try {
    // Find the user by userId in the database
    const user = await User.findOne({ userId: userId });

    // If the user is not found, return an error
    if (!user) {
      return res.status(404).json({ status: 0, message: "User not found" });
    }

    // Return the user details (excluding sensitive data like password)
    const { password, ...userDetails } = user.toObject(); // Remove the password from the response

    res.status(200).json({
      status: 1,
      message: "User details retrieved successfully",
      user: userDetails,
    });
  } catch (err) {
    console.error("Error retrieving user details:", err);
    res.status(500).json({ status: 0, message: "Server error" });
  }
});

// Route to update a task (only creator of the task can update it)
app.put(
  "/task-update/:taskId",
  verifyToken,
  verifyTaskCreator,
  async (req, res) => {
    const { taskId } = req.params;
    const {
      title,
      description,
      assignedTo,
      associates,
      expectedCompletionDate,
      rewardType,
      fairType,
      fairAmount,
      taskStatus,
      associatedInterestsChild,
      fairDistribution,
      penaltyAmount,
      taskPriority,
      paymentStatus,
      schedule,
      taskType,
      completionDate,
      completionTime,
    } = req.body;

    try {
      // Find the task by taskId
      const task = await Task.findOne({ taskId });

      // If no task is found, return an error message
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      // Update the task with the new data
      task.title = title || task.title;
      task.description = description || task.description;
      task.assignedTo = assignedTo || task.assignedTo;
      task.associates = associates || task.associates;
      task.expectedCompletionDate =
        expectedCompletionDate || task.expectedCompletionDate;
      task.rewardType = rewardType || task.rewardType;
      task.fairType = fairType || task.fairType;
      task.fairAmount = fairAmount || task.fairAmount;
      task.taskStatus = taskStatus || task.taskStatus;
      task.associatedInterestsChild =
        associatedInterestsChild || task.associatedInterestsChild;
      task.fairDistribution = fairDistribution || task.fairDistribution;
      task.penaltyAmount = penaltyAmount || task.penaltyAmount;
      task.taskPriority = taskPriority || task.taskPriority;
      task.paymentStatus = paymentStatus || task.paymentStatus;
      task.schedule = schedule || task.schedule;
      task.taskType = taskType || task.taskType;
      task.completionDate = completionDate || task.completionDate;
      task.completionTime = completionTime || task.completionTime;

      // Save the updated task
      await task.save();

      // Return the updated task
      res.status(200).json({ message: "Task updated successfully", task });
    } catch (err) {
      console.error("Error updating task:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.get("/view-tasks", verifyToken, async (req, res) => {
  try {
    const user = req.user; // Get user info from the token

    // Fetch tasks based on user role
    let tasks;
    const taskFields =
      "taskId title expectedCompletionDate taskStatus fairAmount isExpired";
    if (user.role === "parent") {
      // Parent can view tasks they created
      tasks = await Task.find({ createdBy: user.userId })
        // Assuming the 'createdBy' field stores parent who created the task
        .select(taskFields + "-_id")
        .populate("assignedTo", "name email -_id") // Optional: populate assignedTo field with user details
        .sort({ expectedCompletionDate: 1 }); // Optional: Sort by due date
    } else if (user.role === "child") {
      // Child can view tasks assigned to them
      tasks = await Task.find({ assignedTo: user.userId })
        .select(taskFields + " -_id")
        .populate("assignedTo", "name email -_id") // Optional: populate assignedTo field with user details
        .sort({ expectedCompletionDate: 1 }); // Optional: Sort by due date
    } else {
      return res.status(403).json({ message: "Access denied. Invalid role" });
    }

    // If no tasks are found, return an appropriate message
    if (!tasks || tasks.length === 0) {
      return res
        .status(404)
        .json({ message: `No tasks associated with this ${user.role}` });
    }

    // Return the tasks in the response
    res.status(200).json({
      status: 1,
      message: `${
        user.role.charAt(0).toUpperCase() + user.role.slice(1)
      }'s tasks retrieved successfully.`,
      tasks: tasks,
    });
  } catch (err) {
    console.error("Error fetching tasks:", err);
    res.status(500).json({ message: "Server error while fetching tasks" });
  }
});

//Updated view children with fair type and fair amount
// app.get("/childrens", verifyToken, async (req, res) => {
//   try {
//     const parent = req.user; // Get user info from the token
//     // Ensure the logged-in user is a parent
//     if (parent.role !== "parent") {
//       return res
//         .status(403)
//         .json({ status: 0, message: "Access denied. You must be a parent." });
//     }

//     // Fetch children where the parent's userId is the parentId
//     const children = await User.find({ parentId: parent.userId , role: "child" })
//       .select("userId name email gender dob isActive") // Select only relevant fields
//       .sort({ name: 1 }); // Optional: Sort children by name or any other criteria

//     if (children.length === 0) {
//       return res
//         .status(404)
//         .json({ status: 0, message: "No children found for this parent." });
//     }

//     // Fetch tasks related to each child (populate the tasks with fairAmount and fairType)
//     const childrenWithTasks = await Promise.all(
//       children.map(async (child) => {
//         const formattedDob = child.dob
//           ? moment(child.dob).format('DD-MM-YYYY') // Use moment.js to format the date
//           : null;
//         // Fetch the tasks related to each child
//         const task = await Task.find({ assignedTo: child.userId }) // or Task.find({ childId: child.userId }) depending on your Task schema
//           // .select('fairAmount rewardType taskType')  // Select only relevant fields
//           .sort({ createdAt: -1 }); // Optional: Sort tasks by creation date or any other criteria

//         // Attach tasks to each child
//         return {
//           ...child.toObject(), // Convert Mongoose document to plain object
//           dob: formattedDob,
//           task, // Add tasks to the child object
//         };
//       })
//     );

//     // Return the list of children along with their tasks
//     res.status(200).json({
//       status: 1,
//       message: "Children retrieved successfully.",
//       children: childrenWithTasks,
//     });
//   } catch (err) {
//     console.error("Error fetching children:", err);
//     res.status(500).json({
//       status: 0,
//       message: "Server error while fetching children",
//       err,
//     });
//   }
// });

app.get("/children", verifyToken, async (req, res) => {
  try {
    const parent = req.user; // Get user info from the token

    // Ensure the logged-in user is a parent
    if (parent.role !== "parent" && parent.role !== "guardian") {
      return res
        .status(403)
        .json({ status: 0, message: "Access denied. You must be a parent." });
    }

    // Fetch the family where the logged-in parent is either the first or second parent
    const family = await Family.findOne({ 
      $or: [{ parentId: parent.userId }, { secondParentId: parent.userId },{ guardianIds: { $in: [parent.userId] }}] 
    });

    if (!family) {
      return res
        .status(404)
        .json({ status: 0, message: "No family found for this parent." });
    }

    // Fetch children where the parentId or secondParentId belongs to this family
    const children = await User.find({ 
      familyId: family.familyId,  // Assuming `familyId` is the field linking children to a family
      role: "child" 
    })
      .select("userId name email gender dob isActive") // Select only relevant fields
      .sort({ name: 1 }); // Optional: Sort children by name or any other criteria

    if (children.length === 0) {
      return res
        .status(404)
        .json({ status: 0, message: "No children found for this parent." });
    }

    // Fetch tasks related to each child (populate the tasks with fairAmount and fairType)
    const childrenWithTasks = await Promise.all(
      children.map(async (child) => {
        const formattedDob = child.dob
          ? moment(child.dob).format('DD-MM-YYYY') // Use moment.js to format the date
          : null;
        
        // Fetch the tasks related to each child
        const tasks = await Task.find({ assignedTo: child.userId })
          .sort({ createdAt: -1 }); // Optional: Sort tasks by creation date or any other criteria

        // Attach tasks to each child
        return {
          ...child.toObject(), // Convert Mongoose document to plain object
          dob: formattedDob,
          tasks, // Add tasks to the child object
        };
      })
    );

    // Return the list of children along with their tasks
    res.status(200).json({
      status: 1,
      message: "Children retrieved successfully.",
      children: childrenWithTasks,
    });
  } catch (err) {
    console.error("Error fetching children:", err);
    res.status(500).json({
      status: 0,
      message: "Server error while fetching children",
      err,
    });
  }
});



app.get("/coparents", verifyToken, async (req, res) => {
  try {
    const parent = req.user; // Get user info from the token
    console.log(parent);

    // Ensure the logged-in user is a parent or guardian
    // if (parent.role !== "parent" && parent.role !== "guardian") {
    //   return res
    //     .status(403)
    //     .json({ status: 0, message: "Access denied. You must be a parent or guardian." });
    // }

    // Fetch the family where the logged-in parent is listed as parent or guardian
    const family = await Family.findOne({
      $or: [
        { parentId: parent.userId },
        { guardianIds: parent.userId },
      ],
    });

    if (!family) {
      return res
        .status(404)
        .json({ status: 0, message: "No family found for this parent." });
    }

    // Initialize an empty array to store co-parents
    let coParents = [];

    // Get all parents (excluding the logged-in user) from the parentId array
    if (family.parentId && family.parentId.length > 0) {
      // Filter out the logged-in user from the parentId array
      const otherParents = family.parentId.filter(parentId => parentId !== parent.userId);
      
      // Fetch the details of the other parents (users) and add to coParents
      const parents = await User.find({ userId: { $in: otherParents } });
      coParents.push(...parents);
    }

    // Check for all guardians (excluding the logged-in user)
    if (family.guardianIds && family.guardianIds.length > 0) {
      const guardians = await User.find({
        userId: { $in: family.guardianIds },
      });

      // Add guardians to the co-parents list, excluding the logged-in user
      guardians.forEach((guardian) => {
        if (guardian.userId !== parent.userId) {
          coParents.push(guardian);
        }
      });
    }

    // If no co-parents are found, return a message
    if (coParents.length === 0) {
      return res
        .status(404)
        .json({ status: 0, message: "No co-parents found for this parent." });
    }

    

    // Return the list of co-parents
    res.status(200).json({
      status: 1,
      message: "Co-parents retrieved successfully.",
       coParents:coParents,//coParents.map((coParent) => ({
      //   name: coParent.name,
      //   firstName:coParent.firstName,
      //   lastName:coParent.lastName,
      //   email: coParent.email,
      //   role: coParent.role,
      // })),
    });
  } catch (err) {
    console.error("Error fetching co-parents:", err);
    res.status(500).json({
      status: 0,
      message: "Server error while fetching co-parents",
      err,
    });
  }
});




app.post("/update-device-id", async (req, res) => {
  const { userId, deviceId } = req.body;

  // Validate input
  if (!userId || !deviceId) {
    return res
      .status(400)
      .json({ message: "User ID and Device ID are required." });
  }

  try {
    // Find the user and update the deviceId
    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Update the user's deviceId
    user.deviceId = deviceId;
    await user.save();

    // Send a success response
    return res.status(200).json({ message: "Device ID updated successfully." });
  } catch (err) {
    console.error("Error updating device ID:", err);
    return res
      .status(500)
      .json({ message: "Server error", error: err.message });
  }
});

app.post("/saveDeviceToken", async (req, res) => {
  const { userId, deviceId } = req.body;

  // Check if both userId and deviceId are provided
  if (!userId || !deviceId) {
    return res.status(400).json({ error: "userId and deviceId are required" });
  }

  try {
    // Check if the user already exists
    let user = await User.findOne({ userId });

    if (user) {
      // If the user exists, update the deviceId
      user.deviceId = deviceId;
      await user.save();
      return res
        .status(200)
        .json({ message: "Device ID updated successfully" });
    } else {
      // If the user does not exist, create a new user with the deviceId
      user = new User({ userId, deviceId });
      await user.save();
      return res.status(201).json({ message: "Device ID saved successfully" });
    }
  } catch (error) {
    console.error("Error saving device ID:", error);
    return res.status(500).json({ error: "Failed to save device ID" });
  }
});

// API to view a specific child user
app.get("/view-child/:childId", verifyParentRole, async (req, res) => {
  const { childId } = req.params; // Extract the childId from URL parameters
  const parentId = req.user.userId; // Extract the logged-in parent's userId (from the JWT payload)

  try {
    // Step 1: Find the child by their userId
    const child = await User.findOne({ userId: childId }); // Assuming childId is unique

    // Step 2: If child is not found
    if (!child) {
      return res.status(404).json({ status: 0, message: "Child not found" });
    }

    if (child.parentId && child.parentId.toString() !== parentId.toString()) {
      return res.status(403).json({
        status: 0,
        message: "You are not authorized to view this child",
      });
    }

    // Step 4: If everything is correct, return child details
    return res.status(200).json({
      status: 1,
      message: "Child details retrieved successfully",
      child, // The child data
    });
  } catch (error) {
    console.error("Error fetching child details:", error);
    return res
      .status(500)
      .json({ status: 0, message: "Error fetching child details" });
  }
});

// API to register a device ID after user login
app.post("/register-device", verifyToken, async (req, res) => {
  const { deviceId } = req.body;

  if (!deviceId) {
    return res.status(400).json({ message: "Device ID is required" });
  }

  try {
    // Get the token from the request header
    console.log("Received device ID:", deviceId); // Log the token

    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Decode the JWT token to get the userId
    //const decoded = jwt.verify(token, 'your-secret-key');  // Replace with your actual secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Fetch the user from the database using the decoded userId
    const user = await User.findOne({ userId: decoded.userId });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    //     // Update the deviceId for the logged-in user
    user.deviceId = deviceId;

    //     // Save the updated user document (since `user` is now a Mongoose model instance)
    await user.save();

    res
      .status(200)
      .json({ message: "Device registered successfully", deviceId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error registering device" });
  }
});

// // API to send a notification to a device by user email
// app.post('/notification',async (req, res) => {
//     const { email, message } = req.body;

//     if (!email || !message) {
//         return res.status(400).json({ status:0, message: 'Email and message are required' });
//     }

//     try {
//         // Find the user by email
//         const user = await User.findOne({ email });

//         if (!user) {
//             return res.status(404).json({ status:0, message: 'User not found' });
//         }

//         // Get the deviceId from the user
//         const deviceId = user.deviceId;

//         if (!deviceId) {
//             return res.status(404).json({ status:0, message: 'Device ID not found for this user' });
//         }

//         // Simulate sending a notification (replace with real logic)
//         sendNotificationToDevice(deviceId, message);

//         res.status(200).json({ status:1, message: `Notification sent to user with Device Id ${deviceId}` });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ status:0, message: 'Error sending notification' });
//     }
// });

// // Simulate sending a notification (this could be a real integration with FCM or similar service)
// // function sendNotificationToDevice(deviceId, message) {
// //     console.log(`Sending notification to device ${deviceId}: ${message}`);
// // }

// // Function to send a notification to a specific device using the device token
// async function sendNotificationToDevice(deviceId, message) {
//   const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     // Fetch the user from the database using the decoded userId
//     const user = await User.findOne({ userId: decoded.userId });
//   const messagePayload = {
//     notification: {
//       title: 'New Notification',
//       body: message,  // The message content to send to the device
//     },
//     token:deviceId// The device token (ID) that identifies the device

//   };

//   try {
//     // Send the message using Firebase Admin SDK
//     await admin.messaging().send(messagePayload);
//     console.log('Notification sent successfully to device:', deviceId);
//   } catch (error) {
//     console.error('Error sending notification:', error);
//   }
// }

// // API to send a notification to a device by user ID from the token
// app.post('/send-notification', async (req, res) => {
//   const { message } = req.body;

//   if (!message) {
//       return res.status(400).json({ status: 0, message: 'Message is required' });
//   }

//   try {
//       // Extract userId from JWT token
//       const token = req.headers.authorization?.split(" ")[1]; // Assuming token is sent in the "Authorization" header as Bearer <token>
//       if (!token) {
//           return res.status(400).json({ status: 0, message: 'Authorization token is required' });
//       }
//       console.log(token);

//       const decoded = jwt.verify(token, process.env.JWT_SECRET); // Use your JWT secret here
//       const userId = decoded.userId; // Get the userId from the decoded token

//       // Find the user by userId in the database
//       const user = await User.findOne({ userId });

//       if (!user) {
//           return res.status(404).json({ status: 0, message: 'User not found' });
//       }

//       // Get the device token (FCM token) from the user
//       const deviceId = user.deviceId;  // Assuming 'deviceToken' is where you store the FCM device token

//       if (!deviceId) {
//           return res.status(404).json({ status: 0, message: 'Device Id not found for this user' });
//       }

//       // Send the notification to the device
//       await sendNotificationToDevice(deviceId, message);

//       res.status(200).json({ status: 1, message: `Notification sent to user with device Id ${deviceId}` });
//   } catch (error) {
//       console.error(error);
//       res.status(500).json({ status: 0, message: 'Error sending notification' });
//   }
// });

// // Function to send a notification to a specific device using the device token
// async function sendNotificationToDevice(deviceId, message) {
//   const messagePayload = {
//       notification: {
//           title: 'New Notification',
//           body: message,  // The message content to send to the device
//       },
//       token:deviceId  // The FCM device token that identifies the device
//   };
//   console.log(messagePayload.token);

//   try {
//       // Send the message using Firebase Admin SDK
//       await admin.messaging().send(messagePayload);
//       console.log('Notification sent successfully to device:', deviceId);
//   } catch (error) {
//       console.error('Error sending notification:', error);
//   }
// }

// POST endpoint to create a new reward
app.post("/create-rewards", verifyToken, async (req, res) => {
  const userId = req.user.userId; // Get user ID from the authentication middleware (assumes JWT)
  console.log(userId);

  const user = await User.findOne({ userId });
  if (user.role !== "parent") {
    return res.status(400).json({
      status: 0,
      message: "Only parents are allowed to create rewards.",
    });
  }
  const {
    rewardName,
    rewardType,
    requiredPoints,
    startDate,
    expiryDate,
    category,
    expirationGracePeriod,
  } = req.body;
  currentDate = Date.now();

  try {
    if (
      !rewardName ||
      !rewardType ||
      !requiredPoints ||
      !startDate ||
      !expiryDate ||
      !category
    ) {
      return res.status(400).json({
        status: 0,
        message:
          "Missing required fields: rewardId,rewardName,rewardType,requiredPoints,startDate,expiryDate,category",
      });
    }

    if (new Date(startDate) < currentDate) {
      return res
        .status(400)
        .json({ error: "Start Date cannot be in the past." });
    }

    if (new Date(expiryDate) < currentDate) {
      return res
        .status(400)
        .json({ status: 0, message: "Provide accurate Expiry Date." });
    }

    if (new Date(expiryDate) < new Date(startDate)) {
      return res.status(400).json({
        status: 0,
        message:
          "Provide valid Expiry Date, Expiry Date should be a Date occuring after Start Date.",
      });
    }
    const rewardId = uuidv4().split("-")[0];

    const newReward = new Reward({
      rewardName,
      rewardType,
      requiredPoints,
      startDate,
      expiryDate,
      category,
      expirationGracePeriod,
      createdBy: user.userId,
      rewardId: rewardId,
    });

    console.log("Before saving, rewardId:", newReward.rewardId);

    await newReward.save();

    res.status(201).json({
      status: 1,
      message: "Reward created successfully!",
      reward: newReward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to create reward" });
  }
});

// POST endpoint to claim a reward
app.post("/rewards/claim/:rewardId", verifyToken, async (req, res) => {
  try {
    const rewardId = req.params.rewardId;

    const userId = req.user.userId;

    // Find the user
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).json({ status: 0, message: "User not found" });
    }

    // Find the reward
    const reward = await Reward.findOne({ rewardId });

    //reward.claimedBy = req.user.userId;
    if (!reward) {
      return res.status(404).json({ status: 0, message: "Reward not found" });
    }

    // Get the current date
    const currentDate = new Date();

    // Check if the reward's startDate is in the future
    if (reward.startDate > currentDate) {
      return res.status(400).json({
        status: 0,
        message:
          "This reward cannot be claimed yet. The reward starts on " +
          reward.startDate.toDateString(),
      });
    }

    // Check if the user's total points are greater than or equal to the required points for the reward
    if (user.Totalpoints < reward.requiredPoints) {
      return res.status(400).json({
        status: 0,
        message: `You need ${
          reward.requiredPoints - user.Totalpoints
        } more points to claim this reward.`,
      });
    }

    reward.claimedBy.push(user.userId);

    reward.dateClaimed = new Date(); // Optionally store the date the reward was claimed
    reward.claimStatus = "claimed";

    // Save the updated reward
    await reward.save();

    // Optionally, you can deduct points from the user if claiming the reward costs points
    user.Totalpoints -= reward.requiredPoints;
    await user.save();

    const redemptionDetail = {
      redemptionId: uuidv4(), // Generate a unique ID for the redemption
      userId: user.userId,
      rewardId: reward.rewardId,
      dateClaimed: new Date(),
      method: "points", // Assuming the user is claiming with points (adjust as necessary)
      rewardPaymentStatus: "pending",
    };
    reward.redemptionDetails.push(redemptionDetail);

    await reward.save();

    // Respond with success
    res.status(200).json({
      status: 1,
      message: "Reward claimed successfully!",
      reward: reward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, message: "Failed to claim the reward" });
  }
});

// PUT endpoint to edit an existing reward
app.put("/rewards/:rewardId", verifyToken, async (req, res) => {
  const { rewardId } = req.params; // Get rewardId from the URL params
  const userId = req.user.userId; // Get user ID from the authentication middleware (assumes JWT)

  const {
    rewardName,
    rewardType,
    requiredPoints,
    startDate,
    expiryDate,
    category,
    expirationGracePeriod,
  } = req.body;

  const currentDate = Date.now();

  try {
    // Validate required fields are provided for update
    if (
      !rewardName &&
      !rewardType &&
      !requiredPoints &&
      !startDate &&
      !expiryDate &&
      !category &&
      !expirationGracePeriod
    ) {
      return res
        .status(400)
        .json({ status: 0, message: "No valid fields provided for update." });
    }

    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });

    if (!reward) {
      return res.status(404).json({ status: 0, message: "Reward not found." });
    }

    if (reward.createdBy !== userId) {
      return res.status(403).json({
        status: 0,
        message: "You are not authorised to edit this reward.",
      });
    }

    // If provided, validate and update the startDate and expiryDate
    if (expiryDate) {
      if (new Date(expiryDate) < currentDate) {
        return res
          .status(400)
          .json({ status: 0, message: "Provide accurate Expiry Date." });
      }
      if (new Date(expiryDate) < new Date(startDate || reward.startDate)) {
        return res.status(400).json({
          status: 0,
          message: "Expiry Date should be after Start Date.",
        });
      }
    }

    // Update reward with new data (only update provided fields)
    reward.rewardName = rewardName || reward.rewardName;
    reward.rewardType = rewardType || reward.rewardType;
    reward.requiredPoints = requiredPoints || reward.requiredPoints;
    reward.startDate = startDate || reward.startDate;
    reward.expiryDate = expiryDate || reward.expiryDate;
    reward.category = category || reward.category;
    reward.expirationGracePeriod =
      expirationGracePeriod || reward.expirationGracePeriod;
    //reward.redemptionDetails = redemptionDetails || reward.redemptionDetails

    // Save updated reward to the database
    await reward.save();

    // Return success response with the updated reward data
    res.status(200).json({
      status: 1,
      message: "Reward updated successfully!",
      reward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, error: "Failed to update reward." });
  }
});

// API Endpoint to approve a reward
app.put("/rewards/approve/:rewardId", verifyToken, async (req, res) => {
  const { rewardId } = req.params; // Get rewardId from the URL params
  const userId = req.user.userId;
  try {
    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });
    const claimedId = reward.claimedBy;

    //const claimedId = reward.claimedBy[0];
    console.log(claimedId);

    if (!reward) {
      return res.status(404).json({ status: 0, message: "Reward not found." });
    }

    //Check if the reward is already approved
    if (reward.isApproved) {
      return res
        .status(400)
        .json({ status: 0, message: "This reward is already approved." });
    }

    // Approve the reward by updating the isApproved field
    if (reward.createdBy === userId && reward.claimStatus === "claimed") {
      reward.isApproved = true;
    }

    if (reward.createdBy !== userId) {
      return res.status(403).json({
        status: 0,
        message: "You are not authorised to approve this reward.",
      });
    }

    if (reward.claimStatus !== "claimed") {
      return res
        .status(400)
        .json({ status: 0, message: "No user has claimed this reward yet." });
    }
    // Update the redemption details for each user who has claimed the reward
    for (const claimedUserId of reward.claimedBy) {
      // Find the redemption detail for the claimed user
      const redemptionDetail = reward.redemptionDetails.find(
        (detail) => detail.userId.toString() === claimedUserId.toString()
      );
      if (!redemptionDetail) {
        return res.status(400).json({
          status: 0,
          message: `No redemption details found for user with ID ${claimedUserId}.`,
        });
      }

      // Update the redemption details for this user
      redemptionDetail.rewardPaymentStatus = "complete"; // Assuming the payment status is complete
      redemptionDetail.dateClaimed = new Date(); // Update the date the reward was claimed
    }

    await reward.save();
    // After successful update, reset the reward's approval and claim status
    reward.isApproved = false; // Reset the approval status
    reward.claimStatus = "unclaimed"; // Set the claim status to 'unclaimed'
    await reward.save();

    // Return success response with the updated reward data
    res.status(200).json({
      status: 1,
      message: "Reward approved successfully!",
      reward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, message: "Failed to approve reward." });
  }
});

app.put("/rewards/redemption/:rewardId", verifyToken, async (req, res) => {
  const { rewardId } = req.params; // Get rewardId from the URL params
  const userId = req.user.userId;

  const { redemptionId, method, rewardPaymentStatus } = req.body;

  try {
    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });
    const claimedId = reward.claimedBy;
    const isApproved = reward.isApproved;
    const claimStatus = reward.claimStatus;
    const length = reward.redemptionDetails.length;
    const redemptionDetails = reward.redemptionDetails[0];

    if (!reward) {
      return res.status(404).json({ status: 0, message: "Reward not found." });
    }

    if (reward.createdBy !== userId) {
      return res.status(403).json({
        status: 0,
        message: "You are not authorised to approve this reward.",
      });
    }

    if (reward.isApproved !== true || reward.claimStatus !== "claimed") {
      return res.status(400).json({
        status: 0,
        message: "This reward is not approved or claimed yet",
      });
    }

    //if(reward.claimStatus !=="claimed"){
    //return res.status(400).json({ status:0, message:"This reward is not claimed yet."});
    //}

    if (length === 0) {
      if (
        reward.createdBy === userId &&
        isApproved &&
        claimStatus === "claimed"
      ) {
        const newRedemptionDetail = {
          redemptionId,
          rewardId: rewardId,
          userId: claimedId,
          method,
          rewardPaymentStatus,
          dateClaimed: Date.now(), // Automatically set the current time
        };
        reward.redemptionDetails.push(newRedemptionDetail);
        reward.isApproved = false;
        reward.claimStatus = "unclaimed";
      }
    } else {
      if (
        redemptionDetails.userId === claimedId &&
        redemptionDetails.rewardPaymentStatus === "pending"
      ) {
        reward.isApproved = false;
        reward.claimStatus = "unclaimed";
        await reward.save();

        return res.status(400).json({
          status: 0,
          message:
            "You have a redemption with payment status-pending for this user ",
        });
      }

      if (
        reward.createdBy === userId &&
        isApproved &&
        claimStatus === "claimed"
      ) {
        const newRedemptionDetail = {
          redemptionId,
          rewardId: rewardId,
          userId: claimedId,
          method,
          rewardPaymentStatus,
          dateClaimed: Date.now(), // Automatically set the current time
        };
        reward.redemptionDetails.push(newRedemptionDetail);
        reward.isApproved = false;
        reward.claimStatus = "unclaimed";
      }
    }

    await reward.save();

    // Return success response with the updated reward data
    res.status(200).json({
      status: 1,
      message: "Reward reedemed successfully!",
      reward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, message: "Failed to approve reward." });
  }
});

app.post("/flush-data", async (req, res) => {
  try {
    // Flush all data from the "users" collection
    const result = await User.deleteMany({});

    // Return a success response
    res.status(200).json({
      status: "success",
      message: "All data has been flushed successfully",
      deletedCount: result.deletedCount,
    });
  } catch (err) {
    console.error("Error flushing data:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to flush data",
    });
  }
});

app.post("/flush-verificationtokens", async (req, res) => {
  try {
    // Flush all data from the "users" collection
    const result = await VerificationToken.deleteMany({});

    // Return a success response
    res.status(200).json({
      status: "success",
      message: "All data has been flushed successfully",
      deletedCount: result.deletedCount,
    });
  } catch (err) {
    console.error("Error flushing data:", err);
    res.status(500).json({
      status: "error",
      message: "Failed to flush data",
    });
  }
});

app.post("/app_versions", async (req, res) => {
  const { platform, version, url } = req.body;

  // Validate the input
  if (!platform || !version || !url) {
    return res.status(400).json({
      status: 0,
      message: "Please provide all required fields: platform, version and url",
    });
  }

  try {
    // Create a new app version record
    const newAppVersion = new app_versions({
      platform,
      version,
      url,
    });

    // Save the record to the database
    const savedAppVersion = await newAppVersion.save();

    // Send the response
    return res.status(201).json({
      status: 1,
      message: "App version created successfully",
      data: savedAppVersion,
    });
  } catch (err) {
    console.error("Error creating app version:", err);
    return res.status(500).json({
      status: 0,
      message: "Server error. Failed to create app version.",
    });
  }
});

// API to check for updates
// app.get('/check-update', async (req, res) => {
//   const { platform, version } = req.query;  // Platform and current version passed as query params

//   if (!platform || !version) {
//     return res.status(400).json({
//       status: 0,
//       message: 'Please provide both platform and current version'
//     });
//   }

//   try {
//     // Find the latest version for the specified platform
//     const latestVersion = await app_versions.findOne({ platform }).sort({ created_at: -1 });  // Sort by created_at, so the latest version is first

//     if (!latestVersion) {
//       return res.status(404).json({
//         status: 0,
//         message: 'No version found for the specified platform'
//       });
//     }

//     // Check if the current version is up-to-date
//     if (version === latestVersion.version) {
//       return res.status(200).json({
//         status: 1,
//         message: 'Your app is up-to-date'
//       });
//     }

//     // If the current version is less than the latest version, return the latest version and update details
//     return res.status(200).json({
//       status: 1,
//       message: 'A new update is available',
//       latestVersion: latestVersion.version,
//       downloadUrl:'https://drive.google.com/uc?export=download&id=1BLb6HJEZaCiIA_NpvrtFofkDAFYMuREP',
//     });
//   } catch (err) {
//     console.error('Error checking update:', err);
//     return res.status(500).json({
//       status: 0,
//       message: 'Server error',
//     });
//   }
// });
// app.get("/check-update", async (req, res) => {
//   try {
//     // Find the most recent app version by sorting the collection in descending order of version
//     //const allAppVersions = await app_versions.find();
//     //console.log(allAppVersions);
//     const latestAppVersion = await app_versions.findOne().sort({ version: -1 }).collation({ locale: 'en', numericOrdering: true }).exec();;
//     console.log(latestAppVersion);

//     // If no app version is found
//     if (!latestAppVersion) {
//       return res.status(404).json({
//         status: 0,
//         message: "No app versions found.",
//       });
//     }

//     // Send the latest app version as the response
//     return res.status(200).json({
//       status: 1,
//       message: "Latest app version retrieved successfully.",
//       data: {
//         platform: latestAppVersion.platform,
//         version: latestAppVersion.version,
//         url: latestAppVersion.url,
//       },
//     });
//     console.log(data);
//   } catch (err) {
//     console.error("Error retrieving the latest app version:", err);
//     return res.status(500).json({
//       status: 0,
//       message: "Server error. Failed to retrieve the latest app version.",
//     });
//   }
// });

app.get("/check-update", async (req, res) => {
  try {
    // Convert version string to an array of integers for proper sorting
    const latestAppVersion = await app_versions
      .findOne()
      .sort({
        version: -1, // You may need to manually parse and sort versions numerically
      })
      .collation({ locale: "en", numericOrdering: true }) // Ensure correct ordering for version strings
      .exec();

    // If no app version is found
    if (!latestAppVersion) {
      return res.status(404).json({
        status: 0,
        message: "No app versions found.",
      });
    }

    // Send the latest app version as the response
    return res.status(200).json({
      status: 1,
      message: "Latest app version retrieved successfully.",
      data: {
        platform: latestAppVersion.platform,
        version: latestAppVersion.version,
        url: latestAppVersion.url,
      },
    });
  } catch (err) {
    console.error("Error retrieving the latest app version:", err);
    return res.status(500).json({
      status: 0,
      message: "Server error. Failed to retrieve the latest app version.",
    });
  }
});


// Assuming you are using Express.js and Mongoose
app.delete("/delete-account", async (req, res) => {
  const { userId } = req.body; // The user ID of the parent account

  if (!userId) {
    return res.status(400).json({
      status: 0,
      message: "User ID is required to delete the account.",
    });
  }

  try {
    // Find the parent user by userId
    const parentUser = await User.findOne({ userId });

    if (!parentUser) {
      return res
        .status(404)
        .json({ status: 0, message: "Parent user not found." });
    }

    // Check if the user is a parent
    if (parentUser.role !== "parent") {
      return res.status(400).json({
        status: 0,
        message:
          "Only parent accounts can delete themselves and child accounts.",
      });
    }

    // Find and delete all child accounts associated with this parent (via parentId)
    const childAccounts = await User.deleteMany({
      parentId: parentUser.userId,
    });
    console.log(`${childAccounts.deletedCount} child accounts deleted.`);

    // Delete the parent account
    await User.deleteOne({ userId });

    res.status(200).json({
      status: 1,
      message:
        "Parent user and all associated child accounts have been successfully deleted.",
    });
  } catch (err) {
    console.error("Error deleting user account:", err);
    res.status(500).json({
      status: 0,
      message: "Server error occurred while deleting the account.",
    });
  }
});

// API to get both primary and secondary families based on guardianId
app.get("/get-family", verifyToken, async (req, res) => {
  const guardianId = req.user.userId; // Assuming the token contains the guardianId
  console.log(guardianId);

  // if (!guardianId) {
  //   return res.status(400).json({ status: 0, message: 'Guardian ID is required.' });
  // }

  try {
    // Find the guardian (user) by guardianId
    const guardian = await User.findOne({ userId: guardianId });

    if (!guardian) {
      return res
        .status(404)
        .json({ status: 0, message: "Guardian not found." });
    }

    // Find the primary family by familyId (from the guardian)
    const primaryFamily = await Family.findOne({
      familyId: guardian.familyId[0],
    });
    console.log(primaryFamily);

    if (!primaryFamily) {
      return res
        .status(404)
        .json({ status: 0, message: "Primary family not found." });
    }

    // Find the secondary family by guardianId (used as familyId in user)
    const secondaryFamily = await Family.findOne({ familyId: guardianId });

    if (!secondaryFamily) {
      return res
        .status(404)
        .json({ status: 0, message: "Secondary family not found." });
    }

    // Respond with the primary and secondary family details
    res.status(200).json({
      status: 1,
      message: "Families retrieved successfully.",
      data: {
        primaryFamily,
        secondaryFamily,
      },
    });
  } catch (err) {
    console.error("Error fetching family data:", err);
    res.status(500).json({
      status: 0,
      message: "Server error occurred while fetching family data.",
    });
  }
});

app.get("/get-user-families/:userId", async (req, res) => {
  const { userId } = req.params; // User ID from the URL parameter

  try {
    // Find the user by userId
    const user = await User.findOne({ userId: userId });

    if (!user) {
      return res.status(404).json({ status: 0, message: "User not found" });
    }

    // Fetch the families associated with the user
    let familyIds = [];

    // Add user's familyId (if any) to the list
    if (user.familyId && user.familyId.length > 0) {
      familyIds = [...familyIds, ...user.familyId];
    }

    // Add the families where the user is a guardian (guardianId) to the list
    if (user.guardianId) {
      const guardianFamilies = await Family.find({ guardianIds: user.userId });
      const guardianFamilyIds = guardianFamilies.map(
        (family) => family.familyId
      );
      familyIds = [...familyIds, ...guardianFamilyIds];
      const role = "guardian";
    }

    // Add the families where the user is a child (parentId) to the list
    const childFamilies = await Family.find({ parentId: user.userId });
    const childFamilyIds = childFamilies.map((family) => family.familyId);
    familyIds = [...familyIds, ...childFamilyIds];

    // Remove duplicates by converting to a Set
    familyIds = [...new Set(familyIds)];
    //const parentFamilyName = user.name;
    //const formattedFamilyName = `${parentFamilyName}'s Family`;  // Format as "FamilyName's Family"

    let formattedFamilyName = "";
    if (user.role === "parent") {
      const parentFamilyName = user.name;
      formattedFamilyName = `${parentFamilyName}'s Family`; // For the parent, it's the parent's name
    } else if (user.role === "guardian" || user.role === "child") {
      // For a guardian or child, fetch the family info of the parent
      const parentUser = await User.findOne({ userId: user.parentId });
      if (parentUser) {
        formattedFamilyName = `${parentUser.name}'s Family`; // Parent's family name
      }
    }

    // Return the familyIds
    res.status(200).json({
      status: 1,
      message: "Family IDs associated with user fetched successfully",
      familyIds,
      familyName: formattedFamilyName,
      role: user.role,
    });
  } catch (err) {
    console.error("Error fetching user families:", err);
    res.status(500).json({ status: 0, message: "Server error" });
  }
});

// app.get("/get-guardian-families/:userId", async (req, res) => {
//   const { userId } = req.params; // User ID from the URL parameter

//   try {
//     // Find the user by userId
//     const user = await User.findOne({ userId: userId });

//     if (!user) {
//       return res.status(404).json({ status: 0, message: "User not found" });
//     }

//     // Fetch the families where the user is a parent (via parentId field)
//     let parentFamilies = await Family.find({ parentId: user.userId });
//     let parentFamilyIds = parentFamilies.map(family => family.familyId);

//     // Fetch the families where the user is a guardian (via guardianIds array)
//     let guardianFamilies = await Family.find({ guardianIds: user.userId });
//     let guardianFamilyIds = guardianFamilies.map(family => family.familyId);

//     // Combine both sets of family IDs, with parent families listed first
//     let allFamilyIds = [...parentFamilyIds, ...guardianFamilyIds];

//     // Remove duplicates by converting to a Set
//     allFamilyIds = [...new Set(allFamilyIds)];

//     // Return the list of familyIds where the user is either a parent or guardian
//     res.status(200).json({
//       status: 1,
//       message: "Families where the user is a parent or guardian fetched successfully",
//       familyIds: allFamilyIds
//     });

//   } catch (err) {
//     console.error("Error fetching guardian families:", err);
//     res.status(500).json({ status: 0, message: "Server error" });
//   }
// });

// app.get("/get-guardian-families1/:userId", async (req, res) => {
//   const { userId } = req.params; // User ID from the URL parameter

//   try {
//     // Find the user by userId
//     const user = await User.findOne({ userId: userId });

//     if (!user) {
//       return res.status(404).json({ status: 0, message: "User not found" });
//     }

//     let familyIds = [];
//     let familyNames = [];

//     // If the user is a parent, include their primary familyId (stored in `familyId`)
//     if (user.familyId && user.familyId.length > 0) {
//       familyIds = [...familyIds, ...user.familyId];
//     }

//     // If the user is a guardian, include the family IDs stored in `guardianIds`
//     if (user.guardianId && user.guardianId.length > 0) {
//       familyIds = [...familyIds, ...user.guardianId];
//     }

//     // Remove duplicates by converting to a Set and back to an array
//     familyIds = [...new Set(familyIds)];

//     // Fetch family names by looking up the familyId in each case
//     for (let familyId of familyIds) {
//       let familyName = '';
//       let role = '';

//       // For the user's primary family (familyId stored in User model)
//       if (user.familyId.includes(familyId)) {
//         const parentName = user.name;
//         familyName = `${parentName}'s Family`;  // Parent's family
//         role = 'parent';
//         console.log(role);
//       } else {
//         if (user.guardianId && user.guardianId.includes(familyId)) {
//           const parentUser = await User.findOne({ familyId: familyId });
//           console.log(parentUser);

//           if (parentUser) {
//             familyName = `${parentUser.name}'s Family`;  // Parent's family name for the guardian's family
//             role ='guardian';
//           }
//         }
//       }

//         // For guardian's family ID, get the parent name
//       //   const family = await Family.findOne({ familyId: familyId });
//       //   if (family && family.parentId) {
//       //     const parentUser = await User.findOne({ userId: family.parentId });
//       //     if (parentUser) {
//       //       familyName = `${parentUser.name}'s Family`;
//       //     }
//       //   }

//       // }

//       // Store the familyId and familyName
//       familyNames.push({ familyId, familyName,role });
//     }

//     // Return the list of familyIds
//     res.status(200).json({
//       status: 1,
//       message: "Families where the user is a parent or guardian fetched successfully",
//       families: familyNames,
//     });

//   } catch (err) {
//     console.error("Error fetching guardian families:", err);
//     res.status(500).json({ status: 0, message: "Server error" });
//   }
// });

// app.get("/get-families/:userId", async (req, res) => {
//   const { userId } = req.params; // User ID from the URL parameter

//   try {
//     // Find the user by userId
//     const user = await User.findOne({ userId: userId });

//     if (!user) {
//       return res.status(404).json({ status: 0, message: "User not found" });
//     }

//     let familyIds = [];
//     let familyNames = [];

//     // If the user is a parent, include their primary familyId (stored in `familyId`)
//     if (user.familyId && user.familyId.length > 0) {
//       familyIds = [...familyIds, ...user.familyId];
//     }

//     // If the user is a guardian, include the family IDs stored in `guardianIds`
//     if (user.guardianIds && user.guardianIds.length > 0) {
//       familyIds = [...familyIds, ...user.guardianIds];  // Corrected field for guardians
//     }

//     // Remove duplicates by converting to a Set and back to an array
//     familyIds = [...new Set(familyIds)];

//     // Fetch family names by looking up the familyId in each case
//     for (let familyId of familyIds) {
//       let familyName = '';
//       let role = '';

//       // For the user's primary family (familyId stored in User model)
//       if (user.familyId && user.role === "parent" && user.familyId.includes(familyId)) {
//         familyName = `${user.name}'s Family`;  // Parent's family
//         role = 'parent';  // Set role to parent
//       } else if (user.guardianIds && user.guardianIds.includes(familyId)) {
//         // For guardian's family (guardianIds)
//         const parentUser = await User.findOne({ familyId: familyId });

//         if (parentUser) {
//           familyName = `${parentUser.name}'s Family`;  // Guardian's family name
//           role = 'guardian';  // Set role to guardian
//         }
//       } else {
//         // For the user's family as a child (check if the user is a child in the family)
//         const parentUser = await User.findOne({ familyId: familyId });

//         // Check if this user is a child in the familyId (not parent or guardian)
//         if (parentUser && parentUser.familyId && parentUser.familyId.includes(familyId)) {
//           familyName = `${parentUser.name}'s Family`;  // Family of the parent
//           role = 'child';  // Set role to child
//         }
//       }

//       // Store familyId, familyName, and role
//       familyNames.push({ familyId, familyName, role });  // Include role here
//     }

//     // Return the list of familyIds with roles
//     res.status(200).json({
//       status: 1,
//       message: "Families where the user is a parent, guardian, or child fetched successfully",
//       families: familyNames,
//     });

//   } catch (err) {
//     console.error("Error fetching guardian families:", err);
//     res.status(500).json({ status: 0, message: "Server error" });
//   }
// });

app.get("/get-families1/:userId", async (req, res) => {
  const { userId } = req.params; // User ID from the URL parameter

  try {
    // Step 1: Find the user by userId
    const user = await User.findOne({ userId: userId });

    if (!user) {
      return res.status(404).json({ status: 0, message: "User not found" });
    }

    // Step 2: Find the families that the user belongs to based on role
    let familyIds = [];
    let familyNames = [];

    // Add familyIds depending on the user's role and their association with families

    // If the user is a parent, include their primary familyId (stored in `familyId`)
    if (user.familyId && user.familyId.length > 0) {
      familyIds = [...familyIds, ...user.familyId];
    }

    // If the user is a guardian, include the family IDs stored in `guardianIds`
    if (user.guardianIds && user.guardianIds.length > 0) {
      familyIds = [...familyIds, ...user.guardianIds]; // Include guardian families
    }

    // Remove duplicates by converting to a Set and back to an array
    familyIds = [...new Set(familyIds)];

    // Step 3: For each familyId, find and update the family document based on the user's role
    for (let familyId of familyIds) {
      // Retrieve the family document
      const family = await Family.findOne({ familyId: familyId });

      if (!family) {
        continue; // If no family is found, skip this iteration
      }

      // Based on the user's role, update the family document
      if (user.role === "parent") {
        // Add to parentId array
        if (!family.parentId) family.parentId = [];
        if (!family.parentId.includes(userId)) {
          family.parentId.push(userId);
        }
      } else if (user.role === "child") {
        // Add to children array
        if (!family.children) family.children = [];
        if (!family.children.includes(userId)) {
          family.children.push(userId);
        }
      } else if (user.role === "guardian") {
        // Add to guardianIds array
        if (!family.guardianIds) family.guardianIds = [];
        if (!family.guardianIds.includes(userId)) {
          family.guardianIds.push(userId);
        }
      }

      // Save the updated family document
      //await family.save();

      // Add the family name to the familyNames array
      const familyName = `${user.name}'s Family`;
      familyNames.push({ familyId, familyName, role: user.role });
      console.log(familyNames);
    }

    // Step 4: Return the family data
    res.status(200).json({
      status: 1,
      message: "Families updated with user roles successfully",
      families: familyNames,
    });
  } catch (err) {
    console.error("Error fetching or updating family data:", err);
    res
      .status(500)
      .json({ status: 0, message: "Server error", error: err.message });
  }
});

app.get("/get-families/:userId", async (req, res) => {
  const { userId } = req.params; // User ID from the URL parameter

  try {
    // Step 1: Find the user by userId
    const user = await User.findOne({ userId: userId });

    if (!user) {
      return res.status(404).json({ status: 0, message: "User not found" });
    }

    // Step 2: Prepare an array to store familyIds the user belongs to
    let familyIds = [];

    // If the user has a familyId (they're a parent), add it
    if (user.familyId && user.familyId.length > 0) {
      familyIds = [...familyIds, ...user.familyId];
    }

    // If the user has guardianIds (they're a guardian), add them
    if (user.guardianId && user.guardianId.length > 0) {
      familyIds = [...familyIds, ...user.guardianId]; // Include guardian families
    }

    // Remove duplicate familyIds by converting to a Set and then back to an array
    familyIds = [...new Set(familyIds)];

    // Step 3: Fetch family details for each familyId
    const families = [];

    for (let familyId of familyIds) {
      // Retrieve the family document by familyId
      const family = await Family.findOne({ familyId: familyId });

      if (!family) {
        continue; // If no family is found for this familyId, skip to the next
      }

      // Based on the user's role, prepare the response
      let role = "";

      // Check if userId is in the guardianId array of the family
      if (family.guardianIds && family.guardianIds.includes(userId)) {
        role = "guardian";
      }
      // Check if userId is in the parentId array of the family
      else if (family.parentId && family.parentId.includes(userId)) {
        role = "parent";
      }
      else if (family.children && family.children.includes(userId)) {
          role = "child";
        }

      // Construct the family name (e.g., "John's Family")
      //const familyName = `${user.name}'s Family`;
      const familyName = family.familyName || `${user.firstName}'s Family`;

      families.push({
        familyId: family.familyId,
        familyName,
        role,
      });
    }
    console.log(families);

    // Step 4: Return the list of families
    res.status(200).json({
      status: 1,
      message: "Families updated with user roles successfully",
      families,
    });
  } catch (err) {
    console.error("Error fetching family data:", err);
    res.status(500).json({
      status: 0,
      message: "Server error",
      error: err.message,
    });
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  // Validate required fields
  if (!email) {
    return res.status(400).json({
      status: 0,
      message: 'Please provide an email address',
    });
  }

  try {
    // Check if the email exists in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        status: 0,
        message: 'Email not found',
      });
    }

    // Generate a reset token (using JWT)
    const resetToken = jwt.sign({ email: user.email, userId: user.userId }, process.env.JWT_SECRET, {
      expiresIn: '1h', // Token expires in 1 hour
    });

    // Generate reset link
    const resetLink = `http://93.127.172.167:5001/reset-password?token=${resetToken}&email=${email}`;

    // Set up the transporter to send emails (Using Nodemailer)
    // const transporter = nodemailer.createTransport({
    //   host: process.env.EMAIL_HOST,
    //   port: process.env.EMAIL_PORT,
    //   secure: true, // true for 465, false for other ports
    //   auth: {
    //     user: process.env.EMAIL_USER,
    //     pass: process.env.EMAIL_PASS,
    //   },
    // });

    // // Prepare email content
    // const mailOptions = {
    //   from: process.env.EMAIL_USER,
    //   to: email,
    //   subject: 'Password Reset Request',
    //   text: `Hello,\n\nYou requested a password reset. Click the link to reset your password: ${resetLink}`,
    // };

    // // Send reset email
    // transporter.sendMail(mailOptions, (error, info) => {
    //   if (error) {
    //     return res.status(500).json({
    //       status: 0,
    //       message: 'Error sending password reset email',
    //     });
    //   }

    const transporter = nodemailer.createTransport({
      host: "mail.weighingworld.com",
      port: 465,
      secure: true,
      auth: {
        user: "no-reply@weighingworld.com",
        pass: "$]IIWt4blS^_",
      },
    });

    const mailOptions = {
      from: "no-reply@weighingworld.com",
      to: email,
      subject: "Password Reset - Email Verification",
      text: `Hello ${email},\n\nPlease verify your email by clicking on the following link: ${resetLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({
          status: 0,
          message: "Error sending verification email",
        });
      }


      // Respond with success if email was sent successfully
      res.status(200).json({
        status: 1,
        message: 'Password reset link sent. Please check your email to reset your password.',
      });
    });
  } catch (err) {
    console.error('Error processing forgot-password:', err);
    res.status(500).json({
      status: 0,
      message: 'Server error',
    });
  }
});

app.post('/reset-password', async (req, res) => {
  //const { email,token } = req.params;
  const { token,email,newPassword, confirmPassword } = req.body;
  console.log(newPassword);

  // Validate password fields
  if (!newPassword || !confirmPassword) {
    return res.status(400).json({
      status: 0,
      message: 'Please provide both password and confirm password',
    });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({
      status: 0,
      message: 'Passwords do not match',
    });
  }
  try {
    // Verify the reset token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { email, userId } = decoded;

    // Find the user by email (or userId)
    const user = await User.findOne({ userId: userId, email });
    if (!user) {
      return res.status(404).json({
        status: 0,
        message: 'User not found or token expired',
      });
    }

    const isMatch = await bcrypt.compare(newPassword, user.password);
    if (isMatch) {
      return res.status(400).json({
        status: 0,
        message: 'New password cannot be the same as the current password.',
      });
    }

    // Hash the new password
    //const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    user.password = newPassword;
    await user.save();
    

    res.status(200).json({
      status: 1,
      message: 'Password successfully updated.',
    });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({
      status: 0,
      message: 'Server error',
    });
  }
});

// API endpoint for email suggestions


app.get("/suggest-emails", async (req, res) => {
  const { emailPrefix } = req.query; // Get the input from the query parameter

  // Ensure the emailPrefix has at least 3 characters
  if (!emailPrefix || emailPrefix.length < 3) {
    return res.status(400).json({
      status: 0,
      message: "Please enter at least 3 characters."
    });
  }

  try {
    // Query the database for emails starting with the provided prefix
    const emails = await User.find({
      email: { $regex: `^${emailPrefix}`, $options: "i" }, // Case-insensitive regex match
    }).select("email"); // Only select the email field

    // Return the suggestions if found
    if (emails.length > 0) {
      const emailSuggestions = emails.map(user => user.email);
      return res.json({
        status: 1,
        suggestions: emailSuggestions
      });
    } else {
      return res.json({
        status: 0,
        message: "No suggestions found."
      });
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 0,
      message: "Server error. Please try again later."
    });
  }
});

app.get("/suggest-username", async (req, res) => {
  const { usernamePrefix } = req.query; // Get the input from the query parameter

  // Ensure the emailPrefix has at least 3 characters
  if (!usernamePrefix || usernamePrefix.length < 3) {
    return res.status(400).json({
      status: 0,
      message: "Please enter at least 3 characters."
    });
  }

  try {
    // Query the database for emails starting with the provided prefix
    const emails = await User.find({
      email: { $regex: `^${emailPrefix}`, $options: "i" }, // Case-insensitive regex match
    }).select("email"); // Only select the email field

    // Return the suggestions if found
    if (emails.length > 0) {
      const emailSuggestions = emails.map(user => user.email);
      return res.json({
        status: 1,
        suggestions: emailSuggestions
      });
    } else {
      return res.json({
        status: 0,
        message: "No suggestions found."
      });
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 0,
      message: "Server error. Please try again later."
    });
  }
});


app.post('/change-password', async (req, res) => {
  try {
    const { parentId, childId, currentPassword, newPassword } = req.body;

    // Step 1: Retrieve the child user based on childId
    const child = await User.findOne({userId:childId});  // Use `findById` instead of `findOne` for direct ObjectId lookup
    if (!child) {
      return res.status(404).json({ status: 0, message: 'Child user not found.' });
    }

    if (child.parentId.toString() !== parentId) {
      return res.status(403).json({ status: 0, message: 'This child does not belong to the specified parent.' });
    }

    // Step 3: Compare the provided current password with the stored password (hashed)
    const isCurrentPasswordCorrect = await bcrypt.compare(currentPassword, child.password);
    if (!isCurrentPasswordCorrect) {
      return res.status(400).json({ status: 0, message: 'The current password is incorrect.' });
    }

    // Step 4: Compare the new password with the stored password to prevent reusing the same password
    const isSamePassword = await bcrypt.compare(newPassword, child.password);
    if (isSamePassword) {
      return res.status(400).json({ status: 0, message: 'The new password cannot be the same as the current password.' });
    }

    // Step 5: Hash the new password
    //const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Step 6: Update the child's password in the database
    child.password = newPassword;
    await child.save();

    return res.status(200).json({ status: 1, message: 'Password updated successfully for the child user.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, message: 'Server Error.' });
  }
});





//Start the server

app.listen(port, () => {
  console.log(`Server running at http://93.127.172.167:${port}`);
});
