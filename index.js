const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('./models/User');
const Family = require('./models/family');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const app = express();
// const { authenticate, checkParentRole } = require('./middleware/auth');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();
const multer = require('multer');
const path = require('path');
//router.put('/update', protect, updateUserDetails);
const axios = require('axios');
const admin = require('firebase-admin');
//const sendNotificationToDevice = require('./notificationService');
const Reward = require('./models/reward');
const rateLimit = require('express-rate-limit'); 
const compression = require('compression');  // Import compression
const VerificationToken = require('./models/VerificationToken');
const FRONTEND_URL='templates/sample.html';
//const app_versions = require("./models/app_versions");

//const Redemption = require('./models/Redemption');

//const { sendNotification } = require('./notifications/sendNotification');

app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 500, 
  message: 'Too many requests, please try again later.',
});

app.use(limiter);
app.use(compression());

app.get('/large-data', (req, res) => {
  const largeData = // large data payload //
  res.json(largeData); // The response will be compressed before being sent to the client
});
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/sample.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'sample.html'));
});


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
  dest: 'uploads/images/',  // Store uploaded files in this directory
  limits: { fileSize: 5 * 1024 * 1024 },  // Limit file size to 5MB
  fileFilter: (req, file, cb) => {
    // Allow only image files (JPEG, PNG, GIF)
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed.'));
    }
  }
});
module.exports = upload;





dotenv.config(); // Load environment variables from .env file

const port = process.env.PORT || 5001;



// Middleware
require('dotenv').config();
//app.use(express.json()); // for parsing application/json
app.use(express.json({ limit: '10mb' }));

app.use(cors()); // Enable cross-origin requests

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/react-native-app')
  .then(() => console.log('MongoDB Connected'))
  .catch((err) => console.log('MongoDB connection error:', err));

// User registration route
// POST /register (For Parent User)
app.post('/register-user', async (req, res) => {
  //console.log(req.body);
  console.log('Request body:', req.body);
  console.log('Request Headers:', req.headers);
  const { name, gender, email, password, role, dob } = req.body;
  const normalizedRole = role ? role.toLowerCase() : '';
  const normalizedgender = gender ? gender.toLowerCase() : '';
  //console.log(req.body);  

  // Ensure only 'parent' role user can register
  //if (role !== 'parent' &&'Parent' && role!='guardian'&&'Guardian') {
  if (normalizedRole !== 'parent' && normalizedRole !== 'guardian'){
    return res.status(400).json({ status: 0, message: 'Only parent and guardian role is allowed to register' });
  }

  // Validate required fields
  if ( !name || !email || !password || !dob || !gender) {
    return res.status(400).json({ status: 0, message: 'Please provide all required fields:name,email,password,dob,gender' });
  }

  if (!role) {
    return res.status(400).json({ status: 0, message: 'Please provide role of user' })
  }
  // if (gender === "") {
  //   return res.status(400).json({ status: 0, message: 'Gender cannot be empty' });
  // }


  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({ $or: [{ email },{name}] });
    if (existingUser) {
      return res.status(200).json({ status: 0, message: 'Email or Name already exists' });
    }
    //const existingName = await User.findOne

    // Create the new user
    const newUser = new User({
      name,
      gender:normalizedgender,
      email,
      password,
      role:normalizedRole,
      dob,
      //isActive,
      //deviceId
    });

    // Save the new user to the database
    await newUser.save();
    const token = jwt.sign(
      { userId: newUser.userId, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: '15d' } // Token will expire in 15 days
    );
    res.status(200).json({ status: 1, message: 'Parent registered successfully', user: newUser, token:token});

  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ status: 0, message: 'Server error' ,err});
  }
});

app.post('/register', async (req, res) => {
  const { name, gender, email, password, role, dob } = req.body;
  const normalizedRole = role ? role.toLowerCase() : '';
  const normalizedgender = gender ? gender.toLowerCase() : '';

  if (normalizedRole !== 'parent' && normalizedRole !== 'guardian') {
    return res.status(400).json({ status: 0, message: 'Only parent and guardian role is allowed to register' });
  }

  // Validate required fields
  if (!name || !email || !password || !dob || !gender) {
    return res.status(400).json({ status: 0, message: 'Please provide all required fields' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { name }] }).where('deleted').equals(false);
    if (existingUser) {
      return res.status(200).json({ status: 0, message: 'Email or Name already exists' });
    }
    // const salt = await bcrypt.genSalt(10);
    // const hashedPassword = await bcrypt.hash(password, salt);
    // const newUser = new User({
    //   name,
    //   gender: normalizedgender,
    //   email,
    //   password:hashedPassword,  // Make sure to hash the password before saving
    //   role: normalizedRole,
    //   dob,
    // });

    


    //Create the new user
    // const newUser = new User({
    //   name,
    //   gender: normalizedgender,
    //   email,
    //   password,
    //   role: normalizedRole,
    //   dob,
    // });

    // // Save the new user to the database
    // await newUser.save();

    // Create a unique email verification token with 24 hours expiration
    //const token = crypto.randomBytes(32).toString('hex');  // 32 bytes token

    // Save the token in the database (or cache it for 24 hours expiration)
   
    const token = jwt.sign(
      {email  }, //userId: newUser.userId, role: newUser.role
      process.env.JWT_SECRET, // Token will expire in 15 days
    );
    const verificationLink = `http://93.127.172.167:5001/sample.html?token=${token}&email=${email}`;

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verificationToken = new VerificationToken({
      email,
      token,
      name,
      role:normalizedRole,
      gender:normalizedgender,
      dob,
      password:hashedPassword,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // expires in 24 hours
    });
    await verificationToken.save();

    

    // Send the verification link to the user's email
    const transporter = nodemailer.createTransport({
      host: 'mail.weighingworld.com',
      port: 465,
      secure: true,
      auth: {
        user: 'no-reply@weighingworld.com',
        pass: '$]IIWt4blS^_',
      },
    });

    const mailOptions = {
      from: 'no-reply@weighingworld.com',
      to: email,
      subject: 'Email Verification',
      text: `Please verify your email by clicking on the following link: ${verificationLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ status: 0, message: 'Error sending verification email' });
      }

      res.status(200).json({
        status: 1,
        message: 'Registration successful. A verification email has been sent.',
      });
    });

  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ status: 0, message: 'Server error' });
  }
});

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

app.post('/verify-email', async (req, res) => {
  const { token, email } = req.body;

  // Check if token and email are provided
  if (!token || !email) {
    return res.status(400).json({ status: 0, message: 'Token and email are required' });
  }

  try {
    // Find the verification token in the database
    const verificationToken = await VerificationToken.findOne({ email, token }).where('deleted').equals(false);

    if (!verificationToken) {
      return res.status(400).json({ status: 0, message: 'Invalid or expired token' });
    }

    // Check if the token has expired
    if (verificationToken.expiresAt < Date.now()) {
      return res.status(400).json({ status: 0, message: 'Token has expired' });
    }

    // Mark user as verified in the User model (or update `isActive` field)
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ status: 0, message: 'User not found' });
    }

    // Mark user as active/verified
    //user.isActive = true; // You can add an `isActive` field in the User schema to track verification status
    const newUser = new User({
      email:verificationToken.email,
      name:verificationToken.name,
      role:verificationToken.role,
      gender:verificationToken.gender,
      dob:verificationToken.dob,
      password:verificationToken.password,
    })
    
    await newUser.save();
    console.log(newUser);

    // Delete the verification token (optional)
    verificationToken.verified = true;
    await verificationToken.save();
    //await VerificationToken.deleteOne({ email, token });

    res.status(200).json({ status: 1, message: 'Email successfully verified' });

  } catch (err) {
    console.error('Error verifying email:', err);
    res.status(500).json({ status: 0, message: 'Server error '+err });
  }
});


const verifyParentRole = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];  // Get token from header

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify token and extract user role
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    console.log(req.user.role);
    //const normalizedRole = role ? role.toLowerCase() : '';
    // Only allow if the role is parent
    if (req.user.role !== "parent" ){ //&& req.user.role !== 'parent'
      return res.status(403).json({ message: 'Access denied. Only parents are allowed to do perform this action .' });
    }

    next();  // Proceed to the next middleware or route handler
  } catch (err) {
    return res.status(400).json({ message: 'Invalid token', error: err.message });
  }
};

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];  // Extract token from Authorization header

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify the token and extract the user information
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;  // Attach decoded user info (including userId) to request object
    next();  // Proceed to the next middleware or route handler
  } catch (err) {
    return res.status(400).json({ message: 'Invalid token', error: err.message });
  }
};


app.put('/upload-image', verifyToken, upload.single('image'), async (req, res) => {
  try {
    const userId = req.user.userId;  // Get userId from the decoded token
    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get the image filename and store it in the database
    const imageFilename = req.file.filename;  // This is the autogenerated filename from multer

    // Optionally, you can store the full path
    const imagePath = `/uploads/images/${imageFilename}`;

    // Update the user image field with the image file path
    user.image = imagePath;  // Save the path in the user document

    await user.save();

    res.status(200).json({
      message: 'User image uploaded successfully',
      //imagePath
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error uploading image' });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).send('File is too large');
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

app.post('/login', async (req, res) => {
  const { email, name, password } = req.body;

  // Check if email or name is provided along with the password
  if (!password) {
    return res.status(400).json({ status: 0, message: 'Please provide password' });
  }

  try {
    let user;

    // If email is provided, search for user by email
    if (email) {
      user = await User.findOne({ email });
    } else if (name) {
      // If no email, check if it's a child and search by name
      user = await User.findOne({ name });

      // Ensure user is found and the role is 'child' if name is provided
      if (!user || user.role !== 'child') {
        return res.status(401).json({ status: 0, message: 'User not found or not a child user' });
      }
    } else {
      return res.status(400).json({ status: 0, message: 'Please provide either email or name' });
    }

    if (!user) {
      return res.status(401).json({ status: 0, message: 'User not found' });
    }

    // Compare the provided password with the stored password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: 0,
        message: 'Invalid email/name or password',
      });
    }

    // Generate a 4-digit OTP (after successful password verification)
    const otp = Math.floor(1000 + Math.random() * 9000); // Generate a 4-digit number

    // Set up SMTP transporter using provided credentials
    const transporter = nodemailer.createTransport({
      host: 'mail.weighingworld.com', // SMTP server
      port: 465, // SSL port
      secure: true, // Use SSL (true for port 465)
      auth: {
        user: 'no-reply@weighingworld.com', // Email address (username)
        pass: '$]IIWt4blS^_', // Email password or app password
      },
    });

    const mailOptions = {
      from: 'no-reply@weighingworld.com', // Sender address
      to: user.email, // Receiver address (only if email exists)
      subject: 'Test Email', // Subject line
      text: `Your OTP is: ${otp}`, // Plain text body
    };

    // Send OTP email if email is provided
    if (user.email) {
      transporter.sendMail(mailOptions, async (error, info) => {
        if (error) {
          console.error('Error sending OTP email:', error);
          return res.status(500).json({ status: 0, message: 'Error sending OTP email' });
        }
        console.log('OTP email sent: ' + info.response);

        // After OTP is sent, create JWT token and send response
        const token = jwt.sign(
          { userId: user.userId, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '15d' } // Token will expire in 15 days
        );

        // Send response with token
        return res.status(200).json({
          status: 1,
          message: 'Login successful',
          otpstatus: 'OTP sent successfully',
          otp: otp, // In real cases, do not return OTP in response
          token: token,
          userId: user.userId,
          role: user.role,
          name: user.name,
          familyId: user.familyId || null,
          familyName: user.familyId ? await Family.findOne({ familyId: user.familyId }).familyName : null,
        });
      });
    } else {
      // If no email is provided for the child, skip sending OTP and directly issue the token
      const token = jwt.sign(
        { userId: user.userId, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '15d' } // Token will expire in 15 days
      );

      // Send response with token for child (no OTP sent)
      return res.status(200).json({
        status: 1,
        message: 'Login successful',
        token: token,
        userId: user.userId,
        role: user.role,
        name: user.name,
        familyId: user.familyId || null,
        familyName: user.familyId ? await Family.findOne({ familyId: user.familyId }).familyName : null,
      });
    }
  } catch (err) {
    console.error('Error logging in user:', err);
    res.status(500).json({ status: 0, message: 'Server error' });
  }
});


app.post('/create-family', verifyToken, async (req, res) => {
  const { familyId, familyName, region, currency, budgetlimit} = req.body;
  const userId = req.user.userId;
  //const normalizedRole = role ? role.toLowerCase() : '';
  console.log(userId);

  // Validate required fields
  if (!familyName) {
    return res.status(400).json({
      status: 0,
      message: 'Family Name is required',
    });
  }

  // Ensure only parents can create a family
  if (req.user.role!== "parent") {
    return res.status(401).json({
      status: 0,
      message: 'Only parents can create a family',
    });
  }

  try {
    // First, check if the parent already has a family
    const user = await User.findOne({ userId: userId });
    if (user.familyId && user.familyId.length > 0) {
      return res.status(400).json({
        status: 0,
        message: "You already have a family!!", // Prevent parent from creating multiple families
      });
    }

    // Also, check if any children associated with the parent already have a family
    const children = await User.find({ parentId: user.userId, role: 'child' });
    for (let child of children) {
      if (child.familyId && child.familyId.length > 0) {
        return res.status(400).json({
          status: 0,
          message: `One of your children (User ID: ${child.userId}) already has a family!`,
        });
      }
    }

    // Now, create the new family as no one is currently in a family
    const newFamily = new Family({
      familyId,
      familyName,
      region,
      currency,
      budgetlimit: budgetlimit || 0,
      parentId: req.user.userId,
    });

    // Save the new family to the database
    await newFamily.save();

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
      message: 'Family created successfully',
      family: newFamily,
    });
  } catch (err) {
    console.error('Error creating family:', err);
    res.status(500).json({ status: 0, message: 'Internal server error' });
  }
});



// logic is create family, then create guardian, inside guardian - family [family Id1, familyId2], inside child user- family [familyId] and guardian[guardian2,guardian2]
app.post('/create-guardian', async (req, res) => {
  const { userId, name, gender, email, password, role, dob } = req.body;
  const normalizedRole = role ? role.toLowerCase() : '';
  const normalizedgender = gender ? gender.toLowerCase() : '';

  // Only allow 'child' or 'guardian' roles
  if ( normalizedRole !== 'guardian') {
    return res.status(400).json({ message: 'Role must be "guardian"' });
  }

  // Validate required fields
  if ( !name || !email || !password || !dob) {
    return res.status(400).json({ message: 'Please provide all required fields' });
  }

  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({ $or: [{ email },{name}] });
    if (existingUser) {
      return res.status(200).json({ message: 'Email or Name already exists' });
    }
    
    // Create the new user
    const newUser = new User({
      userId,
      name,
      gender:normalizedgender,
      email,
      password,
      role:normalizedRole,
      dob,
      //parentId: userIdFromToken,
    });

    // Save the new user to the database
    await newUser.save();
    res.status(200).json({ message: 'User created successfully', user: newUser });

  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/assign-guardians', verifyParentRole, async (req, res) => {
  const { childId, guardian, familyId } = req.body;

  // Validate required fields
  if (!childId || !guardian || !familyId) {
    return res.status(400).json({ message: 'Please provide childId, guardianIds, and familyId' });
  }

  if (!Array.isArray(guardian)) {
    return res.status(400).json({ message: "guardian should be an array" });
  }


  try {
    // Validate that the childId belongs to a 'child' user
    const child = await User.findOne({userId:childId});
    if (!child || child.role.toLowerCase() !=='child' ) {
      return res.status(400).json({ message: 'Invalid childId or the user is not a child' });
    }

    // Validate that the familyId exists and is associated with a valid family
    const family = await Family.findOne({familyId:familyId});
    if (!family) {
      return res.status(400).json({ message: 'Invalid familyId or the family does not exist' });
    }

    // Validate guardian user roles
    //const guardians = await User.find({ 'userId': { $in: guardian }, role: 'guardian'&&'Guardian' }).select('userId role');
    const guardians = await User.find({ 
      'userId': { $in: guardian }, 
      role: { $in: ['guardian', 'Guardian'].map(r => r.toLowerCase()) }
    }).select('userId role');
    console.log(guardians);
    if (guardians.length !== guardian.length) {
      return res.status(400).json({ message: 'Some guardianIds are invalid or the users are not guardians',guardiansFound: guardians,  // Send back the found guardians for debugging
        guardianIdsReceived: guardian });
    }
    const existingGuardians = child.guardian.filter(guardianId => guardian.includes(guardianId));
    if (existingGuardians.length > 0) {
      return res.status(400).json({ message: 'This guardians are already assigned to this child' });
    }
  
    // Step 2: Add guardians to the child's list using $addToSet to avoid duplicates
    const updateChild = await User.updateOne(
      { 'userId':childId, role: { $regex: '^child$', $options: 'i' } },
      { $addToSet: { guardian: { $each: guardian } } }
    );

    
    
    if (updateChild.modifiedCount === 0) {
      return res.status(400).json({ message: 'Failed to update child guardian list.' });
    }
  
    // Step 3: Add the child to each guardian's list using $addToSet to avoid duplicates
    const guardianUpdates = await Promise.all(guardian.map(async (guardianId) => {
      const guardian = await User.findOne({ userId: guardianId, role: { $regex: '^guardian$', $options: 'i' }  });
      if (!guardian) {
        return { error: `Guardian with userId ${guardian} not found.` };
      }
  
      const updateGuardian = await User.updateOne(
        { userId: guardianId, role: { $regex: '^guardian$', $options: 'i' } },
        { $addToSet: { familyId: familyId } }
      );
  
      if (updateGuardian.modifiedCount === 0) {
        return { error: `Failed to add child to guardian ${guardianId}` };
      }
  
      return { success: `Child successfully added to guardian ${guardianId}` };
    }));
  
    // Check if any guardian update failed
    const errors = guardianUpdates.filter(update => update.error);
    if (errors.length > 0) {
      return res.status(400).json({ message: 'Some guardian updates failed', errors });
    }
  
    // Success response
    res.status(200).json({
      message: 'Guardians assigned successfully',
      //child: child,
      guardians: guardians
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
    console.error('Error assigning guardians:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


app.post('/create-child', verifyParentRole, async (req, res) => {
  const parentId = req.user.userId; // Get the parentId from the decoded token
  console.log('Parent ID:', parentId);

  const { name, gender, email, password, role, dob, Totalpoints } = req.body;
  const normalizedRole = role ? role.toLowerCase() : '';
  const normalizedGender = gender ? gender.toLowerCase() : '';

  // Only allow 'child' role
  if (normalizedRole !== 'child') {
    return res.status(400).json({ message: 'Role must be "child"' });
  }

  // Validate required fields
  if (!name || !password || !dob) {
    return res.status(400).json({ message: 'Please provide all required fields' });
  }

  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({ $or: [{ email }, { name }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or Name already exists' });
    }
    // Find the parent user
    const parent = await User.findOne({ userId: parentId });
    if (!parent) {
      return res.status(400).json({ message: 'Parent not found' });
    }

    // Create the new user (child)
    const newUser = new User({
      name,
      gender: normalizedGender,
      email: email || null,
      password,
      role: 'child',
      dob,
      parentId,
      Totalpoints,
      familyId: parent.familyId,
    });

    // Save the new user to the database
    await newUser.save();
    res.status(200).json({ message: 'User created successfully', user: newUser });

  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error' });
  }
});



app.get('/points',verifyToken, async (req, res) => {
  try {
    // user = req.user; // The user object is set by the authenticate middleware
    //console.log(user);
    const userId =req.user.userId;
    const user = await User.findOne({ userId:userId }) ;
    const task = await Task.findOne({})
    

    // Ensure the user is a child before allowing access to points
    if (user.role !== 'child') {
      return res.status(403).json({ message: 'Access denied, only children can view points' });
    }

    // Return the child's points
    return res.status(200).json({
      status: 1,
      message: 'Points fetched successfully',
      points: user.Totalpoints, // Points stored in the Totalpoints field
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      status: 0,
      message: 'An error occurred while fetching points',
    });
  }
});
app.put('/update', verifyToken, async (req, res) => {
  try {
    // Extract the userId from the decoded token
    const { userId } = req.user; // req.user is populated by verifyToken middleware
    const { name, email, password  } = req.body;

    // Check if the request body is empty (no fields provided)
    if (!name && !email && !password ) {
      return res.status(400).json({ message: 'name , email or password or fields not provided for update' });
    }

    // Check if any other fields are present in the payload (not allowed to be updated)
    const allowedFields = ['name', 'email', 'password'];
    const invalidFields = Object.keys(req.body).filter(field => !allowedFields.includes(field));

    if (invalidFields.length > 0) {
      return res.status(400).json({ message: 'Only Email, name, password are allowed to be updated' });
    }

    // Validate that fields are not empty
    if (email && email.trim() === "") {
      return res.status(400).json({ message: 'Email cannot be empty' });
    }
    if (name && name.trim() === "") {
      return res.status(400).json({ message: 'Name cannot be empty' });
    }
    if (password && password.trim() === "") {
      return res.status(400).json({ message: 'Password cannot be empty' });
    }

    // Find the user by userId extracted from token
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update the fields if they are provided
    if (email) user.email = email;
    if (name) user.name = name;
    if (password) user.password = password;
    

    // Save the updated user document
    await user.save();

    // Respond with success and the updated user data (exclude password for security)
    res.status(200).json({
      message: 'User updated successfully',
      user: {
        userId: user.userId,
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


const verifyParentOrGuardianRole = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];  // Extract token from Authorization header




  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify token and decode it
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Check if the user's role is 'parent' or 'guardian'
    if (req.user.role !== 'parent' && req.user.role !== 'guardian') {
      return res.status(403).json({ message: 'Access denied. Only parents and guardians can create tasks.' });
    }

    next();  // Proceed to the next middleware or route handler
  } catch (err) {
    return res.status(400).json({ message: 'Invalid token.', error: err.message });
  }
};


const token = jwt.sign(
  { userId: User.userId, role: User.role },
  process.env.JWT_SECRET,
  { expiresIn: '1h' }
);


//Tasks

const Task = require('./models/Task'); 
app.post('/create-task', verifyParentOrGuardianRole, async (req, res) => {
  const {
    title,
    description,
    taskId,
    assignedTo,
    associates,
    expectedCompletionDate,
    rewardType,
    fairType,
    fairAmount,
    taskStatus,
    associatedInterestsChild,
    // createdBy,
    fairDistribution,
    penaltyAmount,
    taskPriority,
    paymentStatus,
    schedule,
    taskType,
    completionDate,
    completionTime,
    parentId,
  } = req.body;

  
  if (!title || !assignedTo) {
    return res.status(400).json({ status: 0, message: 'Please provide all required fields' });
  }

  const currentDate = new Date();
  const expectedDate = new Date(expectedCompletionDate);

  if (expectedDate < currentDate) {
    return res.status(400).json({ status: 0, message: 'Expected completion date must be in the future' });
  }

  try {
    // Check if taskId already exists
    console.log('User ID from token:', req.user.userId);

    const existingTask = await Task.findOne({ taskId });
    if (existingTask) {
      return res.status(400).json({ status: 0, message: 'Task ID already exists' });
    }
    const userIdFromToken = req.user.userId;

    // Create the new task
    const newTask = new Task({
      title,
      description,
      taskId,
      assignedTo,
      associates,
      expectedCompletionDate,
      rewardType,
      fairType,
      fairAmount,
      taskStatus,
      associatedInterestsChild,
      createdBy: userIdFromToken,//req.user.userId ,
      fairDistribution,
      penaltyAmount,
      taskPriority,
      paymentStatus,
      schedule,
      taskType,
      completionDate,
      completionTime,
    });

    // Save the new task to the database
    await newTask.save();
    res.status(201).json({ status: 1, message: 'Task created successfully', task: newTask });

  } catch (err) {
    console.error('Error creating task:', err);
    res.status(500).json({ status: 0, message: 'Server error' });
  }
});
//End of task

// Middleware to verify token

const verifyTaskCreatorOrAssigned = (req, res, next) => {
  const { taskId } = req.params;  // Get taskId from URL parameters

  // Find the task by taskId
  Task.findOne({ taskId }).then(task => {
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    // Check if the user is the creator of the task or is assigned to the task
    if (task.createdBy.toString() === req.user.userId || task.assignedTo.toString() === req.user.userId) {
      next();  // User is authorized, proceed to the next middleware or handler
    } else {
      return res.status(403).json({ message: 'Access denied. You are not authorized to view this task.' });
    }
  }).catch(err => {
    return res.status(500).json({ message: 'Error fetching task', error: err.message });
  });
};


app.get('/tasks', async (req, res) => {
  try {
    // Fetch all tasks from the database
    const tasks = await Task.find(); // You can also add query parameters for filtering or pagination

    if (!tasks.length) {
      return res.status(404).json({
        status: 0,
        message: 'No tasks found',
      });
    }

    // Respond with the tasks in JSON format
    res.status(200).json({
      status: 1,
      message: 'Tasks retrieved successfully',
      tasks: tasks,
    });
  } catch (err) {
    console.error('Error fetching tasks:', err);
    res.status(500).json({
      status: 0,
      message: 'Server error while fetching tasks',
    });
  }
});

app.get('/categorize-tasks', verifyToken, async (req, res) => {
  try {
    const user = req.user;  // Get user info from the token

    // Ensure the user has tasks to view
    if (!user) {
      return res.status(400).json({ message: 'User not found or invalid token' });
    }

    // Fetch tasks based on user role (parent or child)
    let tasks = [];
    if (user.role === 'parent') {
      tasks = await Task.find({ createdBy: user.userId, assignedTo: { $exists: true } })
      .select('taskId title expectedCompletionDate taskStatus createdBy fairAmount taskId -_id') // Only include specific fields
      .lean(); 
      
    } else if (user.role === 'child') {
      tasks = await Task.find({ assignedTo: user.userId })
      .select('description title expectedCompletionDate taskStatus assignedTo fairAmount taskId -_id') // Only include specific fields
      .lean(); // 
    } else {
      return res.status(403).json({ message: 'Access denied. Invalid role' });
    }

    // Categorize tasks into active, completed, and expired
    const categorizedTasks = {
      active: [],
      completed: [],
      expired: []
    };

    const currentDate = new Date();

    tasks.forEach(task => {
      if (task.taskStatus === 'completed') {
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
      return res.status(404).json({ message: 'No tasks found for this user' });
    }

    // Return categorized tasks
    res.status(200).json({
      status: 1,
      message: 'Tasks categorized successfully.',
      categorizedTasks: categorizedTasks
    });

  } catch (err) {
    console.error('Error categorizing tasks:', err);
    res.status(500).json({ message: 'Server error while categorizing tasks' });
  }
});




// Route to view a task (only creator or assigned user can view it)
app.get('/view-task/:taskId', verifyToken, verifyTaskCreatorOrAssigned, async (req, res) => {
  const { taskId } = req.params;

  try {
    // Find the task by taskId
    const task = await Task.findOne({ taskId });

    // If no task is found, return an error message
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    // Return the task details
    res.status(200).json({ task });

  } catch (err) {
    console.error('Error fetching task:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

//To view all tasks assigned to specific user
app.get('/view-task/:taskId', verifyToken, verifyTaskCreatorOrAssigned, async (req, res) => {
  const { taskId } = req.params;

  try {
    // Find the task by taskId
    const task = await Task.findOne({ taskId });

    // If no task is found, return an error message
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    // Return the task details
    res.status(200).json({ task });

  } catch (err) {
    console.error('Error fetching task:', err);
    res.status(500).json({ message: 'Server error' });
  }
});



// Middleware to check if the logged-in user is the creator of the task
const verifyTaskCreator = (req, res, next) => {
  const { taskId } = req.params;  // Get taskId from URL parameters

  // Find the task by taskId
  Task.findOne({ taskId }).then(task => {
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    // Check if the logged-in user is the creator of the task
    if (task.createdBy.toString() === req.user.userId) {
      next();  // User is the creator, proceed to the next middleware or handler
    } else {
      return res.status(403).json({ message: 'Access denied. You are not authorized to update this task.' });
    }
  }).catch(err => {
    return res.status(500).json({ message: 'Error fetching task', error: err.message });
  });
};


//To view child Details




//To view user details
app.get('/user-details/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;  // Extract the userId from the request parameters

  try {
    // Find the user by userId in the database
    const user = await User.findOne({ userId: userId });

    // If the user is not found, return an error
    if (!user) {
      return res.status(404).json({ status: 0, message: 'User not found' });
    }

    // Return the user details (excluding sensitive data like password)
    const { password, ...userDetails } = user.toObject();  // Remove the password from the response

    res.status(200).json({
      status: 1,
      message: 'User details retrieved successfully',
      user: userDetails
    });
  } catch (err) {
    console.error('Error retrieving user details:', err);
    res.status(500).json({ status: 0, message: 'Server error' });
  }
});


// Route to update a task (only creator of the task can update it)
app.put('/task-update/:taskId', verifyToken, verifyTaskCreator, async (req, res) => {
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
      return res.status(404).json({ message: 'Task not found' });
    }

    // Update the task with the new data
    task.title = title || task.title;
    task.description = description || task.description;
    task.assignedTo = assignedTo || task.assignedTo;
    task.associates = associates || task.associates;
    task.expectedCompletionDate = expectedCompletionDate || task.expectedCompletionDate;
    task.rewardType = rewardType || task.rewardType;
    task.fairType = fairType || task.fairType;
    task.fairAmount = fairAmount || task.fairAmount;
    task.taskStatus = taskStatus || task.taskStatus;
    task.associatedInterestsChild = associatedInterestsChild || task.associatedInterestsChild;
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
    res.status(200).json({ message: 'Task updated successfully', task });

  } catch (err) {
    console.error('Error updating task:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


app.get('/view-tasks', verifyToken, async (req, res) => {
  try {
    const user = req.user;  // Get user info from the token

    // Fetch tasks based on user role
    let tasks;
    const taskFields = 'taskId title expectedCompletionDate taskStatus fairAmount isExpired';
    if (user.role === 'parent') {
      // Parent can view tasks they created
      tasks = await Task.find({ createdBy: user.userId })
        // Assuming the 'createdBy' field stores parent who created the task
        .select(taskFields + '-_id')
        .populate('assignedTo', 'name email -_id')  // Optional: populate assignedTo field with user details
        .sort({ expectedCompletionDate: 1 });  // Optional: Sort by due date
    } else if (user.role === 'child') {
      // Child can view tasks assigned to them
      tasks = await Task.find({ assignedTo: user.userId })
        .select(taskFields + ' -_id')
        .populate('assignedTo', 'name email -_id')  // Optional: populate assignedTo field with user details
        .sort({ expectedCompletionDate: 1 });  // Optional: Sort by due date
    } else {
      return res.status(403).json({ message: 'Access denied. Invalid role' });
    }

    // If no tasks are found, return an appropriate message
    if (!tasks || tasks.length === 0) {
      return res.status(404).json({ message: `No tasks associated with this ${user.role}` });
    }

    // Return the tasks in the response
    res.status(200).json({
      status: 1,
      message: `${user.role.charAt(0).toUpperCase() + user.role.slice(1)}'s tasks retrieved successfully.`,
      tasks: tasks
    });

  } catch (err) {
    console.error('Error fetching tasks:', err);
    res.status(500).json({ message: 'Server error while fetching tasks' });
  }
});

//Updated view children with fair type and fair amount
app.get('/children', verifyToken, async (req, res) => {
  try {
    const parent = req.user;  // Get user info from the token
    // Ensure the logged-in user is a parent
    if (parent.role !== 'parent') {
      return res.status(403).json({ message: 'Access denied. You must be a parent.' });
    }

    // Fetch children where the parent's userId is the parentId
    const children = await User.find({ parentId: parent.userId })
      .select('userId name email gender dob isActive')  // Select only relevant fields
      .sort({ name: 1 });  // Optional: Sort children by name or any other criteria

    if (children.length === 0) {
      return res.status(404).json({ message: 'No children found for this parent.' });
    }

    // Fetch tasks related to each child (populate the tasks with fairAmount and fairType)
    const childrenWithTasks = await Promise.all(
      children.map(async (child) => {
        // Fetch the tasks related to each child
        const task = await Task.find({ assignedTo: child.userId }) // or Task.find({ childId: child.userId }) depending on your Task schema
          // .select('fairAmount rewardType taskType')  // Select only relevant fields
          .sort({ createdAt: -1 });  // Optional: Sort tasks by creation date or any other criteria

        // Attach tasks to each child
        return {
          ...child.toObject(),  // Convert Mongoose document to plain object
          task  // Add tasks to the child object
        };
      })
    );

    // Return the list of children along with their tasks
    res.status(200).json({
      status: 1,
      message: 'Children retrieved successfully.',
      children: childrenWithTasks
    });

  } catch (err) {
    console.error('Error fetching children:', err);
    res.status(500).json({ message: 'Server error while fetching children' });
  }
});



app.post('/update-device-id', async (req, res) => {
  const { userId, deviceId } = req.body;

  // Validate input
  if (!userId || !deviceId) {
    return res.status(400).json({ message: 'User ID and Device ID are required.' });
  }

  try {
    // Find the user and update the deviceId
    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Update the user's deviceId
    user.deviceId = deviceId;
    await user.save();

    // Send a success response
    return res.status(200).json({ message: 'Device ID updated successfully.' });

  } catch (err) {
    console.error('Error updating device ID:', err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});






app.post('/saveDeviceToken', async (req, res) => {
  const { userId, deviceId } = req.body;

  // Check if both userId and deviceId are provided
  if (!userId || !deviceId) {
    return res.status(400).json({ error: 'userId and deviceId are required' });
  }

  try {
    // Check if the user already exists
    let user = await User.findOne({ userId });

    if (user) {
      // If the user exists, update the deviceId
      user.deviceId = deviceId;
      await user.save();
      return res.status(200).json({ message: 'Device ID updated successfully' });
    } else {
      // If the user does not exist, create a new user with the deviceId
      user = new User({ userId, deviceId });
      await user.save();
      return res.status(201).json({ message: 'Device ID saved successfully' });
    }
  } catch (error) {
    console.error('Error saving device ID:', error);
    return res.status(500).json({ error: 'Failed to save device ID' });
  }
});





// API to view a specific child user
app.get('/view-child/:childId', verifyParentRole, async (req, res) => {
  const { childId } = req.params;  // Extract the childId from URL parameters
  const parentId = req.user.userId;;     // Extract the logged-in parent's userId (from the JWT payload)
 
  
  

  try {
    // Step 1: Find the child by their userId
    const child = await User.findOne({ userId: childId }); // Assuming childId is unique
    
    // Step 2: If child is not found
    if (!child) {
      return res.status(404).json({ status:0, message: 'Child not found' });
    }


    if (child.parentId && child.parentId.toString() !== parentId.toString()) {
      return res.status(403).json({ status:0 , message: 'You are not authorized to view this child' });
    }
    
    // Step 4: If everything is correct, return child details
    return res.status(200).json({
      status:1,
      message: 'Child details retrieved successfully',
      child, // The child data
    });

  } catch (error) {
    console.error('Error fetching child details:', error);
    return res.status(500).json({ status:0 , message: 'Error fetching child details' });
  }
});



// API to register a device ID after user login
app.post('/register-device', verifyToken, async (req, res) => {
  const { deviceId } = req.body;

  if (!deviceId) {
      return res.status(400).json({ message: 'Device ID is required' });
  }

  try {
    // Get the token from the request header
    console.log('Received device ID:', deviceId);  // Log the token


    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Decode the JWT token to get the userId
    //const decoded = jwt.verify(token, 'your-secret-key');  // Replace with your actual secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Fetch the user from the database using the decoded userId
    const user = await User.findOne({ userId: decoded.userId });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
     }

//     // Update the deviceId for the logged-in user
     user.deviceId = deviceId;

//     // Save the updated user document (since `user` is now a Mongoose model instance)
     await user.save();

     res.status(200).json({ message: 'Device registered successfully', deviceId });

  } catch (error) {
     console.error(error);
     res.status(500).json({ message: 'Error registering device' });
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
app.post('/create-rewards',verifyToken, async (req, res) => {
  const userId = req.user.userId; // Get user ID from the authentication middleware (assumes JWT)
  console.log(userId);

  
  
  const user = await User.findOne({ userId });
  if (user.role !=="parent"){
    return res.status(400).json({status:0, message:"Only parents are allowed to create rewards."});
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
    if ( !rewardName || !rewardType || !requiredPoints ||!startDate || !expiryDate || !category ) {
      return res.status(400).json({  status:0 , message: 'Missing required fields: rewardId,rewardName,rewardType,requiredPoints,startDate,expiryDate,category' });
    }
    
    if (new Date(startDate) < currentDate) {
       return res.status(400).json({ error: 'Start Date cannot be in the past.' });
     }

    if (new Date(expiryDate) < currentDate) {
      return res.status(400).json({ status: 0 ,message: 'Provide accurate Expiry Date.' });
    }

    if (new Date(expiryDate)< new Date(startDate)){
      return res.status(400).json({ status:0 ,message:'Provide valid Expiry Date, Expiry Date should be a Date occuring after Start Date.'});
    }
    const rewardId = uuidv4().split('-')[0];

    const newReward = new Reward({
      rewardName,
      rewardType,
      requiredPoints,
      startDate,
      expiryDate,
      category,
      expirationGracePeriod,
      createdBy:user.userId,
      rewardId: rewardId,
  
    });

    console.log('Before saving, rewardId:', newReward.rewardId);

    await newReward.save();

    res.status(201).json({ status:1,
      message: 'Reward created successfully!',
      reward: newReward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create reward' });
  }
});

// POST endpoint to claim a reward
app.post('/rewards/claim/:rewardId',verifyToken,async (req, res) => {
  try {
    const rewardId = req.params.rewardId;
    
    const userId = req.user.userId;

    // Find the user
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).json({ status:0,message: 'User not found' });
    }

    // Find the reward
    const reward = await Reward.findOne({ rewardId });
    
    //reward.claimedBy = req.user.userId;  
    if (!reward) {
      return res.status(404).json({status:0, message: 'Reward not found' });
    }

    // Get the current date
    const currentDate = new Date();

    // Check if the reward's startDate is in the future
    if (reward.startDate > currentDate) {
      return res.status(400).json({ status:0,
        message: 'This reward cannot be claimed yet. The reward starts on ' + reward.startDate.toDateString()
      });
    }

    // Check if the user's total points are greater than or equal to the required points for the reward
    if (user.Totalpoints < reward.requiredPoints) {
      return res.status(400).json({ status:0,
        message: `You need ${reward.requiredPoints - user.Totalpoints} more points to claim this reward.`
      });
    }

    reward.claimedBy.push(user.userId); 

    reward.dateClaimed = new Date();  // Optionally store the date the reward was claimed
    reward.claimStatus ='claimed';

    // Save the updated reward
    await reward.save();

    // Optionally, you can deduct points from the user if claiming the reward costs points
    user.Totalpoints -= reward.requiredPoints;
    await user.save();

    const redemptionDetail = {
      redemptionId: uuidv4(),  // Generate a unique ID for the redemption
      userId: user.userId,
      rewardId: reward.rewardId,
      dateClaimed: new Date(),
      method: 'points',  // Assuming the user is claiming with points (adjust as necessary)
      rewardPaymentStatus: 'pending',
    };
    reward.redemptionDetails.push(redemptionDetail);

    await reward.save();



    // Respond with success
    res.status(200).json({ status:1,
      message: 'Reward claimed successfully!',
      reward: reward
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status:0,message: 'Failed to claim the reward' });
  }
});

// PUT endpoint to edit an existing reward
app.put('/rewards/:rewardId', verifyToken,async (req, res) => {
  const { rewardId } = req.params;  // Get rewardId from the URL params
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
    if (!rewardName && !rewardType && !requiredPoints && !startDate && !expiryDate && !category && !expirationGracePeriod) {
      return res.status(400).json({ status: 0, message: 'No valid fields provided for update.' });
    }



    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });

    
    
    if (!reward) {
      return res.status(404).json({ status: 0, message: 'Reward not found.' });
    }

    if (reward.createdBy !== userId){
      return res.status(403).json({ status:0, message:'You are not authorised to edit this reward.'});
    }

    // If provided, validate and update the startDate and expiryDate
    if (expiryDate) {
      if (new Date(expiryDate) < currentDate) {
        return res.status(400).json({ status: 0, message: 'Provide accurate Expiry Date.' });
      }
      if (new Date(expiryDate) < new Date(startDate || reward.startDate)) {
        return res.status(400).json({ status: 0, message: 'Expiry Date should be after Start Date.' });
      }
    }

    // Update reward with new data (only update provided fields)
    reward.rewardName = rewardName || reward.rewardName;
    reward.rewardType = rewardType || reward.rewardType;
    reward.requiredPoints = requiredPoints || reward.requiredPoints;
    reward.startDate = startDate || reward.startDate;
    reward.expiryDate = expiryDate || reward.expiryDate;
    reward.category = category || reward.category;
    reward.expirationGracePeriod = expirationGracePeriod || reward.expirationGracePeriod;
    //reward.redemptionDetails = redemptionDetails || reward.redemptionDetails

    // Save updated reward to the database
    await reward.save();

    // Return success response with the updated reward data
    res.status(200).json({
      status: 1,
      message: 'Reward updated successfully!',
      reward,
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, error: 'Failed to update reward.' });
  }
});

// API Endpoint to approve a reward
app.put('/rewards/approve/:rewardId', verifyToken, async (req, res) => {
  const { rewardId } = req.params; // Get rewardId from the URL params
  const userId = req.user.userId;
  try {
    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });
    const claimedId = reward.claimedBy;

    //const claimedId = reward.claimedBy[0];
    console.log(claimedId);

    if (!reward) {
      return res.status(404).json({ status: 0, message: 'Reward not found.' });
    }

    

     //Check if the reward is already approved
      if (reward.isApproved) {
      return res.status(400).json({ status: 0, message: 'This reward is already approved.' });
    }

    // Approve the reward by updating the isApproved field
    if(reward.createdBy === userId && reward.claimStatus === "claimed"){
        reward.isApproved = true;
    }

    if(reward.createdBy !== userId){
      return res.status(403).json({ status:0, message:"You are not authorised to approve this reward."});
    }

    if(reward.claimStatus !=="claimed"){
      return res.status(400).json({ status:0, message:"No user has claimed this reward yet."});
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
      redemptionDetail.rewardPaymentStatus = 'complete'; // Assuming the payment status is complete
      redemptionDetail.dateClaimed = new Date(); // Update the date the reward was claimed

    }

      
    await reward.save();
     // After successful update, reset the reward's approval and claim status
     reward.isApproved = false;  // Reset the approval status
     reward.claimStatus = 'unclaimed';  // Set the claim status to 'unclaimed'
     await reward.save();

    // Return success response with the updated reward data
    res.status(200).json({
      status: 1,
      message: 'Reward approved successfully!',
      reward,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, message: 'Failed to approve reward.' });
  }
});

app.put('/rewards/redemption/:rewardId', verifyToken, async (req, res) => {
  const { rewardId } = req.params; // Get rewardId from the URL params
  const userId = req.user.userId;
  
  const {  redemptionId,method, rewardPaymentStatus } = req.body; 
  

  try {
    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });
    const claimedId = reward.claimedBy;
    const isApproved =reward.isApproved;
    const claimStatus =reward.claimStatus;
    const length=reward.redemptionDetails.length;
    const redemptionDetails=reward.redemptionDetails[0];
    

    if (!reward) {
      return res.status(404).json({ status: 0, message: 'Reward not found.' });
    }
    
    if(reward.createdBy !== userId){
      return res.status(403).json({ status:0, message:"You are not authorised to approve this reward."});
    }

    if(reward.isApproved !== true || reward.claimStatus !=="claimed"){
      return res.status(400).json({ status:0 , message:"This reward is not approved or claimed yet"});
    }

    //if(reward.claimStatus !=="claimed"){
      //return res.status(400).json({ status:0, message:"This reward is not claimed yet."});
    //}
    
  if(length ===0){
    if(reward.createdBy === userId && isApproved  && claimStatus==="claimed"){

    
      
      const newRedemptionDetail = {
        redemptionId,
        rewardId:rewardId,
        userId:claimedId,
        method,
        rewardPaymentStatus,
        dateClaimed: Date.now()  // Automatically set the current time
        
      };
      reward.redemptionDetails.push(newRedemptionDetail);
      reward.isApproved = false;
      reward.claimStatus ="unclaimed";
    
    
    }
  }
  
    
  else{
     if(redemptionDetails.userId ===claimedId && redemptionDetails.rewardPaymentStatus ==="pending"){
      reward.isApproved=false;
      reward.claimStatus="unclaimed";
      await reward.save();

     return res.status(400).json({ status:0, message:"You have a redemption with payment status-pending for this user "});

    }

    if(reward.createdBy ===userId &&isApproved && claimStatus==="claimed"){
      const newRedemptionDetail = {
        redemptionId,
        rewardId:rewardId,
        userId:claimedId,
        method,
        rewardPaymentStatus,
        dateClaimed: Date.now()  // Automatically set the current time
        
      };
      reward.redemptionDetails.push(newRedemptionDetail);
      reward.isApproved = false;
      reward.claimStatus ="unclaimed";

    }
  }
  

    await reward.save();

    // Return success response with the updated reward data
    res.status(200).json({
      status: 1,
      message: 'Reward reedemed successfully!',
      reward,
    });
} catch (error) {
    console.error(error);
    res.status(500).json({ status: 0, message: 'Failed to approve reward.' });

  }
});




// Start the server
app.listen(port, () => {
  console.log(`Server running at http://93.127.172.167:${port}`);

});


