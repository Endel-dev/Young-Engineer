const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('./models/User');
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

//const Redemption = require('./models/Redemption');

//const { sendNotification } = require('./notifications/sendNotification');
// Limit the size of URL-encoded payloads to 5MB
// Limit JSON payload size to 10MB
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Set up rate limiter (e.g., 100 requests per hour)
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});

app.use(limiter);

// Use compression middleware to compress responses
app.use(compression());

app.get('/large-data', (req, res) => {
  const largeData = // large data payload //
  res.json(largeData); // The response will be compressed before being sent to the client
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
app.post('/register', async (req, res) => {
  const { userId, name, gender, email, password, role, dob, isActive, deviceId } = req.body;

  // Ensure only 'parent' role user can register
  if (role !== 'parent') {
    return res.status(400).json({ status: 1, message: 'Only parent role is allowed to register' });
  }

  // Validate required fields
  if (!userId || !name || !email || !password || !dob || !gender) {
    return res.status(400).json({ status: 0, message: 'Please provide all required fields' });
  }

  if (!role) {
    return res.status(400).json({ status: 0, message: 'Please provide role of user' })
  }
  // if (gender === "") {
  //   return res.status(400).json({ status: 0, message: 'Gender cannot be empty' });
  // }


  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({ $or: [{ email }, { userId }] });
    if (existingUser) {
      return res.status(400).json({ status: 0, message: 'Email or User ID already exists' });
    }

    // Create the new user
    const newUser = new User({
      userId,
      name,
      gender,
      email,
      password,
      role,
      dob,
      isActive,
      deviceId
    });

    // Save the new user to the database
    await newUser.save();
    res.status(201).json({ status: 1, message: 'Parent registered successfully', user: newUser });

  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ status: 0, message: 'Server error' });
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

    // Only allow if the role is parent
    if (req.user.role !== 'parent') {
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
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ status: 0, message: 'Please provide email and password' });
  }

  try {
    // Check if user exists by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ status: 0, message: 'Invalid email or password' });


    }

    // Generate a 4-digit OTP
    const otp = Math.floor(1000 + Math.random() * 9000); // Generate a 4-digit number

    // Set up SMTP transporter using provided credentials
    const transporter = nodemailer.createTransport({
      service: 'gmail', // Or use your preferred email service
      auth: {
        user: 'nik.823840@gmail.com', // SMTP email address
        pass: 'jgmqtqislbckeinz', // SMTP password
      },
    });


    const mailOptions = {
      from: 'nik.823840@gmail.com',
      to: email,
      subject: 'Your OTP for Login',
      text: `Your OTP is: ${otp}`, // OTP body message
    };

    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending OTP email:', error);
        return res.status(500).json({ status: 0, message: 'Error sending OTP email' });
      }
      console.log('OTP email sent: ' + info.response);

      // Send response with the OTP (note: you might want to store it temporarily for further validation)
      // res.status(200).json({
      //   status: 1,
      //   message: 'OTP sent successfully to your email',
      //   otp: otp, // Send OTP in the response (for testing or future validation)
      // });
    });


    // Compare the provided password with the stored password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: 0, message: 'Invalid email or password', userId: null,
        role: null
      });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user.userId, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15d' } // Token will expire in 1 hour
    );
    console.log(process.env.JWT_SECRET);

    // Send response with token
    res.status(200).json({
      status: 1,
      message: 'Login successful',
      otpstatus: 'OTP Send successfully',
      otp: otp,
      token: token,
      userId: user.userId,  // Include the userId directly in the response
      role: user.role,  // Send the token to be used for subsequent authenticated requests

      //   //userId: user.userId,
      name: user.name,
      // //role: user.role,
      // email: user.email,
      //   //role:user.role,

    });
  } catch (err) {
    console.error('Error logging in user:', err);
    res.status(500).json({ status: 0, message: 'Server error' });
  }
});


// POST /create-user (Only parent can create child or guardian)
app.post('/create-user', verifyParentRole, async (req, res) => {
  const { userId, name, gender, email, password, role, dob, Totalpoints } = req.body;

  // Only allow 'child' or 'guardian' roles
  if (role !== 'child' && role !== 'guardian') {
    return res.status(400).json({ message: 'Role must be either "child" or "guardian"' });
  }

  // Validate required fields
  if (!userId || !name || !email || !password || !dob) {
    return res.status(400).json({ message: 'Please provide all required fields' });
  }

  try {
    // Check if email or userId already exists
    const existingUser = await User.findOne({ $or: [{ email }, { userId }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or User ID already exists' });
    }
    const userIdFromToken = req.user.userId;
    // Create the new user
    const newUser = new User({
      userId,
      name,
      gender,
      email,
      password,
      role,
      dob,
      parentId: userIdFromToken,
      Totalpoints
    });

    // Save the new user to the database
    await newUser.save();
    res.status(201).json({ message: 'User created successfully', user: newUser });

  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Server error' });
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
    // if (password) {
    //   // Hash the new password before saving
    //   const salt = await bcrypt.genSalt(10);
    //   user.password = await bcrypt.hash(password, salt);
    // }
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

// Route to get tasks for the logged-in user
app.get('/active-tasks', verifyToken, async (req, res) => {
  try {
    const user = req.user;  // Get user info from the token

    // Fetch tasks based on user role
    let tasks;
    const taskFields = 'taskId title expectedCompletionDate taskStatus fairAmount isExpired';
    if (user.role === 'parent') {
      // Parent can view tasks they created
      tasks = await Task.find({ createdBy: user.userId, expectedCompletionDate: { $gte: new Date() } })
        // Assuming the 'createdBy' field stores parent who created the task
        .select(taskFields + '-_id')
        .populate('assignedTo', 'name email -_id')  // Optional: populate assignedTo field with user details
        .sort({ expectedCompletionDate: 1 });  // Optional: Sort by due date
    } else if (user.role === 'child') {
      // Child can view tasks assigned to them
      tasks = await Task.find({ assignedTo: user.userId, expectedCompletionDate: { $gte: new Date() } })
        .select(taskFields + ' -_id')
        .populate('assignedTo', 'name email -_id')  // Optional: populate assignedTo field with user details
        .sort({ expectedCompletionDate: 1 });  // Optional: Sort by due date
    } else {
      return res.status(403).json({ message: 'Access denied. Invalid role' });
    }

    // If no tasks are found, return an appropriate message
    if (!tasks || tasks.length === 0) {
      return res.status(404).json({ message: `No tasks found for this ${user.role}` });
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
          .select('fairAmount rewardType')  // Select only relevant fields
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

  // Find the user
  //const user = await User.findById(userId);
  const user = await User.findOne({ userId });
  if (user.role !=="parent"){
    return res.status(400).json({status:0, message:"Only parents are allowed to create rewards."});
  }
  const {
    rewardId,
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

    
    // Validation of required fields
    if (!rewardId || !rewardName || !rewardType || !requiredPoints ||!startDate || !expiryDate || !category ) {
      return res.status(400).json({  status:0 , message: 'Missing required fields: rewardId,rewardName,rewardType,requiredPoints,startDate,expiryDate,category' });
    }
    
    // Check if the rewardId already exists in the database
    const existingReward = await Reward.findOne({ rewardId });
    
    if (existingReward) {
      return res.status(400).json({ status:0, message: 'Reward ID already exists. Please provide a unique Reward ID.' });
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

    // Create a new reward document
    const newReward = new Reward({
      rewardId,
      rewardName,
      rewardType,
      requiredPoints,
      startDate,
      expiryDate,
      category,
      expirationGracePeriod,
      createdBy:user.userId,

  
    });

    // Save the new reward to the database
    await newReward.save();

    // Send a success response
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
    
    const userId = req.user.userId; // Get user ID from the authentication middleware (assumes JWT)
    //console.log(userId);

    // Find the user
    //const user = await User.findById(userId);
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

    // Check if the reward has already been claimed (optional)
    // if (reward.claimedBy.includes(userId)){
    //   return res.status(400).json({status:0 , message: 'This reward has already been claimed.' });

    // }

    // If eligible, update the reward's claimedBy field with the user's ID
    reward.claimedBy = user.userId;
    //reward.claimedBy.push(userId); 

    reward.dateClaimed = new Date();  // Optionally store the date the reward was claimed
    reward.claimStatus ='claimed';

    // Save the updated reward
    await reward.save();

    // Optionally, you can deduct points from the user if claiming the reward costs points
    user.Totalpoints -= reward.requiredPoints;
    await user.save();

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
  
  //const {  method, rewardPaymentStatus } = req.body; 
  //console.log(userId);


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
        //const newRedemptionDetail = {
          //rewardId:rewardId,
          //userId:claimedId,
          //method,
          //rewardPaymentStatus,
          //dateClaimed: Date.now()  // Automatically set the current time
//};

        //if (newRedemptionDetail.userId === claimedId){
          //return res.status(400).json({ status:0, message:"You already have redemption details for this user."});
        //}
        
    
        // 4. Push the new redemption details into the redemptionDetails array
        //reward.redemptionDetails.push(newRedemptionDetail);
    
    }

  

    if(reward.createdBy !== userId){
      return res.status(403).json({ status:0, message:"You are not authorised to approve this reward."});
    }

    if(reward.claimStatus !=="claimed"){
      return res.status(400).json({ status:0, message:"No user has claimed this reward yet."});
    }

    // Save the updated reward to the database
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
  //console.log(userId);

  try {
    // Find the existing reward by rewardId
    const reward = await Reward.findOne({ rewardId });
    const claimedId = reward.claimedBy;
    const isApproved =reward.isApproved;
    const claimStatus =reward.claimStatus;
    const length=reward.redemptionDetails.length;
    console.log(length);
    const redemptionDetails=reward.redemptionDetails[0];
    
    
    
    
    //console.log(redemptionDetails.rewardPaymentStatus);
    
    
    
    //const claimedId = reward.claimedBy[0];
    console.log(claimedId);
    

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
    
    //else(redemptionDetails.userId ===claimedId && redemptionDetails.rewardPaymentStatus ==="pending"){
         //reward.isApproved=false;
         //reward.claimStatus="unclaimed";
    

      //(newRedemptionDetail.userId === claimedId && ){
       // return res.status(400).json({ status:0, message:"You already have the entry"});
      //}
    
    }
  }
  
  

    // if(reward.createdBy === userId && isApproved  && claimStatus==="claimed" ){

    
      
    //   const newRedemptionDetail = {
    //     redemptionId,
    //     rewardId:rewardId,
    //     userId:claimedId,
    //     method,
    //     rewardPaymentStatus,
    //     dateClaimed: Date.now()  // Automatically set the current time
        
    //   };
    //   reward.redemptionDetails.push(newRedemptionDetail);
    //   reward.isApproved = false;
    //   reward.claimStatus ="unclaimed";
    // }
    
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
  

    

    //if(reward.createdBy !==userId || isApproved || claimStatus !=="claimed"){
      //return res.status(400).json({ status:0, message:"Error Occured"});
    //} 

    
    //if(reward.redemptionDetails[0].rewardPaymentStatus ==="complete"){
      //return res.status(400).json({ status:0, message:'This reward is already been redeemed'});
    //}

    //if(reward.RedemptionDetails[0].rewardPaymentStatus ==='complete'){
      //reward.isApproved ="false",
      //reward.claimStatus ="unclaimed"
//}

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
  console.log(`Server running at http://192.168.3.17:${port}`);

});


