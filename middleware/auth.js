const jwt = require('jsonwebtoken');
const User = require('../models/User');


// Middleware to verify token and extract user information
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', ''); // Get token from Authorization header

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);  // Verify the token
    req.user = decoded;  // Attach user data (including role) to the request
    next();  // Proceed to the next middleware/route handler
  } catch (error) {
    res.status(400).json({ message: 'Invalid or expired token.' });
  }
};

// Middleware to check if user has 'parent' role
const checkParentRole = (req, res, next) => {
  if (req.user.role !== 'parent') {
    return res.status(403).json({ message: 'Only parents can create child or guardian users.' });
  }
  next();  // User has 'parent' role, proceed to the next middleware/route handler
};

module.exports = { authenticate, checkParentRole };


// Middleware to check if the user is a parent or guardian
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


