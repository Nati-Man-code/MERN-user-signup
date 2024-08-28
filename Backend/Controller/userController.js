// controllers/authController.js
const User = require('../Models/userModel.js');
const jwt = require('jsonwebtoken');

exports.registerUser = async (req, res) => {
  const { name, email, password, oauthProvider, oauthId } = req.body;

  const userExists = await User.findOne({ email });

  if (userExists) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const user = await User.create({
    name,
    email,
    password,
    oauthProvider,
    oauthId,
  });

  if (user) {
    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      accessToken: generateToken(user._id, '10m'),
      refreshToken: generateToken(user._id, '7d'),
    });
  } else {
    res.status(400).json({ message: 'Invalid user data' });
  }
};

exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (user && (await user.matchPassword(password))) {
    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      accessToken: generateToken(user._id, '10m'),
      refreshToken: generateToken(user._id, '7d'),
    });
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
};

exports.getUserProfile = async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
    });
  } else {
    res.status(404).json({ message: 'User not found' });
  }
};
exports.verifyToken = (req, res) => {
    try {
      const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);
      res.json({ valid: true, userId: decoded.id });
    } catch (error) {
      res.status(401).json({ valid: false, message: 'Invalid token' });
    }
  };
  
  exports.refreshToken = async (req, res) => {
    const { token } = req.body;
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
      const newAccessToken = generateToken(decoded.id, '10m');
      res.json({ accessToken: newAccessToken });
    } catch (error) {
      res.status(401).json({ message: 'Invalid refresh token' });
    }
  };