import { upsertStreamUser } from "../lib/stream.js";
import { generateAccessToken, generateRefreshToken } from "../utils/generateTokens.js";
import User from "../models/User.js";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import validator from "validator";
import crypto from "crypto";
import bcrypt from "bcryptjs";

// Rate limiters for different auth operations
export const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // limit each IP to 3 signup requests per windowMs
  message: { message: "Too many signup attempts, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: { message: "Too many login attempts, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

export const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 refresh requests per windowMs
  message: { message: "Too many refresh token requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Helper function to sanitize input
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return validator.escape(input.trim());
  }
  return input;
};

// Helper function to validate password strength
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasNonalphas = /\W/.test(password);
  
  if (password.length < minLength) {
    return { valid: false, message: "Password must be at least 8 characters long" };
  }
  if (!hasUpperCase) {
    return { valid: false, message: "Password must contain at least one uppercase letter" };
  }
  if (!hasLowerCase) {
    return { valid: false, message: "Password must contain at least one lowercase letter" };
  }
  if (!hasNumbers) {
    return { valid: false, message: "Password must contain at least one number" };
  }
  if (!hasNonalphas) {
    return { valid: false, message: "Password must contain at least one special character" };
  }
  
  return { valid: true };
};

// Helper function to set secure cookies
const setSecureCookie = (res, name, value, maxAge = 7 * 24 * 60 * 60 * 1000) => {
  res.cookie(name, value, {
    maxAge,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    path: "/",
  });
};

// ---------------- SIGNUP ----------------
export async function signUp(req, res) {
  try {
    let { email, password, fullName } = req.body;

    // Sanitize inputs
    email = sanitizeInput(email);
    fullName = sanitizeInput(fullName);

    // Validation
    if (!email || !password || !fullName) {
      return res.status(400).json({ 
        success: false,
        message: "All fields are required" 
      });
    }

    // Validate email
    if (!validator.isEmail(email)) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid email format" 
      });
    }

    // Normalize email
    email = validator.normalizeEmail(email);

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ 
        success: false,
        message: passwordValidation.message 
      });
    }

    // Validate full name
    if (fullName.length < 2 || fullName.length > 50) {
      return res.status(400).json({ 
        success: false,
        message: "Full name must be between 2 and 50 characters" 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: "User with this email already exists" 
      });
    }

    // Generate secure random avatar
    const avatarId = crypto.randomInt(1, 101);
    const randomAvatar = `https://avatar.iran.liara.run/public/${avatarId}.png`;

    // Hash password before saving
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = await User.create({
      email,
      password: hashedPassword,
      fullName,
      profilePic: randomAvatar,
      createdAt: new Date(),
    });

    // Create user in Stream (non-blocking)
    upsertStreamUser({
      id: newUser._id.toString(),
      name: newUser.fullName,
      image: newUser.profilePic || "",
    }).catch(error => {
      console.error(`Error creating Stream user:`, error);
    });

    // Generate tokens
    const accessToken = generateAccessToken(newUser._id);
    const refreshToken = generateRefreshToken(newUser._id);

    // Set refresh token in secure cookie
    setSecureCookie(res, "refreshToken", refreshToken);

    // Remove password from response
    const userResponse = {
      _id: newUser._id,
      email: newUser.email,
      fullName: newUser.fullName,
      profilePic: newUser.profilePic,
      isOnBoarded: newUser.isOnBoarded || false,
      createdAt: newUser.createdAt,
    };

    res.status(201).json({ 
      success: true, 
      user: userResponse, 
      accessToken,
      message: "Account created successfully"
    });

  } catch (error) {
    console.error("Error in signup controller:", error);
    
    // Don't expose internal errors to client
    res.status(500).json({ 
      success: false,
      message: "Internal server error. Please try again later." 
    });
  }
}

// ---------------- LOGIN ----------------
export async function logIn(req, res) {
  try {
    let { email, password } = req.body;

    // Sanitize inputs
    email = sanitizeInput(email);

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Email and password are required" 
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid email format" 
      });
    }

    // Normalize email
    email = validator.normalizeEmail(email);


    // Find user
    const user1 = await User.findOne({ email })
    if (!user1) {
      return res.status(401).json({ 
        success: false,
        message: "User Not Exist" 
      });
    }

    // Find user
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Verify password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Set refresh token in secure cookie
    setSecureCookie(res, "refreshToken", refreshToken);

    // Remove password from response
    const userResponse = {
      _id: user._id,
      email: user.email,
      fullName: user.fullName,
      profilePic: user.profilePic,
      isOnBoarded: user.isOnBoarded || false,
      lastLogin: user.lastLogin,
    };

    res.status(200).json({ 
      success: true, 
      user: userResponse, 
      accessToken,
      message: "Login successful"
    });

  } catch (error) {
    console.error("Error in login controller:", error);
    res.status(500).json({ 
      success: false,
      message: "Internal server error. Please try again later." 
    });
  }
}

// ---------------- LOGOUT ----------------
export function logOut(req, res) {
  try {
    // Clear refresh token cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      path: "/",
    });

    res.status(200).json({ 
      success: true, 
      message: "Logout successful" 
    });
  } catch (error) {
    console.error("Error in logout controller:", error);
    res.status(500).json({ 
      success: false,
      message: "Internal server error" 
    });
  }
}

// ---------------- REFRESH TOKEN ----------------
export async function refreshAccessToken(req, res) {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ 
        success: false,
        message: "No refresh token provided" 
      });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      res.clearCookie("refreshToken");
      return res.status(401).json({ 
        success: false,
        message: "Invalid or expired refresh token" 
      });
    }

    // Find user
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      res.clearCookie("refreshToken");
      return res.status(401).json({ 
        success: false,
        message: "User not found" 
      });
    }

    // Generate new access token
    const accessToken = generateAccessToken(user._id);

    res.json({ 
      success: true, 
      accessToken,
      user: {
        _id: user._id,
        email: user.email,
        fullName: user.fullName,
        profilePic: user.profilePic,
        isOnBoarded: user.isOnBoarded || false,
      }
    });

  } catch (error) {
    console.error("Error in refresh token controller:", error);
    res.clearCookie("refreshToken");
    res.status(401).json({ 
      success: false,
      message: "Invalid or expired refresh token" 
    });
  }
}

// ---------------- ONBOARD ----------------
export async function onboard(req, res) {
  try {
    const userId = req.user._id;
    let { fullName, bio, nativeLanguage, learningLanguage, location, profilePic } = req.body;

    const sanitizeInput1 = (input, isUrl = false) => {
      if (typeof input !== 'string') return input;
      return isUrl ? input.trim() : validator.escape(input.trim());
    };


    // Sanitize inputs
    fullName = sanitizeInput1(fullName);
    bio = sanitizeInput1(bio);
    nativeLanguage = sanitizeInput1(nativeLanguage);
    learningLanguage = sanitizeInput1(learningLanguage);
    location = sanitizeInput1(location);
    profilePic = sanitizeInput1(profilePic, true);


    // Validation
    const missingFields = [];
    if (!fullName) missingFields.push("fullName");
    if (!bio) missingFields.push("bio");
    if (!nativeLanguage) missingFields.push("nativeLanguage");
    if (!learningLanguage) missingFields.push("learningLanguage");
    if (!location) missingFields.push("location");
    if (!profilePic) missingFields.push("profilePic");

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
        missingFields,
      });
    }

    // Additional validation
    if (bio.length < 10 || bio.length > 500) {
      return res.status(400).json({
        success: false,
        message: "Bio must be between 10 and 500 characters"
      });
    }

    // Update user
    const updateUser = await User.findByIdAndUpdate(
      userId,
      { 
        fullName, 
        bio, 
        nativeLanguage, 
        learningLanguage, 
        location,
        profilePic,
        isOnBoarded: true,
        updatedAt: new Date(),
      },
      { new: true, select: "-password" }
    );

    if (!updateUser) {
      return res.status(400).json({ 
        success: false,
        message: "Failed to update user profile" 
      });
    }

    // Update Stream user (non-blocking)
    upsertStreamUser({
      id: updateUser._id.toString(),
      name: updateUser.fullName,
      image: updateUser.profilePic || "",
    }).catch(error => {
      console.error(`Error updating Stream user:`, error);
    });

    res.status(200).json({ 
      success: true, 
      user: updateUser,
      message: "Profile updated successfully"
    });

  } catch (error) {
    console.error("Onboarding error:", error);
    res.status(500).json({ 
      success: false,
      message: "Internal server error. Please try again later." 
    });
  }
}

// ---------------- GET CURRENT USER ----------------
export async function getCurrentUser(req, res) {
  try {
    const user = await User.findById(req.user._id).select("-password");
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    console.error("Error getting current user:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
}