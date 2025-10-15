import jwt from "jsonwebtoken";
import User from "../models/User.js";
import rateLimit from "express-rate-limit";
import { verifyAccessToken } from "../utils/generateTokens.js";

// Rate limiter for protected routes
export const protectedRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs for protected routes
  message: { 
    success: false,
    message: "Too many requests from this IP, please try again later." 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting in development
    return process.env.NODE_ENV === 'development';
  }
});

// Main authentication middleware
export const protectRoute = async (req, res, next) => {
  try {
    let token = null;

    // 1. Try to get token from Authorization header (Preferred for mobile/API)
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    // 2. If no header token, try cookies (for web browsers)
    if (!token && req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    // 3. If still no token -> reject
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "Access denied. No authentication token provided.",
        code: "NO_TOKEN"
      });
    }

    // 4. Verify token using utility function (enhanced security)
    let decoded;
    const tokenResult = verifyAccessToken(token);
    
    if (!tokenResult.success) {
      // Handle different token errors
      if (tokenResult.error.includes('expired')) {
        return res.status(401).json({ 
          success: false,
          message: "Access token has expired. Please refresh your token.",
          code: "TOKEN_EXPIRED"
        });
      } else if (tokenResult.error.includes('invalid')) {
        return res.status(401).json({ 
          success: false,
          message: "Invalid authentication token.",
          code: "INVALID_TOKEN"
        });
      } else {
        return res.status(401).json({ 
          success: false,
          message: "Token verification failed.",
          code: "TOKEN_VERIFICATION_FAILED"
        });
      }
    }

    decoded = tokenResult.decoded;

    // 5. Validate token payload
    if (!decoded.userId) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token payload.",
        code: "INVALID_PAYLOAD"
      });
    }

    // 6. Find user in database
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User associated with this token no longer exists.",
        code: "USER_NOT_FOUND"
      });
    }

    // 7. Check if user account is active (optional - add status field to User model)
    if (user.status === 'suspended' || user.status === 'inactive') {
      return res.status(403).json({ 
        success: false,
        message: "Your account has been suspended. Please contact support.",
        code: "ACCOUNT_SUSPENDED"
      });
    }

    // 8. Check token type (ensure it's an access token)
    if (decoded.type !== 'access') {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token type. Access token required.",
        code: "WRONG_TOKEN_TYPE"
      });
    }

    // 9. Attach user to request object
    req.user = user;
    req.token = token;
    req.tokenData = decoded;
    
    // 10. Continue to next middleware
    next();

  } catch (error) {
    console.error("Authentication Error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Internal server error during authentication.",
      code: "AUTH_ERROR"
    });
  }
};

// Alternative: Simple middleware without enhanced token verification (if you prefer basic approach)
export const protectRouteSimple = async (req, res, next) => {
  try {
    let token = null;

    // Get token from header or cookie
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "Access denied. No token provided." 
      });
    }

    // Verify token using basic jwt.verify
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          success: false,
          message: "Access token has expired.",
          code: "TOKEN_EXPIRED"
        });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
          success: false,
          message: "Invalid token.",
          code: "INVALID_TOKEN"
        });
      } else {
        throw error;
      }
    }

    // Find user
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User not found." 
      });
    }

    req.user = user;
    next();

  } catch (error) {
    console.error("Auth Error:", error);
    return res.status(401).json({ 
      success: false,
      message: "Authentication failed." 
    });
  }
};

// Middleware to check if user has completed onboarding
export const requireOnboarding = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      success: false,
      message: "Authentication required.",
      code: "NOT_AUTHENTICATED"
    });
  }

  if (!req.user.isOnBoarded) {
    return res.status(403).json({ 
      success: false,
      message: "Please complete your profile setup first.",
      code: "ONBOARDING_REQUIRED"
    });
  }

  next();
};

// Middleware to check user roles (if you implement role-based access)
export const requireRole = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false,
        message: "Authentication required.",
        code: "NOT_AUTHENTICATED"
      });
    }

    // Convert single role to array
    const allowedRoles = Array.isArray(roles) ? roles : [roles];

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false,
        message: "Insufficient permissions to access this resource.",
        code: "INSUFFICIENT_PERMISSIONS"
      });
    }

    next();
  };
};

// Middleware for soft authentication (user is optional)
export const optionalAuth = async (req, res, next) => {
  try {
    let token = null;

    // Try to get token
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    // If no token, continue without user
    if (!token) {
      req.user = null;
      return next();
    }

    // Try to verify token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
      const user = await User.findById(decoded.userId).select("-password");
      req.user = user;
    } catch (error) {
      // If token is invalid, continue without user
      req.user = null;
    }

    next();
  } catch (error) {
    console.error("Optional Auth Error:", error);
    req.user = null;
    next();
  }
};

// Middleware to validate API key (for server-to-server communication)
export const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      message: "API key is required",
      code: "NO_API_KEY"
    });
  }

  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Invalid API key",
      code: "INVALID_API_KEY"
    });
  }

  next();
};

// Security headers middleware
export const securityHeaders = (req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Content Security Policy (basic)
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  
  next();
};

// Token blacklist middleware (optional - for logout functionality)
const blacklistedTokens = new Set(); // In production, use Redis or database

export const checkTokenBlacklist = (req, res, next) => {
  const token = req.token;
  
  if (token && blacklistedTokens.has(token)) {
    return res.status(401).json({
      success: false,
      message: "Token has been revoked",
      code: "TOKEN_REVOKED"
    });
  }
  
  next();
};

// Function to blacklist a token (call during logout)
export const blacklistToken = (token) => {
  blacklistedTokens.add(token);
  // In production, you'd also store this in Redis with expiration
};

// Admin only middleware
export const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      success: false,
      message: "Authentication required" 
    });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false,
      message: "Admin access required" 
    });
  }

  next();
};

// Middleware to log authentication events
export const logAuthEvent = (event, additionalData = {}) => {
  return (req, res, next) => {
    const logData = {
      event,
      userId: req.user?.id,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      timestamp: new Date().toISOString(),
      ...additionalData
    };
    
    console.log('Auth Event:', JSON.stringify(logData));
    // In production, send to logging service (like Winston, LogRocket, etc.)
    
    next();
  };
};