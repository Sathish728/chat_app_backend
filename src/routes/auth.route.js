// routes/auth.route.js - Complete implementation with all middleware
import express from 'express';
import { 
  logIn, 
  logOut, 
  signUp, 
  onboard, 
  refreshAccessToken,
  getCurrentUser,
  signupLimiter,
  loginLimiter,
  refreshLimiter
} from '../controllers/auth.controller.js';

import { 
  protectRoute,                    // Main auth middleware
  protectRouteSimple,              // Simpler version if you prefer
  requireOnboarding,               // Requires completed onboarding
  requireRole,                     // Role-based access
  optionalAuth,                    // Soft auth (user optional)
  validateApiKey,                  // API key validation
  securityHeaders,                 // Security headers
  protectedRouteLimiter,           // Rate limiting for protected routes
  checkTokenBlacklist,             // Token blacklist checking
  requireAdmin,                    // Admin only access
  logAuthEvent                     // Auth event logging
} from '../middleware/auth.middleware.js';

const router = express.Router();

// Apply security headers to all auth routes
router.use(securityHeaders);

// ================== PUBLIC ROUTES ==================
// These don't require authentication

router.post("/signup", 
  // signupLimiter,                           // Rate limit signups
  logAuthEvent('signup_attempt'),          // Log signup attempts
  signUp
);

router.post("/login", 
  // loginLimiter,                            // Rate limit logins
  logAuthEvent('login_attempt'),           // Log login attempts
  logIn
);

router.post("/logout", 
  optionalAuth,                            // User might or might not be logged in
  logAuthEvent('logout_attempt'),          // Log logout attempts
  logOut
);

router.get("/refresh", 
  refreshLimiter,                          // Rate limit refresh requests
  logAuthEvent('token_refresh_attempt'),   // Log refresh attempts
  refreshAccessToken
);

// Health check endpoint
router.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Auth service is healthy",
    timestamp: new Date().toISOString()
  });
});

// ================== PROTECTED ROUTES ==================
// Apply rate limiting to all protected routes
router.use(protectedRouteLimiter);

// Basic protected route - requires authentication only
router.get("/me", 
  protectRoute,                            // Requires valid access token
  logAuthEvent('profile_access'),          // Log profile access
  getCurrentUser
);

// Protected route with token blacklist checking
router.get("/profile", 
  protectRoute,                            // Requires authentication
  checkTokenBlacklist,                     // Check if token is blacklisted
  logAuthEvent('detailed_profile_access'), // Log access
  (req, res) => {
    res.status(200).json({
      success: true,
      user: req.user,
      tokenData: req.tokenData,             // Available from protectRoute
      message: "Profile retrieved successfully"
    });
  }
);

// Onboarding - requires auth but not completed onboarding
router.post("/onboarding", 
  protectRoute,                            // Must be logged in
  logAuthEvent('onboarding_attempt'),      // Log onboarding attempts
  onboard
);

// Routes that require completed onboarding
router.get("/dashboard", 
  protectRoute,                            // Must be authenticated
  requireOnboarding,                       // Must have completed onboarding
  logAuthEvent('dashboard_access'),        // Log dashboard access
  (req, res) => {
    res.status(200).json({
      success: true,
      user: req.user,
      message: "Welcome to your dashboard!"
    });
  }
);

// ================== ROLE-BASED ROUTES ==================
// Routes that require specific roles (if you implement user roles)

// Admin only routes
router.get("/admin/users", 
  protectRoute,                            // Must be authenticated
  requireAdmin,                            // Must be admin
  logAuthEvent('admin_users_access'),      // Log admin access
  (req, res) => {
    res.status(200).json({
      success: true,
      message: "Admin users list",
      // Return users list for admin
    });
  }
);

// Multiple roles allowed
router.get("/moderator/reports", 
  protectRoute,                                    // Must be authenticated
  requireRole(['admin', 'moderator']),             // Must be admin or moderator
  logAuthEvent('moderator_reports_access'),        // Log access
  (req, res) => {
    res.status(200).json({
      success: true,
      message: "Moderator reports",
      userRole: req.user.role
    });
  }
);

// ================== API KEY ROUTES ==================
// Server-to-server communication routes

router.post("/server/sync-users", 
  validateApiKey,                          // Requires valid API key
  logAuthEvent('server_sync_attempt'),     // Log server sync
  (req, res) => {
    res.status(200).json({
      success: true,
      message: "Server sync completed"
    });
  }
);

// ================== OPTIONAL AUTH ROUTES ==================
// Routes where user authentication is optional

router.get("/public-profile/:userId", 
  optionalAuth,                            // User login is optional
  (req, res) => {
    const isOwnProfile = req.user?.id === req.params.userId;
    
    res.status(200).json({
      success: true,
      profile: {
        // Return different data based on whether user is logged in
        // and whether it's their own profile
      },
      isOwnProfile,
      isAuthenticated: !!req.user
    });
  }
);

// ================== PAYMENT ROUTES ==================
// Routes for payment processing (requires completed onboarding)

router.post("/payment/create-intent", 
  protectRoute,                            // Must be authenticated
  requireOnboarding,                       // Must have completed profile
  logAuthEvent('payment_intent_created'),  // Log payment attempts
  (req, res) => {
    // Payment processing logic here
    res.status(200).json({
      success: true,
      message: "Payment intent created",
      userId: req.user._id
    });
  }
);

router.post("/payment/webhook", 
  validateApiKey,                          // Webhook requires API key
  express.raw({type: 'application/json'}), // Raw body for webhook verification
  (req, res) => {
    // Webhook processing logic
    res.status(200).json({ received: true });
  }
);

// ================== ERROR HANDLING ==================
// Catch-all for undefined auth routes
router.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Auth route ${req.originalUrl} not found`,
    availableRoutes: [
      'POST /api/auth/signup',
      'POST /api/auth/login',
      'POST /api/auth/logout',
      'GET  /api/auth/refresh',
      'GET  /api/auth/me',
      'POST /api/auth/onboarding',
      'GET  /api/auth/dashboard',
      // Add other routes as needed
    ]
  });
});

export default router;