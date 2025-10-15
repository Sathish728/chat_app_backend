import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Validate environment variables
const validateSecrets = () => {
  if (!process.env.JWT_SECRET_KEY || process.env.JWT_SECRET_KEY.length < 32) {
    throw new Error('JWT_SECRET_KEY must be at least 32 characters long');
  }
  if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
    throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
  }
};

// Generate cryptographically secure random string
export const generateSecureSecret = (length = 64) => {
  return crypto.randomBytes(length).toString('base64');
};

export const generateAccessToken = (userId) => {
  validateSecrets();
  
  const payload = {
    userId: userId.toString(),
    type: 'access',
    iat: Math.floor(Date.now() / 1000),
  };

  const options = {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRY || '15m',
    issuer: process.env.JWT_ISSUER || 'your-app-name',
    audience: process.env.JWT_AUDIENCE || 'your-app-users',
    algorithm: 'HS256'
  };

  return jwt.sign(payload, process.env.JWT_SECRET_KEY, options);
};

export const generateRefreshToken = (userId) => {
  validateSecrets();
  
  const payload = {
    userId: userId.toString(),
    type: 'refresh',
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(), // Unique token ID for revocation
  };

  const options = {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY || '7d',
    issuer: process.env.JWT_ISSUER || 'your-app-name',
    audience: process.env.JWT_AUDIENCE || 'your-app-users',
    algorithm: 'HS256'
  };

  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, options);
};

// Verify and decode access token
export const verifyAccessToken = (token) => {
  validateSecrets();
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY, {
      issuer: process.env.JWT_ISSUER || 'your-app-name',
      audience: process.env.JWT_AUDIENCE || 'your-app-users',
      algorithms: ['HS256']
    });
    
    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }
    
    return { success: true, decoded };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Verify and decode refresh token
export const verifyRefreshToken = (token) => {
  validateSecrets();
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      issuer: process.env.JWT_ISSUER || 'your-app-name',
      audience: process.env.JWT_AUDIENCE || 'your-app-users',
      algorithms: ['HS256']
    });
    
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }
    
    return { success: true, decoded };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Generate secure random password (for temporary passwords, etc.)
export const generateSecurePassword = (length = 12) => {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  const allChars = lowercase + uppercase + numbers + symbols;
  
  let password = '';
  
  // Ensure at least one character from each category
  password += lowercase[crypto.randomInt(0, lowercase.length)];
  password += uppercase[crypto.randomInt(0, uppercase.length)];
  password += numbers[crypto.randomInt(0, numbers.length)];
  password += symbols[crypto.randomInt(0, symbols.length)];
  
  // Fill the rest randomly
  for (let i = 4; i < length; i++) {
    password += allChars[crypto.randomInt(0, allChars.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => crypto.randomInt(-1, 2)).join('');
};

// Hash sensitive data (for storing API keys, etc.)
export const hashData = (data, salt = null) => {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(data, actualSalt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt: actualSalt };
};

// Verify hashed data
export const verifyHashedData = (data, hash, salt) => {
  const testHash = crypto.pbkdf2Sync(data, salt, 10000, 64, 'sha512').toString('hex');
  return testHash === hash;
};

// Generate CSRF token
export const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Verify CSRF token (simple implementation)
export const verifyCSRFToken = (token, expectedToken) => {
  if (!token || !expectedToken) return false;
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken));
};

// Generate API key
export const generateAPIKey = () => {
  const prefix = 'ak_'; // API key prefix
  const randomPart = crypto.randomBytes(32).toString('hex');
  return prefix + randomPart;
};