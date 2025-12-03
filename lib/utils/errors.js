/**
 * Centralized error messages and error codes for mbkauthe
 * Provides consistent, user-friendly error messages across the application
 */

// Error codes for different scenarios
export const ErrorCodes = {
  // Authentication errors (600-699)
  INVALID_CREDENTIALS: 601,
  USER_NOT_FOUND: 602,
  INCORRECT_PASSWORD: 603,
  ACCOUNT_INACTIVE: 604,
  APP_NOT_AUTHORIZED: 605,
  
  // 2FA errors (700-799)
  TWO_FA_REQUIRED: 701,
  TWO_FA_INVALID_TOKEN: 702,
  TWO_FA_NOT_CONFIGURED: 703,
  TWO_FA_EXPIRED: 704,
  
  // Session errors (800-899)
  SESSION_EXPIRED: 801,
  SESSION_INVALID: 802,
  SESSION_NOT_FOUND: 803,
  
  // Authorization errors (900-999)
  INSUFFICIENT_PERMISSIONS: 901,
  ROLE_NOT_ALLOWED: 902,
  
  // Input validation errors (1000-1099)
  MISSING_REQUIRED_FIELD: 1001,
  INVALID_USERNAME_FORMAT: 1002,
  INVALID_PASSWORD_LENGTH: 1003,
  INVALID_TOKEN_FORMAT: 1004,
  
  // Rate limiting (1100-1199)
  RATE_LIMIT_EXCEEDED: 1101,
  
  // Server errors (1200-1299)
  INTERNAL_SERVER_ERROR: 1201,
  DATABASE_ERROR: 1202,
  CONFIGURATION_ERROR: 1203,
  
  // GitHub OAuth errors (1300-1399)
  GITHUB_NOT_LINKED: 1301,
  GITHUB_AUTH_FAILED: 1302,
  OAUTH_STATE_MISMATCH: 1303,
};

// User-friendly error messages
export const ErrorMessages = {
  // Authentication
  [ErrorCodes.INVALID_CREDENTIALS]: {
    message: "Invalid username or password",
    userMessage: "The username or password you entered is incorrect. Please try again.",
    hint: "Check your spelling and make sure Caps Lock is off"
  },
  [ErrorCodes.USER_NOT_FOUND]: {
    message: "User account not found",
    userMessage: "We couldn't find an account with that username.",
    hint: "Please check the username and try again"
  },
  [ErrorCodes.INCORRECT_PASSWORD]: {
    message: "Incorrect password",
    userMessage: "The password you entered is incorrect.",
    hint: "Make sure you're using the correct password for this account"
  },
  [ErrorCodes.ACCOUNT_INACTIVE]: {
    message: "Account is inactive",
    userMessage: "Your account has been deactivated.",
    hint: "Please contact your administrator to reactivate your account"
  },
  [ErrorCodes.APP_NOT_AUTHORIZED]: {
    message: "Not authorized for this application",
    userMessage: "You don't have permission to access this application.",
    hint: "Contact your administrator if you believe this is an error"
  },
  
  // 2FA
  [ErrorCodes.TWO_FA_REQUIRED]: {
    message: "Two-factor authentication required",
    userMessage: "Please enter your 6-digit authentication code.",
    hint: "Check your authenticator app for the code"
  },
  [ErrorCodes.TWO_FA_INVALID_TOKEN]: {
    message: "Invalid 2FA code",
    userMessage: "The authentication code you entered is incorrect.",
    hint: "Make sure you're using the latest code from your authenticator app"
  },
  [ErrorCodes.TWO_FA_NOT_CONFIGURED]: {
    message: "2FA not configured",
    userMessage: "Two-factor authentication is not set up for your account.",
    hint: "Contact your administrator to enable 2FA"
  },
  [ErrorCodes.TWO_FA_EXPIRED]: {
    message: "2FA code expired",
    userMessage: "The authentication code has expired.",
    hint: "Please use a fresh code from your authenticator app"
  },
  
  // Session
  [ErrorCodes.SESSION_EXPIRED]: {
    message: "Session expired",
    userMessage: "Your session has expired. Please log in again.",
    hint: "This happens when you've been inactive for too long"
  },
  [ErrorCodes.SESSION_INVALID]: {
    message: "Invalid session",
    userMessage: "Your session is no longer valid. Please log in again.",
    hint: "This may happen if you logged in from another device"
  },
  [ErrorCodes.SESSION_NOT_FOUND]: {
    message: "Session not found",
    userMessage: "Please log in to continue.",
    hint: "You need to be logged in to access this page"
  },
  
  // Authorization
  [ErrorCodes.INSUFFICIENT_PERMISSIONS]: {
    message: "Insufficient permissions",
    userMessage: "You don't have permission to perform this action.",
    hint: "Contact your administrator if you need access"
  },
  [ErrorCodes.ROLE_NOT_ALLOWED]: {
    message: "Role not allowed",
    userMessage: "Your account role doesn't have access to this feature.",
    hint: "This feature requires a different permission level"
  },
  
  // Input Validation
  [ErrorCodes.MISSING_REQUIRED_FIELD]: {
    message: "Required field missing",
    userMessage: "Please fill in all required fields.",
    hint: "Username and password are required"
  },
  [ErrorCodes.INVALID_USERNAME_FORMAT]: {
    message: "Invalid username format",
    userMessage: "Please enter a valid username.",
    hint: "Username must be 1-255 characters"
  },
  [ErrorCodes.INVALID_PASSWORD_LENGTH]: {
    message: "Invalid password length",
    userMessage: "Password must be at least 8 characters long.",
    hint: "Please use a password with 8 or more characters"
  },
  [ErrorCodes.INVALID_TOKEN_FORMAT]: {
    message: "Invalid token format",
    userMessage: "Please enter a valid 6-digit code.",
    hint: "The code should be 6 numbers from your authenticator app"
  },
  
  // Rate Limiting
  [ErrorCodes.RATE_LIMIT_EXCEEDED]: {
    message: "Too many requests",
    userMessage: "Too many attempts. Please try again later.",
    hint: "Wait a few minutes before trying again"
  },
  
  // Server Errors
  [ErrorCodes.INTERNAL_SERVER_ERROR]: {
    message: "Internal server error",
    userMessage: "Something went wrong on our end.",
    hint: "Please try again later or contact support if the problem persists"
  },
  [ErrorCodes.DATABASE_ERROR]: {
    message: "Database error",
    userMessage: "We're experiencing technical difficulties.",
    hint: "Please try again in a few moments"
  },
  [ErrorCodes.CONFIGURATION_ERROR]: {
    message: "Configuration error",
    userMessage: "The service is temporarily unavailable.",
    hint: "Please contact your administrator"
  },
  
  // GitHub OAuth
  [ErrorCodes.GITHUB_NOT_LINKED]: {
    message: "GitHub account not linked",
    userMessage: "Your GitHub account is not linked to any user account.",
    hint: "Please link your GitHub account in your profile settings first"
  },
  [ErrorCodes.GITHUB_AUTH_FAILED]: {
    message: "GitHub authentication failed",
    userMessage: "We couldn't authenticate you with GitHub.",
    hint: "Please try again or use username/password login"
  },
  [ErrorCodes.OAUTH_STATE_MISMATCH]: {
    message: "OAuth state mismatch",
    userMessage: "Authentication verification failed.",
    hint: "Please try logging in again"
  },
};

/**
 * Get error details by error code
 * @param {number} errorCode - The error code
 * @param {Object} customData - Optional custom data to merge with error
 * @returns {Object} Error details with message, userMessage, and hint
 */
export function getErrorByCode(errorCode, customData = {}) {
  const errorDetails = ErrorMessages[errorCode] || {
    message: "An error occurred",
    userMessage: "An unexpected error occurred. Please try again.",
    hint: "Contact support if this problem continues"
  };
  
  return {
    errorCode,
    ...errorDetails,
    ...customData
  };
}

/**
 * Create a standardized error response
 * @param {number} statusCode - HTTP status code
 * @param {number} errorCode - Application error code
 * @param {Object} customData - Optional custom data
 * @returns {Object} Standardized error response
 */
export function createErrorResponse(statusCode, errorCode, customData = {}) {
  const error = getErrorByCode(errorCode, customData);
  
  return {
    success: false,
    statusCode,
    errorCode: error.errorCode,
    message: error.userMessage || error.message,
    hint: error.hint,
    timestamp: new Date().toISOString(),
    ...customData
  };
}

/**
 * Log error with consistent format
 * @param {string} context - Context where error occurred
 * @param {number} errorCode - Error code
 * @param {Object} additionalInfo - Additional info to log
 */
export function logError(context, errorCode, additionalInfo = {}) {
  const error = getErrorByCode(errorCode);
  console.error(`[mbkauthe] ${context}:`, {
    errorCode,
    message: error.message,
    ...additionalInfo,
    timestamp: new Date().toISOString()
  });
}

export default {
  ErrorCodes,
  ErrorMessages,
  getErrorByCode,
  createErrorResponse,
  logError
};
