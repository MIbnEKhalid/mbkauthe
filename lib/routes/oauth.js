import express from "express";
import passport from 'passport';
import GitHubStrategy from 'passport-github2';
import GoogleStrategy from 'passport-google-oauth20';
import csurf from 'csurf';
import rateLimit from 'express-rate-limit';
import { dblogin } from "../database/pool.js";
import { mbkautheVar } from "../config/index.js";
import { renderError } from "../utils/response.js";
import { checkTrustedDevice, completeLoginProcess } from "./auth.js";

const router = express.Router();

// CSRF protection middleware
const csrfProtection = csurf({ cookie: true });

// Rate limiter for OAuth routes
const createOAuthLimit = (provider) => rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: `Too many ${provider} login attempts, please try again later`,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip validation of X-Forwarded-For header to prevent errors
  validate: {
    xForwardedForHeader: false,
    trustProxy: false
  },
  // Use a more robust key generator that handles proxy scenarios
  keyGenerator: (req) => {
    // Use IP from connection if available, otherwise fallback to a default
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
  }
});

const GitHubOAuthLimit = createOAuthLimit('GitHub');
const GoogleOAuthLimit = createOAuthLimit('Google');

// Common OAuth strategy handler
const createOAuthStrategy = async (provider, profile, done) => {
  try {
    console.log(`[mbkauthe] ${provider} OAuth callback for user: ${profile.emails?.[0]?.value || profile.id}`);
    
    const isGitHub = provider === 'GitHub';
    const tableName = isGitHub ? 'user_github' : 'user_google';
    const idField = isGitHub ? 'github_id' : 'google_id';
    const queryName = isGitHub ? 'github-login-get-user' : 'google-login-get-user';
    
    // Check if this OAuth account is linked to any user
    const oauthUser = await dblogin.query({
      name: queryName,
      text: `SELECT ug.*, u."UserName", u."Role", u."Active", u."AllowedApps", u."id" FROM ${tableName} ug JOIN "Users" u ON ug.user_name = u."UserName" WHERE ug.${idField} = $1`,
      values: [profile.id]
    });

    if (oauthUser.rows.length === 0) {
      const error = new Error(`${provider} account not linked to any user`);
      error.code = `${provider.toUpperCase()}_NOT_LINKED`;
      return done(error);
    }

    const user = oauthUser.rows[0];

    // Check if the user account is active
    if (!user.Active) {
      const error = new Error('Account is inactive');
      error.code = 'ACCOUNT_INACTIVE';
      return done(error);
    }

    // Check if user is authorized for this app
    if (user.Role !== "SuperAdmin") {
      const allowedApps = user.AllowedApps;
      if (!allowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        const error = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
        error.code = 'NOT_AUTHORIZED';
        return done(error);
      }
    }

    // Return user data for login
    const userData = {
      id: user.id,
      username: user.UserName,
      role: user.Role,
    };

    if (isGitHub) {
      userData.githubId = user.github_id;
      userData.githubUsername = user.github_username;
    } else {
      userData.googleId = user.google_id;
      userData.googleEmail = user.google_email;
    }

    return done(null, userData);
  } catch (err) {
    console.error(`[mbkauthe] ${provider} login error:`, err);
    
    // Handle specific OAuth errors
    if (err.name === 'TokenError' || err.code === 'invalid_grant') {
      err.code = 'invalid_grant';
      err.message = 'OAuth token validation failed. This may be due to an expired authorization code or clock synchronization issues.';
    } else {
      err.code = err.code || `${provider.toUpperCase()}_AUTH_ERROR`;
    }
    return done(err);
  }
};

// Configure GitHub Strategy for login
passport.use('github-login', new GitHubStrategy({
  clientID: mbkautheVar.GITHUB_CLIENT_ID,
  clientSecret: mbkautheVar.GITHUB_CLIENT_SECRET,
  callbackURL: '/mbkauthe/api/github/login/callback',
  scope: ['user:email']
}, (accessToken, refreshToken, profile, done) => 
  createOAuthStrategy('GitHub', profile, done)
));

// Configure Google Strategy for login
passport.use('google-login', new GoogleStrategy({
  clientID: mbkautheVar.GOOGLE_CLIENT_ID,
  clientSecret: mbkautheVar.GOOGLE_CLIENT_SECRET,
  callbackURL: '/mbkauthe/api/google/login/callback',
  scope: ['profile', 'email']
}, (accessToken, refreshToken, profile, done) => 
  createOAuthStrategy('Google', profile, done)
));

// Serialize/Deserialize user for OAuth login
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Common OAuth initiation handler
const createOAuthInitiation = (provider, enabledFlag, clientIdFlag, clientSecretFlag) => {
  return (req, res, next) => {
    if (enabledFlag) {
      // Validate OAuth configuration for Google
      if (provider === 'Google' && (!clientIdFlag || !clientSecretFlag)) {
        console.error(`[mbkauthe] ${provider} OAuth not properly configured`);
        return renderError(res, {
          code: 500,
          error: 'Configuration Error',
          message: `${provider} authentication is not properly configured. Please contact your administrator.`,
          page: '/mbkauthe/login',
          pagename: 'Login'
        });
      }

      // Store CSRF token for validation on callback
      const csrfToken = req.csrfToken();
      req.session.oauthCsrfToken = csrfToken;
      console.log(`[mbkauthe] ${provider} OAuth initiation started`);

      // Store redirect parameter in session before OAuth flow
      const redirect = req.query.redirect;
      if (redirect && typeof redirect === 'string') {
        // Only allow relative URLs to prevent open redirect attacks
        if (redirect.startsWith('/') && !redirect.startsWith('//')) {
          req.session.oauthRedirect = redirect;
        } else {
          console.warn(`[mbkauthe] Invalid redirect parameter rejected: ${redirect}`);
        }
      }
      
      // Save session before OAuth redirect to ensure CSRF token is persisted
      req.session.save((err) => {
        if (err) {
          console.error(`[mbkauthe] ${provider} session save error:`, err);
          return renderError(res, {
            code: 500,
            error: 'Session Error',
            message: 'Failed to initialize OAuth flow. Please try again.',
            page: '/mbkauthe/login',
            pagename: 'Login'
          });
        }
        console.log(`[mbkauthe] ${provider} OAuth session saved successfully`);
        passport.authenticate(`${provider.toLowerCase()}-login`, { state: csrfToken })(req, res, next);
      });
    } else {
      return renderError(res, {
        code: 403,
        error: `${provider} Login Disabled`,
        message: `${provider} login is currently disabled. Please use your username and password to log in.`,
        page: '/mbkauthe/login',
        pagename: 'Login'
      });
    }
  };
};

// Common OAuth error handler
const createOAuthErrorHandler = (provider) => {
  return (err) => {
    const providerUpper = provider.toUpperCase();
    switch (err.code) {
      case 'invalid_grant':
      case 'OAUTH_TOKEN_ERROR':
        return {
          code: 400,
          error: 'OAuth Token Error',
          message: `The ${provider} authentication token has expired or is invalid. Please try signing in again.`,
          page: '/mbkauthe/login',
          pagename: 'Login',
          details: process.env.NODE_ENV === 'development' ? `OAuth Error: ${err.message}` : 'Please refresh and try again'
        };

      case `${providerUpper}_NOT_LINKED`:
        return {
          code: 403,
          error: `${provider} Account Not Linked`,
          message: `Your ${provider} account is not linked to any user in our system. To link your ${provider} account, a User must connect their ${provider} account to mbktech account through the user settings.`,
          page: '/mbkauthe/login',
          pagename: 'Login'
        };

      case 'ACCOUNT_INACTIVE':
        return {
          code: 403,
          error: 'Account Inactive',
          message: 'Your account has been deactivated. Please contact your administrator.',
          page: '/mbkauthe/login',
          pagename: 'Login'
        };

      case 'NOT_AUTHORIZED':
        return {
          code: 403,
          error: 'Not Authorized',
          message: `You are not authorized to access ${mbkautheVar.APP_NAME}. Please contact your administrator.`,
          page: '/mbkauthe/login',
          pagename: 'Login'
        };

      default:
        return {
          code: 500,
          error: 'Authentication Error',
          message: `An error occurred during ${provider} authentication. Please try again.`,
          page: '/mbkauthe/login',
          pagename: 'Login'
        };
    }
  };
};

// Common OAuth callback validation
const validateOAuthCallback = (req, res) => {
  const state = req.query.state;
  const sessionCsrfToken = req.session.oauthCsrfToken;
  
  if (!state || !sessionCsrfToken || state !== sessionCsrfToken) {
    console.warn('[mbkauthe] OAuth CSRF token mismatch - possible CSRF attack');
    console.warn(`  - State present: ${!!state}`);
    console.warn(`  - Session token present: ${!!sessionCsrfToken}`);
    console.warn(`  - Tokens match: ${state === sessionCsrfToken}`);
    delete req.session.oauthCsrfToken;
    renderError(res, {
      code: 403,
      error: 'Invalid Request',
      message: 'OAuth security validation failed. Please try again.',
      page: '/mbkauthe/login',
      pagename: 'Login'
    });
    return false; // Invalid - response already sent
  }
  
  console.log(`[mbkauthe] OAuth CSRF validation passed`);
  delete req.session.oauthCsrfToken;
  return true; // Valid
};

// Common OAuth callback handler
const createOAuthCallback = (provider, strategy) => {
  const errorHandler = createOAuthErrorHandler(provider);
  
  return [
    (req, res, next) => {
      const isValid = validateOAuthCallback(req, res);
      if (!isValid) return; // Response already sent
      
      passport.authenticate(strategy, { session: false }, (err, user, info) => {
        if (err) {
          console.error(`[mbkauthe] ${provider} authentication error:`, err);
          const errorData = errorHandler(err);
          renderError(res, errorData);
          return; // Stop execution after sending error
        }

        if (!user) {
          console.error(`[mbkauthe] ${provider} callback: No user data received`);
          renderError(res, {
            code: 401,
            error: 'Authentication Failed',
            message: `${provider} authentication failed. Please try again.`,
            page: '/mbkauthe/login',
            pagename: 'Login'
          });
          return; // Stop execution after sending error
        }

        req.user = user;
        next();
      })(req, res, next);
    },
    async (req, res) => {
      try {
        const oauthUser = req.user;
        const userQuery = `
          SELECT u.id, u."UserName", u."Active", u."Role", u."AllowedApps",
                 tfa."TwoFAStatus"
          FROM "Users" u
          LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
          WHERE u."UserName" = $1
        `;
        
        const userResult = await dblogin.query({
          name: `${provider.toLowerCase()}-callback-get-user`,
          text: userQuery,
          values: [oauthUser.username]
        });

        if (userResult.rows.length === 0) {
          console.error(`[mbkauthe] ${provider} login: User not found: ${oauthUser.username}`);
          return renderError(res, {
            code: 404,
            error: 'User Not Found',
            message: `Your ${provider} account is linked, but the user account no longer exists in our system.`,
            page: '/mbkauthe/login',
            pagename: 'Login',
            details: `${provider} ${provider === 'GitHub' ? 'username' : 'email'}: ${oauthUser[provider === 'GitHub' ? 'githubUsername' : 'googleEmail']}\nPlease contact your administrator.`
          });
        }

        const user = userResult.rows[0];

        // Check for trusted device
        const trustedDeviceUser = await checkTrustedDevice(req, user.UserName);
        if (trustedDeviceUser && (mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus) {
          console.log(`[mbkauthe] ${provider} trusted device login for user: ${user.UserName}, skipping 2FA only`);
          return await handleOAuthRedirect(req, res, user, 'trusted');
        }

        // Check 2FA if enabled
        if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus) {
          const oauthRedirect = req.session.oauthRedirect;
          if (oauthRedirect) delete req.session.oauthRedirect;
          req.session.preAuthUser = {
            id: user.id,
            username: user.UserName,
            role: user.Role,
            allowedApps: user.AllowedApps,
            loginMethod: provider.toLowerCase(),
            redirectUrl: oauthRedirect || null
          };
          console.log(`[mbkauthe] ${provider} login: 2FA required for user: ${oauthUser.username}`);
          return res.redirect('/mbkauthe/2fa');
        }

        // Complete login process
        await handleOAuthRedirect(req, res, user, 'complete');

      } catch (err) {
        console.error(`[mbkauthe] ${provider} login callback error:`, err);
        return renderError(res, {
          code: 500,
          error: 'Internal Server Error',
          message: `An error occurred during ${provider} authentication. Please try again.`,
          page: '/mbkauthe/login',
          pagename: 'Login'
        });
      }
    }
  ];
};

// Helper function to handle OAuth redirect flow
const handleOAuthRedirect = async (req, res, user, type) => {
  const userForSession = {
    id: user.id,
    username: user.UserName,
    role: user.Role,
    allowedApps: user.AllowedApps,
  };

  const oauthRedirect = req.session.oauthRedirect;
  delete req.session.oauthRedirect;

  // Custom response handler for OAuth flow
  const originalJson = res.json.bind(res);
  const originalStatus = res.status.bind(res);
  let statusCode = 200;

  res.status = function (code) {
    statusCode = code;
    return originalStatus(code);
  };

  res.json = function (data) {
    if (data.success && statusCode === 200) {
      const redirectUrl = oauthRedirect || mbkautheVar.loginRedirectURL || '/dashboard';
      console.log(`[mbkauthe] OAuth ${type} login: Redirecting to ${redirectUrl}`);
      res.json = originalJson;
      res.status = originalStatus;
      return res.redirect(redirectUrl);
    }
    res.json = originalJson;
    res.status = originalStatus;
    return originalJson(data);
  };

  return await completeLoginProcess(req, res, userForSession);
};

// GitHub login initiation
router.get('/api/github/login', GitHubOAuthLimit, csrfProtection, 
  createOAuthInitiation('GitHub', mbkautheVar.GITHUB_LOGIN_ENABLED, mbkautheVar.GITHUB_CLIENT_ID, mbkautheVar.GITHUB_CLIENT_SECRET)
);

// Google login initiation  
router.get('/api/google/login', GoogleOAuthLimit, csrfProtection,
  createOAuthInitiation('Google', mbkautheVar.GOOGLE_LOGIN_ENABLED, mbkautheVar.GOOGLE_CLIENT_ID, mbkautheVar.GOOGLE_CLIENT_SECRET)
);


// OAuth callback routes
router.get('/api/github/login/callback', GitHubOAuthLimit, ...createOAuthCallback('GitHub', 'github-login'));
router.get('/api/google/login/callback', GoogleOAuthLimit, ...createOAuthCallback('Google', 'google-login'));

export default router;