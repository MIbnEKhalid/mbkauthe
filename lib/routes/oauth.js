import express from "express";
import passport from 'passport';
import GitHubStrategy from 'passport-github2';
import rateLimit from 'express-rate-limit';
import { dblogin } from "../database/pool.js";
import { mbkautheVar } from "../config/index.js";
import { renderError } from "../utils/response.js";
import { checkTrustedDevice, completeLoginProcess } from "./auth.js";

const router = express.Router();

// Rate limiter for OAuth routes
const GitHubOAuthLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: "Too many GitHub login attempts, please try again later"
});

// Configure GitHub Strategy for login
passport.use('github-login', new GitHubStrategy({
  clientID: mbkautheVar.GITHUB_CLIENT_ID,
  clientSecret: mbkautheVar.GITHUB_CLIENT_SECRET,
  callbackURL: '/mbkauthe/api/github/login/callback',
  scope: ['user:email']
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if this GitHub account is linked to any user
      const githubUser = await dblogin.query({
        name: 'github-login-get-user',
        text: 'SELECT ug.*, u."UserName", u."Role", u."Active", u."AllowedApps", u."id" FROM user_github ug JOIN "Users" u ON ug.user_name = u."UserName" WHERE ug.github_id = $1',
        values: [profile.id]
      });

      if (githubUser.rows.length === 0) {
        // GitHub account is not linked to any user
        const error = new Error('GitHub account not linked to any user');
        error.code = 'GITHUB_NOT_LINKED';
        return done(error);
      }

      const user = githubUser.rows[0];

      // Check if the user account is active
      if (!user.Active) {
        const error = new Error('Account is inactive');
        error.code = 'ACCOUNT_INACTIVE';
        return done(error);
      }

      // Check if user is authorized for this app (same logic as regular login)
      if (user.Role !== "SuperAdmin") {
        const allowedApps = user.AllowedApps;
        if (!allowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
          const error = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
          error.code = 'NOT_AUTHORIZED';
          return done(error);
        }
      }

      // Return user data for login
      return done(null, {
        id: user.id,
        username: user.UserName,
        role: user.Role,
        githubId: user.github_id,
        githubUsername: user.github_username
      });
    } catch (err) {
      console.error('[mbkauthe] GitHub login error:', err);
      err.code = err.code || 'GITHUB_AUTH_ERROR';
      return done(err);
    }
  }
));

// Serialize/Deserialize user for GitHub login
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// GitHub login initiation
router.get('/api/github/login', GitHubOAuthLimit, (req, res, next) => {
  if (mbkautheVar.GITHUB_LOGIN_ENABLED) {
    // Store redirect parameter in session before OAuth flow (validate to prevent open redirect)
    const redirect = req.query.redirect;
    if (redirect && typeof redirect === 'string') {
      // Only allow relative URLs or same-origin URLs to prevent open redirect attacks
      if (redirect.startsWith('/') && !redirect.startsWith('//')) {
        req.session.oauthRedirect = redirect;
      } else {
        console.warn(`[mbkauthe] Invalid redirect parameter rejected: ${redirect}`);
      }
    }
    passport.authenticate('github-login')(req, res, next);
  }
  else {
    return renderError(res, {
      code: '403',
      error: 'GitHub Login Disabled',
      message: 'GitHub login is currently disabled. Please use your username and password to log in.',
      page: '/mbkauthe/login',
      pagename: 'Login',
    });
  }
});

// GitHub login callback
router.get('/api/github/login/callback',
  GitHubOAuthLimit,
  (req, res, next) => {
    passport.authenticate('github-login', {
      session: false // We'll handle session manually
    }, (err, user, info) => {
      // Custom error handling for passport authentication
      if (err) {
        console.error('[mbkauthe] GitHub authentication error:', err);

        // Map error codes to user-friendly messages
        switch (err.code) {
          case 'GITHUB_NOT_LINKED':
            return renderError(res, {
              code: '403',
              error: 'GitHub Account Not Linked',
              message: 'Your GitHub account is not linked to any user in our system. To link your GitHub account, a User must connect their GitHub account to mbktech account through the user settings.',
              page: '/mbkauthe/login',
              pagename: 'Login'
            });

          case 'ACCOUNT_INACTIVE':
            return renderError(res, {
              code: '403',
              error: 'Account Inactive',
              message: 'Your account has been deactivated. Please contact your administrator.',
              page: '/mbkauthe/login',
              pagename: 'Login'
            });

          case 'NOT_AUTHORIZED':
            return renderError(res, {
              code: '403',
              error: 'Not Authorized',
              message: `You are not authorized to access ${mbkautheVar.APP_NAME}. Please contact your administrator.`,
              page: '/mbkauthe/login',
              pagename: 'Login'
            });

          default:
            return renderError(res, {
              code: '500',
              error: 'Authentication Error',
              message: 'An error occurred during GitHub authentication. Please try again.',
              page: '/mbkauthe/login',
              pagename: 'Login',
              details: process.env.NODE_ENV === 'development' ? `${err.message}\n${err.stack}` : 'Error details hidden in production'
            });
        }
      }

      if (!user) {
        console.error('[mbkauthe] GitHub callback: No user data received');
        return renderError(res, {
          code: '401',
          error: 'Authentication Failed',
          message: 'GitHub authentication failed. Please try again.',
          page: '/mbkauthe/login',
          pagename: 'Login'
        });
      }

      // Authentication successful, attach user to request
      req.user = user;
      next();
    })(req, res, next);
  },
  async (req, res) => {
    try {
      const githubUser = req.user;

      // Combined query: fetch user data and 2FA status in one query
      const userQuery = `
        SELECT u.id, u."UserName", u."Active", u."Role", u."AllowedApps",
               tfa."TwoFAStatus"
        FROM "Users" u
        LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
        WHERE u."UserName" = $1
      `;
      const userResult = await dblogin.query({
        name: 'github-callback-get-user',
        text: userQuery,
        values: [githubUser.username]
      });

      if (userResult.rows.length === 0) {
        console.error(`[mbkauthe] GitHub login: User not found: ${githubUser.username}`);
        return renderError(res, {
          code: '404',
          error: 'User Not Found',
          message: 'Your GitHub account is linked, but the user account no longer exists in our system.',
          page: '/mbkauthe/login',
          pagename: 'Login',
          details: `GitHub username: ${githubUser.username}\nPlease contact your administrator.`
        });
      }

      const user = userResult.rows[0];

      // Check for trusted device after OAuth authentication
      const trustedDeviceUser = await checkTrustedDevice(req, user.UserName);
      if (trustedDeviceUser && (mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus) {
        console.log(`[mbkauthe] GitHub trusted device login for user: ${user.UserName}, skipping 2FA only`);

        const userForSession = {
          id: user.id,
          username: user.UserName,
          UserName: user.UserName,
          role: user.Role,
          Role: user.Role,
          allowedApps: user.AllowedApps,
        };

        // For OAuth redirect flow
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
            console.log(`[mbkauthe] GitHub trusted device login: Redirecting to ${redirectUrl}`);
            res.json = originalJson;
            res.status = originalStatus;
            return res.redirect(redirectUrl);
          }
          res.json = originalJson;
          res.status = originalStatus;
          return originalJson(data);
        };

        return await completeLoginProcess(req, res, userForSession);
      }

      // Check 2FA if enabled
      if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus) {
        const oauthRedirect = req.session.oauthRedirect;
        if (oauthRedirect) delete req.session.oauthRedirect;
        req.session.preAuthUser = {
          id: user.id,
          username: user.UserName,
          UserName: user.UserName,
          role: user.Role,
          Role: user.Role,
          loginMethod: 'github',
          redirectUrl: oauthRedirect || null
        };
        console.log(`[mbkauthe] GitHub login: 2FA required for user: ${githubUser.username}`);
        return res.redirect('/mbkauthe/2fa');
      }

      // Complete login process
      const userForSession = {
        id: user.id,
        username: user.UserName,
        UserName: user.UserName,
        role: user.Role,
        Role: user.Role,
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
          console.log(`[mbkauthe] GitHub login: Redirecting to ${redirectUrl}`);
          res.json = originalJson;
          res.status = originalStatus;
          return res.redirect(redirectUrl);
        }
        res.json = originalJson;
        res.status = originalStatus;
        return originalJson(data);
      };

      await completeLoginProcess(req, res, userForSession);

    } catch (err) {
      console.error('[mbkauthe] GitHub login callback error:', err);
      return renderError(res, {
        code: '500',
        error: 'Internal Server Error',
        message: 'An error occurred during GitHub authentication. Please try again.',
        page: '/mbkauthe/login',
        pagename: 'Login',
        details: process.env.NODE_ENV === 'development' ? `${err.message}\n${err.stack}` : 'Error details hidden in production'
      });
    }
  }
);

export default router;
