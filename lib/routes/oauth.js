import express from "express";
import passport from 'passport';
import GitHubStrategy from 'passport-github2';
import GoogleStrategy from 'passport-google-oauth20';
import csurf from 'csurf';
import rateLimit from 'express-rate-limit';
import { dblogin, dialect } from "#pool.js";
import { mbkautheVar } from "#config.js";
import { renderError } from "../utils/response.js";
import { checkTrustedDevice, completeLoginProcess } from "./auth.js";
import { AuthRepository } from "../db/AuthRepository.js";
import { createLogger } from "../utils/logger.js";

const router = express.Router();
const authRepo = new AuthRepository({ db: dblogin, dialect });
const logOAuth = createLogger("oauth");
const csrfProtection = csurf({ cookie: true });

const createOAuthLimit = (provider) => rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: `Too many ${provider} login attempts, please try again later`,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false, trustProxy: false },
  keyGenerator: (req) => req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown'
});

const GitHubOAuthLimit = createOAuthLimit('GitHub');
const GoogleOAuthLimit = createOAuthLimit('Google');

const githubClientId = mbkautheVar.GITHUB_APP_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID;
const githubClientSecret = mbkautheVar.GITHUB_APP_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET;

const createOAuthStrategy = async (provider, profile, done) => {
  try {
    logOAuth(`${provider} OAuth callback for user: ${profile.emails?.[0]?.value || profile.id}`);
    const user = await authRepo.getOAuthUserByProviderId(provider, profile.id);

    if (!user) {
      const error = new Error(`${provider} account not linked to any user`);
      error.code = `${provider.toUpperCase()}_NOT_LINKED`;
      return done(error);
    }

    if (!user.Active) {
      const error = new Error('Account is inactive');
      error.code = 'ACCOUNT_INACTIVE';
      return done(error);
    }

    if (user.Role !== "SuperAdmin") {
      const allowedApps = user.AllowedApps;
      if (!allowedApps || !allowedApps.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        const error = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
        error.code = 'NOT_AUTHORIZED';
        return done(error);
      }
    }

    const userData = {
      userId: user.UserId || undefined,
      username: user.UserName,
      role: user.Role,
      allowedApps: user.AllowedApps,
      TwoFAStatus: user.TwoFAStatus,
    };

    if (provider === 'GitHub') {
      userData.githubId = user.github_id;
      userData.githubUsername = user.github_username;
      userData.installationId = user.installation_id || null;
      userData.installationTargetType = user.installation_target_type || null;
    } else {
      userData.googleId = user.google_id;
      userData.googleEmail = user.google_email;
    }

    return done(null, userData);
  } catch (err) {
    console.error(`[mbkauthe] ${provider} login error:`, err);
    if (err.name === 'TokenError' || err.code === 'invalid_grant') {
      err.code = 'invalid_grant';
      err.message = 'OAuth token validation failed. This may be due to an expired authorization code or clock synchronization issues.';
    } else {
      err.code = err.code || `${provider.toUpperCase()}_AUTH_ERROR`;
    }
    return done(err);
  }
};

const enabledProviders = [];

if (String(mbkautheVar.GITHUB_LOGIN_ENABLED || "").toLowerCase() === "true") {
  if (githubClientId && githubClientSecret) {
    passport.use('github-login', new GitHubStrategy({
      clientID: githubClientId,
      clientSecret: githubClientSecret,
      callbackURL: '/mbkauthe/api/github/login/callback',
      scope: ['user:email']
    }, (accessToken, refreshToken, profile, done) => createOAuthStrategy('GitHub', profile, done)));
    enabledProviders.push('GitHub App');
  } else {
    console.warn('[mbkauthe] GITHUB_LOGIN_ENABLED is true but GITHUB_APP_CLIENT_ID/SECRET are missing; skipping GitHub strategy registration');
  }
}

if (String(mbkautheVar.GOOGLE_LOGIN_ENABLED || "").toLowerCase() === "true") {
  if (mbkautheVar.GOOGLE_CLIENT_ID && mbkautheVar.GOOGLE_CLIENT_SECRET) {
    passport.use('google-login', new GoogleStrategy({
      clientID: mbkautheVar.GOOGLE_CLIENT_ID,
      clientSecret: mbkautheVar.GOOGLE_CLIENT_SECRET,
      callbackURL: '/mbkauthe/api/google/login/callback',
      scope: ['profile', 'email']
    }, (accessToken, refreshToken, profile, done) => createOAuthStrategy('Google', profile, done)));
    enabledProviders.push('Google');
  } else {
    console.warn('[mbkauthe] GOOGLE_LOGIN_ENABLED is true but GOOGLE_CLIENT_ID/SECRET missing; skipping Google strategy registration');
  }
}

if (enabledProviders.length > 0) {
  logOAuth(`Social providers: ${enabledProviders.join(', ')}`);
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const createOAuthInitiation = (provider, enabledFlag, clientIdFlag, clientSecretFlag) => (req, res, next) => {
  if (String(enabledFlag || '').toLowerCase() !== 'true') {
    return renderError(res, req, {
      code: 403,
      error: `${provider} Login Disabled`,
      message: `${provider} login is currently disabled. Please use your username and password to log in.`,
      page: '/mbkauthe/login',
      pagename: 'Login'
    });
  }

  if (!clientIdFlag || !clientSecretFlag) {
    console.error(`[mbkauthe] ${provider} OAuth not properly configured`);
    return renderError(res, req, {
      code: 500,
      error: 'Configuration Error',
      message: `${provider} authentication is not properly configured. Please contact your administrator.`,
      page: '/mbkauthe/login',
      pagename: 'Login'
    });
  }

  const csrfToken = req.csrfToken();
  req.session.oauthCsrfToken = csrfToken;
  logOAuth(`${provider} OAuth initiation started`);

  const redirect = req.query.redirect;
  if (typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')) {
    req.session.oauthRedirect = redirect;
  }

  req.session.save((err) => {
    if (err) {
      console.error(`[mbkauthe] ${provider} session save error:`, err);
      return renderError(res, req, {
        code: 500,
        error: 'Session Error',
        message: 'Failed to initialize OAuth flow. Please try again.',
        page: '/mbkauthe/login',
        pagename: 'Login'
      });
    }
    logOAuth(`${provider} OAuth session saved successfully`);
    passport.authenticate(`${provider.toLowerCase()}-login`, { state: csrfToken })(req, res, next);
  });
};

const createOAuthErrorHandler = (provider) => (err) => {
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

const validateOAuthCallback = (req, res) => {
  const { state } = req.query;
  const { oauthCsrfToken } = req.session;

  if (!state || !oauthCsrfToken || state !== oauthCsrfToken) {
    console.warn('[mbkauthe] OAuth CSRF token mismatch - possible CSRF attack');
    delete req.session.oauthCsrfToken;
    renderError(res, req, {
      code: 403,
      error: 'Invalid Request',
      message: 'Authentication security validation failed. Please try again.',
      page: '/mbkauthe/login',
      pagename: 'Login'
    });
    return false;
  }

  delete req.session.oauthCsrfToken;
  return true;
};

const finishProviderLogin = async (req, res, provider, user) => {
  const trustedDeviceUser = await checkTrustedDevice(req, user.UserName);
  if (trustedDeviceUser && String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus) {
    logOAuth(`${provider} trusted device login for user: ${user.UserName}, skipping 2FA only`);
    return handleOAuthRedirect(req, res, user, 'trusted', provider.toLowerCase());
  }

  if (String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus) {
    const oauthRedirect = req.session.oauthRedirect;
    if (oauthRedirect) delete req.session.oauthRedirect;
    req.session.preAuthUser = {
      userId: user.UserId || user.userId || undefined,
      username: user.UserName,
      role: user.Role,
      allowedApps: user.AllowedApps,
      loginMethod: provider.toLowerCase(),
      redirectUrl: oauthRedirect || null
    };
    logOAuth(`${provider} login: 2FA required for user: ${user.UserName}`);
    return res.redirect('/mbkauthe/2fa');
  }

  return handleOAuthRedirect(req, res, user, 'complete', provider.toLowerCase());
};

const createOAuthCallback = (provider, strategy) => {
  const errorHandler = createOAuthErrorHandler(provider);

  return [
    (req, res, next) => {
      if (!validateOAuthCallback(req, res)) return;

      passport.authenticate(strategy, { session: false }, (err, user) => {
        if (err) {
          console.error(`[mbkauthe] ${provider} authentication error:`, err);
          return renderError(res, req, errorHandler(err));
        }

        if (!user) {
          console.error(`[mbkauthe] ${provider} callback: No user data received`);
          return renderError(res, req, {
            code: 401,
            error: 'Authentication Failed',
            message: `${provider} authentication failed. Please try again.`,
            page: '/mbkauthe/login',
            pagename: 'Login'
          });
        }

        req.user = user;
        next();
      })(req, res, next);
    },
    async (req, res) => {
      try {
        const { user } = req;
        await finishProviderLogin(
          req,
          res,
          provider,
          {
            UserId: user.userId,
            UserName: user.username,
            Role: user.role,
            AllowedApps: user.allowedApps,
            TwoFAStatus: user.TwoFAStatus
          }
        );
      } catch (err) {
        console.error(`[mbkauthe] ${provider} login callback error:`, err);
        return renderError(res, req, {
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

const handleOAuthRedirect = async (req, res, user, type, method = null) => {
  const userForSession = {
    userId: user.UserId || user.userId || undefined,
    username: user.UserName,
    role: user.Role,
    allowedApps: user.AllowedApps,
  };

  const oauthRedirect = req.session.oauthRedirect;
  delete req.session.oauthRedirect;

  const originalJson = res.json.bind(res);
  const originalStatus = res.status.bind(res);
  let statusCode = 200;

  res.status = function (code) {
    statusCode = code;
    return originalStatus(code);
  };

  res.json = function (data) {
    res.json = originalJson;
    res.status = originalStatus;
    if (data?.success && statusCode === 200) {
      const redirectUrl = oauthRedirect || mbkautheVar.loginRedirectURL || '/dashboard';
      logOAuth(`${method || 'social'} ${type} login: Redirecting to ${redirectUrl}`);
      return res.redirect(redirectUrl);
    }
    return originalJson(data);
  };

  return completeLoginProcess(req, res, userForSession, null, false, method);
};

router.get('/api/github/login', GitHubOAuthLimit, csrfProtection,
  createOAuthInitiation('GitHub', mbkautheVar.GITHUB_LOGIN_ENABLED, githubClientId, githubClientSecret)
);

router.get('/api/google/login', GoogleOAuthLimit, csrfProtection,
  createOAuthInitiation('Google', mbkautheVar.GOOGLE_LOGIN_ENABLED, mbkautheVar.GOOGLE_CLIENT_ID, mbkautheVar.GOOGLE_CLIENT_SECRET)
);

router.get('/api/github/login/callback', GitHubOAuthLimit, ...createOAuthCallback('GitHub', 'github-login'));
router.get('/api/google/login/callback', GoogleOAuthLimit, ...createOAuthCallback('Google', 'google-login'));

export default router;