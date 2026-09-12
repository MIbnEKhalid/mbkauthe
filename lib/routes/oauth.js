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
import { AuthRepository } from "../repositories/AuthRepository.js";
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

    const { is_active, role, allowed_apps, user_id, username, is_enabled } = user;
    if (!is_active) {
      const error = new Error('Account is inactive');
      error.code = 'ACCOUNT_INACTIVE';
      return done(error);
    }

    if (role !== "superadmin") {
      if (!allowed_apps || !allowed_apps.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        const error = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
        error.code = 'NOT_AUTHORIZED';
        return done(error);
      }
    }

    const userData = {
      user_id,
      username,
      role,
      allowed_apps,
      is_enabled,
      ...(provider === 'GitHub'
        ? { github_id: user.github_id, github_username: user.github_username, installation_id: user.installation_id || null, installation_target_type: user.installation_target_type || null }
        : { google_id: user.google_id, google_email: user.google_email })
    };

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
    }, (access_token, refresh_token, profile, done) => createOAuthStrategy('GitHub', profile, done)));
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
    }, (access_token, refresh_token, profile, done) => createOAuthStrategy('Google', profile, done)));
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
  req.session.oauth_csrf_token = csrfToken;
  logOAuth(`${provider} OAuth initiation started`);

  const redirect = req.query.redirect;
  if (typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')) {
    req.session.oauth_redirect = redirect;
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
  const { oauth_csrf_token } = req.session;

  if (!state || !oauth_csrf_token || state !== oauth_csrf_token) {
    console.warn('[mbkauthe] OAuth CSRF token mismatch - possible CSRF attack');
    delete req.session.oauth_csrf_token;
    renderError(res, req, {
      code: 403,
      error: 'Invalid Request',
      message: 'Authentication security validation failed. Please try again.',
      page: '/mbkauthe/login',
      pagename: 'Login'
    });
    return false;
  }

  delete req.session.oauth_csrf_token;
  return true;
};

const finishProviderLogin = async (req, res, provider, user) => {
  const trustedDeviceUser = await checkTrustedDevice(req, user.username);
  if (trustedDeviceUser && String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.is_enabled) {
    logOAuth(`${provider} trusted device login for user: ${user.username}, skipping 2FA only`);
    return handleOAuthRedirect(req, res, user, 'trusted', provider.toLowerCase());
  }

  if (String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.is_enabled) {
    const oauth_redirect = req.session.oauth_redirect;
    if (oauth_redirect) delete req.session.oauth_redirect;
    req.session.pre_auth_user = {
      user_id: user.user_id || undefined,
      username: user.username,
      role: user.role,
      allowed_apps: user.allowed_apps,
      login_method: provider.toLowerCase(),
      redirect_url: oauth_redirect || null
    };
    logOAuth(`${provider} login: 2FA required for user: ${user.username}`);
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
            user_id: user.user_id,
            username: user.username,
            role: user.role,
            allowed_apps: user.allowed_apps,
            is_enabled: user.is_enabled
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
    user_id: user.user_id || undefined,
    username: user.username,
    role: user.role,
    allowed_apps: user.allowed_apps,
  };

  const oauth_redirect = req.session.oauth_redirect;
  delete req.session.oauth_redirect;

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
      const redirectUrl = oauth_redirect || mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';
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