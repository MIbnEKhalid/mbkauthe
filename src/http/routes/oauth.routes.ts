import express from "express";
import passport from "passport";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import csurf from "csurf";
import rateLimit from "express-rate-limit";
import { mbkautheVar } from "../../config/index.js";
import { renderError } from "../../ui/response/formatters.js";
import { checkTrustedDevice, completeLoginProcess } from "./auth.routes.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { createLogger } from "../../ui/utils/logger.js";

const router = express.Router();
const logOAuth = createLogger("oauth");
const csrfProtection = csurf({ cookie: true });

const createOAuthLimit = (provider: string) => rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: `Too many ${provider} login attempts, please try again later` as any,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false, trustProxy: false },
  keyGenerator: (req) => req.ip || (req.socket?.remoteAddress) || "unknown",
});

const GitHubOAuthLimit = createOAuthLimit("GitHub");
const GoogleOAuthLimit = createOAuthLimit("Google");

const githubClientId = mbkautheVar.GITHUB_APP_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID;
const githubClientSecret = mbkautheVar.GITHUB_APP_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET;

const createOAuthStrategy = async (provider: string, profile: any, done: (err: any, user?: any) => void) => {
  try {
    logOAuth(`${provider} OAuth callback for user: ${profile.emails?.[0]?.value || profile.id}`);
    const user = await authRepository.getOAuthUserByProviderId(provider, profile.id);

    if (!user) {
      const error: any = new Error(`${provider} account not linked to any user`);
      error.code = `${provider.toUpperCase()}_NOT_LINKED`;
      return done(error);
    }

    const { is_active, role, allowed_apps, user_id, username, is_enabled } = user;
    if (!is_active) {
      const error: any = new Error("Account is inactive");
      error.code = "ACCOUNT_INACTIVE";
      return done(error);
    }

    if (role !== "superadmin") {
      if (!allowed_apps || !allowed_apps.some((app: any) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        const error: any = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
        error.code = "NOT_AUTHORIZED";
        return done(error);
      }
    }

    const userData = {
      user_id,
      username,
      role,
      allowed_apps,
      is_enabled,
      full_name: user.full_name,
      image: user.image,
      ...(provider === "GitHub"
        ? { github_id: user.github_id, github_username: user.github_username, installation_id: user.installation_id || null, installation_target_type: user.installation_target_type || null }
        : { google_id: user.google_id, google_email: user.google_email }),
    };

    return done(null, userData);
  } catch (err: any) {
    console.error(`[mbkauthe] ${provider} login error:`, err);
    if (err.name === "TokenError" || err.code === "invalid_grant") {
      err.code = "invalid_grant";
      err.message = "OAuth token validation failed. This may be due to an expired authorization code or clock synchronization issues.";
    } else {
      err.code = err.code || `${provider.toUpperCase()}_AUTH_ERROR`;
    }
    return done(err);
  }
};

const enabledProviders: string[] = [];

if (String(mbkautheVar.GITHUB_LOGIN_ENABLED || "").toLowerCase() === "true") {
  if (githubClientId && githubClientSecret) {
    passport.use("github-login", new GitHubStrategy({
      clientID: githubClientId,
      clientSecret: githubClientSecret,
      callbackURL: "/mbkauthe/api/github/login/callback",
      scope: ["user:email"],
    }, (access_token: any, refresh_token: any, profile: any, done: any) => createOAuthStrategy("GitHub", profile, done)));
    enabledProviders.push("GitHub App");
  } else {
    console.warn("[mbkauthe] GITHUB_LOGIN_ENABLED is true but GITHUB_APP_CLIENT_ID/SECRET are missing; skipping GitHub strategy registration");
  }
}

if (String(mbkautheVar.GOOGLE_LOGIN_ENABLED || "").toLowerCase() === "true") {
  if (mbkautheVar.GOOGLE_CLIENT_ID && mbkautheVar.GOOGLE_CLIENT_SECRET) {
    passport.use("google-login", new GoogleStrategy({
      clientID: mbkautheVar.GOOGLE_CLIENT_ID,
      clientSecret: mbkautheVar.GOOGLE_CLIENT_SECRET,
      callbackURL: "/mbkauthe/api/google/login/callback",
      scope: ["profile", "email"],
    }, (access_token: any, refresh_token: any, profile: any, done: any) => createOAuthStrategy("Google", profile, done)));
    enabledProviders.push("Google");
  } else {
    console.warn("[mbkauthe] GOOGLE_LOGIN_ENABLED is true but GOOGLE_CLIENT_ID/SECRET missing; skipping Google strategy registration");
  }
}

if (enabledProviders.length > 0) {
  logOAuth(`Social providers: ${enabledProviders.join(", ")}`);
}

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

const createOAuthInitiation = (provider: string, enabledFlag: any, clientIdFlag: any, clientSecretFlag: any) => (req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (String(enabledFlag || "").toLowerCase() !== "true") {
    return renderError(res, req, {
      code: 403,
      error: `${provider} Login Disabled`,
      message: `${provider} login is currently disabled. Please use your username and password to log in.`,
      page: "/mbkauthe/login",
      pagename: "Login",
    });
  }

  if (!clientIdFlag || !clientSecretFlag) {
    console.error(`[mbkauthe] ${provider} OAuth not properly configured`);
    return renderError(res, req, {
      code: 500,
      error: "Configuration Error",
      message: `${provider} authentication is not properly configured. Please contact your administrator.`,
      page: "/mbkauthe/login",
      pagename: "Login",
    });
  }

  const csrfToken = (req as any).csrfToken ? (req as any).csrfToken() : "";
  (req as any).session.oauth_csrf_token = csrfToken;
  logOAuth(`${provider} OAuth initiation started`);

  const redirect = req.query.redirect;
  if (typeof redirect === "string" && redirect.startsWith("/") && !redirect.startsWith("//")) {
    (req as any).session.oauth_redirect = redirect;
  }

  (req as any).session.save((err: any) => {
    if (err) {
      console.error(`[mbkauthe] ${provider} session save error:`, err);
      return renderError(res, req, {
        code: 500,
        error: "Session Error",
        message: "Failed to initialize OAuth flow. Please try again.",
        page: "/mbkauthe/login",
        pagename: "Login",
      });
    }
    logOAuth(`${provider} OAuth session saved successfully`);
    passport.authenticate(`${provider.toLowerCase()}-login`, { state: csrfToken })(req, res, next);
  });
};

const createOAuthErrorHandler = (provider: string) => (err: any) => {
  const providerUpper = provider.toUpperCase();
  switch (err.code) {
    case "invalid_grant":
    case "OAUTH_TOKEN_ERROR":
      return {
        code: 400,
        error: "OAuth Token Error",
        message: `The ${provider} authentication token has expired or is invalid. Please try signing in again.`,
        page: "/mbkauthe/login",
        pagename: "Login",
        details: process.env.NODE_ENV === "development" ? `OAuth Error: ${err.message}` : "Please refresh and try again",
      };
    case `${providerUpper}_NOT_LINKED`:
      return {
        code: 403,
        error: `${provider} Account Not Linked`,
        message: `Your ${provider} account is not linked to any user in our system. To link your ${provider} account, a User must connect their ${provider} account to mbktech account through the user settings.`,
        page: "/mbkauthe/login",
        pagename: "Login",
      };
    case "ACCOUNT_INACTIVE":
      return {
        code: 403,
        error: "Account Inactive",
        message: "Your account has been deactivated. Please contact your administrator.",
        page: "/mbkauthe/login",
        pagename: "Login",
      };
    case "NOT_AUTHORIZED":
      return {
        code: 403,
        error: "Not Authorized",
        message: `You are not authorized to access ${mbkautheVar.APP_NAME}. Please contact your administrator.`,
        page: "/mbkauthe/login",
        pagename: "Login",
      };
    default:
      return {
        code: 500,
        error: "Authentication Error",
        message: `An error occurred during ${provider} authentication. Please try again.`,
        page: "/mbkauthe/login",
        pagename: "Login",
      };
  }
};

const validateOAuthCallback = (req: express.Request, res: express.Response) => {
  const { state } = req.query;
  const { oauth_csrf_token } = (req as any).session || {};

  if (!state || !oauth_csrf_token || state !== oauth_csrf_token) {
    console.warn("[mbkauthe] OAuth CSRF token mismatch - possible CSRF attack");
    if ((req as any).session) delete (req as any).session.oauth_csrf_token;
    renderError(res, req, {
      code: 403,
      error: "Invalid Request",
      message: "Authentication security validation failed. Please try again.",
      page: "/mbkauthe/login",
      pagename: "Login",
    });
    return false;
  }

  if ((req as any).session) delete (req as any).session.oauth_csrf_token;
  return true;
};

const handleOAuthRedirect = async (req: express.Request, res: express.Response, user: any, type: string, method: string | null = null) => {
  const userForSession = {
    user_id: user.user_id || undefined,
    username: user.username,
    role: user.role,
    allowed_apps: user.allowed_apps,
    full_name: user.full_name,
    image: user.image,
  };

  const oauth_redirect = (req as any).session.oauth_redirect;
  delete (req as any).session.oauth_redirect;

  const originalJson = res.json.bind(res);
  const originalStatus = res.status.bind(res);
  let statusCode = 200;

  res.status = function (code: number) {
    statusCode = code;
    return originalStatus(code);
  } as any;

  res.json = function (data: any) {
    res.json = originalJson;
    res.status = originalStatus;
    if (data?.success && statusCode === 200) {
      const redirectUrl = oauth_redirect || mbkautheVar.LOGIN_REDIRECT_URL || "/dashboard";
      logOAuth(`${method || "social"} ${type} login: Redirecting to ${redirectUrl}`);
      res.redirect(redirectUrl);
      return res;
    }
    return originalJson(data);
  } as any;

  return completeLoginProcess(req, res, userForSession, null, false, method);
};

const finishProviderLogin = async (req: express.Request, res: express.Response, provider: string, user: any) => {
  const trustedDeviceUser = await checkTrustedDevice(req, user.username);
  if (trustedDeviceUser && String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.is_enabled) {
    logOAuth(`${provider} trusted device login for user: ${user.username}, skipping 2FA only`);
    return handleOAuthRedirect(req, res, user, "trusted", provider.toLowerCase());
  }

  if (String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.is_enabled) {
    const oauth_redirect = (req as any).session.oauth_redirect;
    if (oauth_redirect) delete (req as any).session.oauth_redirect;
    (req as any).session.pre_auth_user = {
      user_id: user.user_id || undefined,
      username: user.username,
      role: user.role,
      allowed_apps: user.allowed_apps,
      full_name: user.full_name,
      image: user.image,
      login_method: provider.toLowerCase(),
      redirect_url: oauth_redirect || null,
    };
    logOAuth(`${provider} login: 2FA required for user: ${user.username}`);
    return res.redirect("/mbkauthe/2fa");
  }

  return handleOAuthRedirect(req, res, user, "complete", provider.toLowerCase());
};

const createOAuthCallback = (provider: string, strategy: string) => {
  const errorHandler = createOAuthErrorHandler(provider);

  return [
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (!validateOAuthCallback(req, res)) return;

      passport.authenticate(strategy, { session: false }, (err: any, user: any) => {
        if (err) {
          console.error(`[mbkauthe] ${provider} authentication error:`, err);
          return renderError(res, req, errorHandler(err));
        }

        if (!user) {
          console.error(`[mbkauthe] ${provider} callback: No user data received`);
          return renderError(res, req, {
            code: 401,
            error: "Authentication Failed",
            message: `${provider} authentication failed. Please try again.`,
            page: "/mbkauthe/login",
            pagename: "Login",
          });
        }

        (req as any).user = user;
        next();
      })(req, res, next);
    },
    async (req: express.Request, res: express.Response) => {
      try {
        const { user } = (req as any);
        await finishProviderLogin(
          req,
          res,
          provider,
          {
            user_id: user.user_id,
            username: user.username,
            role: user.role,
            allowed_apps: user.allowed_apps,
            is_enabled: user.is_enabled,
            full_name: user.full_name,
            image: user.image,
          }
        );
      } catch (err) {
        console.error(`[mbkauthe] ${provider} login callback error:`, err);
        return renderError(res, req, {
          code: 500,
          error: "Internal Server Error",
          message: `An error occurred during ${provider} authentication. Please try again.`,
          page: "/mbkauthe/login",
          pagename: "Login",
        });
      }
    },
  ];
};

router.get("/api/github/login", GitHubOAuthLimit, csrfProtection,
  createOAuthInitiation("GitHub", mbkautheVar.GITHUB_LOGIN_ENABLED, githubClientId, githubClientSecret)
);

router.get("/api/google/login", GoogleOAuthLimit, csrfProtection,
  createOAuthInitiation("Google", mbkautheVar.GOOGLE_LOGIN_ENABLED, mbkautheVar.GOOGLE_CLIENT_ID, mbkautheVar.GOOGLE_CLIENT_SECRET)
);

router.get("/api/github/login/callback", GitHubOAuthLimit, ...createOAuthCallback("GitHub", "github-login"));
router.get("/api/google/login/callback", GoogleOAuthLimit, ...createOAuthCallback("Google", "google-login"));

export const oauthRouter = router;
export default router;
