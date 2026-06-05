import { dblogin } from "#pool.js";
import { mbkautheVar } from "#config.js";
import { renderError } from "#response.js";
import { clearSessionCookies, cachedCookieOptions, encryptSessionId } from "#cookies.js";
import { ErrorCodes, createErrorResponse } from "../utils/errors.js";
import { hashApiToken } from "#config.js";
import { canAccessMethod } from "#config.js";
import { extractAuthorizationToken, timingSafeTokenMatch } from "../utils/timingSafeToken.js";
import { AuthRepository } from "../db/AuthRepository.js";
import { createLogger } from "../utils/logger.js";

const IS_DEV = process.env.env === 'dev' || process.env.test === 'dev' || process.env.NODE_ENV === 'development';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (val) => typeof val === 'string' && UUID_RE.test(val);
const MAX_API_TOKEN_LENGTH = 4096;
const API_TOKEN_SESSION_RESTORE = Symbol('mbkauthe.apiTokenSessionRestore');
const authRepo = new AuthRepository({ db: dblogin });
const logAuth = createLogger("auth");

/**
 * Decide if the incoming request should return JSON errors instead of HTML.
 * Non-browser clients (API calls / AJAX) should get JSON.
 */
function isJsonRequest(req) {
  if (!req || !req.headers) return false;
  const accept = (req.headers.accept || "").toLowerCase();
  const xRequestedWith = (req.headers["x-requested-with"] || "").toLowerCase();
  const userAgent = (req.headers["user-agent"] || "").toLowerCase();
  const url = (req.originalUrl || req.url || "").toLowerCase();
  const path = (req.path || "").toLowerCase();

  // Explicit opt-in: allow clients to force JSON responses via a minimal user-agent.
  // Useful for health checks / lightweight clients that don't send Accept headers.
  if (userAgent.trim() === "json") return true;

  const isApiPath = url.startsWith("/mbkauthe/api/") || url.startsWith("/api/") || path.startsWith("/mbkauthe/api/") || path.startsWith("/api/");
  const isAcceptJson = accept.includes("application/json") || accept.includes("json") || accept.includes("*/*");

  const nonBrowserAgent = /curl|wget|httpie|python-requests|python|go-http-client|java\/|php|node-fetch|axios|postman|insomnia|okhttp/;
  const browserAgent = /mozilla|applewebkit|chrome|safari|firefox|edg|msie|trident|opera/;

  if (isApiPath || xRequestedWith === "xmlhttprequest") return true;
  if (isAcceptJson && !accept.includes("text/html")) return true;

  if (nonBrowserAgent.test(userAgent) && !browserAgent.test(userAgent)) return true;

  return false;
}

/**
 * Validates a Bearer token (API Token or Session UUID)
 * Returns a user object if valid, or null/error object
 */
async function validateTokenAuthentication(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
  const token = parts[1];

  // 1. Check for API Token (mbk_)
  if (token.startsWith('mbk_')) {
    if (token.length > MAX_API_TOKEN_LENGTH) return { error: 'INVALID_TOKEN' };

    const tokenHash = hashApiToken(token);
    const row = await authRepo.getApiTokenByHash(tokenHash);

    if (!row) return { error: 'INVALID_TOKEN' };
    if (row.ExpiresAt && new Date(row.ExpiresAt) <= new Date()) return { error: 'TOKEN_EXPIRED' };

    // Parse permissions from JSONB
    const permissions = row.Permissions || { scope: 'read-only', allowedApps: null };
    const tokenScope = permissions.scope || 'read-only';
    const tokenAllowedApps = permissions.allowedApps;

    // Determine allowed apps: token-specific takes precedence over user's apps
    let allowedApps = row.user_allowed_apps;
    if (tokenAllowedApps !== null) {
      allowedApps = tokenAllowedApps;
    }

    // Update usage opportunistically, but not on every request.
    authRepo.updateApiTokenLastUsed(row.id).catch(e => console.error(`[mbkauthe] Failed to update token usage:`, e));

    return {
      id: row.uid,
      username: row.UserName,
      fullname: row.FullName,
      role: row.Role,
      sessionId: 'api-token-session',
      allowedApps: allowedApps,
      userAllowedApps: row.user_allowed_apps, // Pass user apps for wildcard validation
      active: row.Active,
      tokenScope: tokenScope
    };
  }

  return null;
}

function attachApiTokenUser(req, res, tokenUser) {
  const user = {
    id: tokenUser.id,
    username: tokenUser.username,
    fullname: tokenUser.fullname,
    role: tokenUser.role,
    sessionId: tokenUser.sessionId,
    allowedApps: tokenUser.allowedApps,
    tokenScope: tokenUser.tokenScope || null,
  };

  req.auth = {
    type: 'api-token',
    user,
    tokenScope: user.tokenScope,
    allowedApps: user.allowedApps,
  };

  // Backwards compatibility: existing protected routes commonly read
  // req.session.user. For API tokens this must be request-local so the
  // Postgres session store is not dirtied/saved on every token request.
  if (req.session) {
    const originalDescriptor = Object.getOwnPropertyDescriptor(req.session, 'user');

    Object.defineProperty(req.session, 'user', {
      value: user,
      enumerable: false,
      configurable: true,
      writable: true,
    });

    if (res && !req.session[API_TOKEN_SESSION_RESTORE]) {
      req.session[API_TOKEN_SESSION_RESTORE] = true;
      const originalEnd = res.end;
      let restored = false;

      res.end = function apiTokenSessionEnd(...args) {
        if (!restored) {
          restored = true;
          if (originalDescriptor) {
            Object.defineProperty(req.session, 'user', originalDescriptor);
          } else {
            delete req.session.user;
          }
          delete req.session[API_TOKEN_SESSION_RESTORE];
        }
        return originalEnd.apply(this, args);
      };
    }
  }

  req.user = user;
  req.userRole = tokenUser.role;
  return user;
}

function hasAppAccess(role, allowedApps) {
  if (role === "SuperAdmin") return true;
  return Array.isArray(allowedApps)
    && allowedApps.length > 0
    && allowedApps.some((app) => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase());
}

function destroySessionCookies(req, res) {
  req.session?.destroy?.(() => { });
  clearSessionCookies(res);
}

function respondSessionFailure(req, res, { prefersJson, code, errorCode, error, message, page, pagename = "Login" }) {
  destroySessionCookies(req, res);
  if (prefersJson) {
    return res.status(code).json(createErrorResponse(code, errorCode));
  }
  return renderError(res, req, {
    code,
    error,
    message,
    pagename,
    page,
  });
}

async function validateCookieSession(req, res, next, { prefersJson }) {
  if (!req.session.user) {
    if (IS_DEV) {
      logAuth(`User not authenticated`);
      logAuth(`req.session.user: %O`, req.session.user);
    }
    if (prefersJson) {
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
    }

    const redirectParams = new URLSearchParams({
      redirect: req.originalUrl,
      reason: 'logged_out'
    });
    return res.redirect(302, `/mbkauthe/login?${redirectParams.toString()}`);
  }

  try {
    const { sessionId } = req.session.user;

    if (!sessionId || !isUuid(sessionId)) {
      console.warn(`[mbkauthe] Missing sessionId for user "${req.session.user.username}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: ErrorCodes.SESSION_EXPIRED,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    const sessionRow = await authRepo.getSessionAuthData(
      sessionId,
      prefersJson ? 'validate-app-session-for-api' : 'validate-app-session'
    );

    if (!sessionRow) {
      logAuth(`Session not found for user "${req.session.user.username}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: prefersJson ? ErrorCodes.SESSION_INVALID : ErrorCodes.SESSION_EXPIRED,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    if (sessionRow.expires_at) {
      const expiresMs = sessionRow.expires_at instanceof Date
        ? sessionRow.expires_at.getTime()
        : Date.parse(sessionRow.expires_at);

      if (!Number.isNaN(expiresMs) && expiresMs <= Date.now()) {
        logAuth(`Session invalidated (expired) for user "${sessionRow.UserName || req.session.user.username}"`);
        return respondSessionFailure(req, res, {
          prefersJson,
          code: 401,
          errorCode: ErrorCodes.SESSION_EXPIRED,
          error: "Session Expired",
          message: "Your Session Has Expired. Please Log In Again.",
          page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
        });
      }
    }

    if (!sessionRow.Active) {
      logAuth(`Account is inactive for user "${sessionRow.UserName || req.session.user.username}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: ErrorCodes.ACCOUNT_INACTIVE,
        error: "Account Inactive",
        message: "Your Account Is Inactive. Please Contact Support.",
        pagename: "Support",
        page: "https://mbktech.org/Support",
      });
    }

    if (!hasAppAccess(sessionRow.Role, sessionRow.AllowedApps)) {
      console.warn(`[mbkauthe] User "${sessionRow.UserName || req.session.user.username}" is not authorized to use the application "${mbkautheVar.APP_NAME}"`);
      return respondSessionFailure(req, res, {
        prefersJson,
        code: 401,
        errorCode: ErrorCodes.APP_NOT_AUTHORIZED,
        error: "Unauthorized",
        message: `You Are Not Authorized To Use The Application "${mbkautheVar.APP_NAME}"`,
        pagename: "Home",
        page: `/${mbkautheVar.loginRedirectURL}`
      });
    }

    req.userRole = sessionRow.Role;
    return next();
  } catch (err) {
    console.error(`[mbkauthe] Session validation error:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
}

async function validateSession(req, res, next, strictTokenValidation = false) {
  if (req.headers.authorization) {
    if (strictTokenValidation) {
      return res.status(401).json(createErrorResponse(401, ErrorCodes.INVALID_AUTH_TOKEN, {
        message: 'Token-based authentication not allowed for this endpoint',
        hint: 'Use session-based authentication (cookies) instead'
      }));
    }

    try {
      const tokenUser = await validateTokenAuthentication(req);

      if (tokenUser && !tokenUser.error) {
        if (!tokenUser.active) {
          return res.status(401).json(createErrorResponse(401, ErrorCodes.ACCOUNT_INACTIVE));
        }

        if (tokenUser.role !== "SuperAdmin") {
          const allowedApps = tokenUser.allowedApps;
          const userAllowedApps = tokenUser.userAllowedApps;

          if (!Array.isArray(allowedApps) || allowedApps.length === 0) {
            return res.status(401).json(createErrorResponse(401, ErrorCodes.APP_NOT_AUTHORIZED));
          }

          const hasWildcard = allowedApps.includes('*');
          const hasSpecificApp = allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase());

          if (hasWildcard) {
            const userHasApp = Array.isArray(userAllowedApps)
              && userAllowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase());
            if (!userHasApp) {
              return res.status(401).json(createErrorResponse(401, ErrorCodes.APP_NOT_AUTHORIZED));
            }
          } else if (!hasSpecificApp) {
            return res.status(401).json(createErrorResponse(401, ErrorCodes.APP_NOT_AUTHORIZED));
          }
        }

        attachApiTokenUser(req, res, tokenUser);

        if (tokenUser.tokenScope) {
          const requestMethod = req.method;
          if (!canAccessMethod(tokenUser.tokenScope, requestMethod)) {
            return res.status(403).json(createErrorResponse(403, ErrorCodes.TOKEN_SCOPE_INSUFFICIENT, {
              message: `Token scope '${tokenUser.tokenScope}' does not allow ${requestMethod} requests`,
              tokenScope: tokenUser.tokenScope,
              requestedMethod: requestMethod,
              hint: 'Use a token with write scope for write operations'
            }));
          }
        }

        return next();
      }

      let errorCode = ErrorCodes.INVALID_AUTH_TOKEN;
      if (tokenUser && tokenUser.error === 'TOKEN_EXPIRED') {
        errorCode = ErrorCodes.API_TOKEN_EXPIRED;
      }
      return res.status(401).json(createErrorResponse(401, errorCode));
    } catch (err) {
      console.error(`[mbkauthe] Token validation error:`, err);
      return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
    }
  }

  return validateCookieSession(req, res, next, { prefersJson: isJsonRequest(req) });
}

/**
 * API-friendly session validation middleware
 * Returns JSON error responses instead of rendering pages
 */
async function validateApiSession(req, res, next) {
  if (req.headers.authorization) {
    return validateSession(req, res, next);
  }
  return validateCookieSession(req, res, next, { prefersJson: true });
}

/**
 * Reload session user values from the database and refresh cookies.
 * - Validates sessionId and active status
 * - Updates `req.session.user` fields (username, role, allowedApps, fullname)
 * - Uses cached `fullName` cookie when available, otherwise queries `Users`
 * - Syncs `username`, `fullName` and `sessionId` cookies
 * Returns: true if session refreshed and valid, false if session invalidated
 */
async function reloadSessionUser(req, res) {
  if (!req.session || !req.session.user || !req.session.user.id) return false;
  try {
    const { sessionId: currentSessionId } = req.session.user;

    if (!currentSessionId) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return false;
    }

    const normalizedSessionId = String(currentSessionId);
    const row = await authRepo.getSessionWithUserForReload(normalizedSessionId, 'reload-session-user');

    if (!row) {
      // Session not found — invalidate session
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return false;
    }

    // Check expired
    if (row.expires_at && new Date(row.expires_at) <= new Date()) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return false;
    }

    if (!row.Active) {
      // Account is inactive
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return false;
    }

    // Authorization: ensure allowed for current app unless SuperAdmin
    if (row.Role !== 'SuperAdmin') {
      const allowedApps = row.AllowedApps;
      const hasAllowedApps = Array.isArray(allowedApps) && allowedApps.length > 0;
      if (!hasAllowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        req.session.destroy(() => { });
        clearSessionCookies(res);
        return false;
      }
    }

    // Update session fields
    req.session.user.username = row.UserName;
    req.session.user.role = row.Role;
    req.session.user.allowedApps = row.AllowedApps;

    // Obtain fullname from client cookie cache when present else DB
    if (typeof row.FullName === 'string' && row.FullName.trim() !== '') {
      req.session.user.fullname = row.FullName;
    } else if (req.cookies && req.cookies.fullName && typeof req.cookies.fullName === 'string') {
      req.session.user.fullname = req.cookies.fullName;
    }

    // Persist session changes
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    // Sync cookies for client UI (sessionId + fullName)
    try {
      res.cookie('fullName', req.session.user.fullname || req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      const encryptedSid = encryptSessionId(req.session.user.sessionId);
      if (encryptedSid) {
        res.cookie('sessionId', encryptedSid, cachedCookieOptions);
      }
    } catch (cookieErr) {
      console.error(`[mbkauthe] Error syncing cookies during reload:`, cookieErr);
    }

    return true;
  } catch (err) {
    console.error(`[mbkauthe] reloadSessionUser error:`, err);
    return false;
  }
}

const checkRolePermission = (requiredRoles, notAllowed) => {
  return async (req, res, next) => {
    try {
      const authUser = req.auth?.user || req.session?.user;

      if (!authUser || !authUser.id) {
        logAuth(`User not authenticated`);
        if (isJsonRequest(req)) {
          return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
        }
        return renderError(res, req, {
          code: 401,
          error: "Not Logged In",
          message: "You Are Not Logged In. Please Log In To Continue.",
          pagename: "Login",
          page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
        });
      }

      // Use role from validateSession to avoid additional DB query
      const userRole = req.userRole || authUser.role;

      // SuperAdmin bypasses all role checks
      if(authUser.role === "SuperAdmin" || userRole === "SuperAdmin") {
        return next();
      }

      // Check notAllowed role
      if (notAllowed && userRole === notAllowed) {
        if (isJsonRequest(req)) {
          return res.status(403).json(createErrorResponse(403, ErrorCodes.ROLE_NOT_ALLOWED));
        }
        return renderError(res, req, {
          code: 403,
          error: "Access Denied",
          message: "You are not allowed to access this resource",
          pagename: "Home",
          page: `/${mbkautheVar.loginRedirectURL}`
        });
      }

      // Convert to array if single role provided
      const rolesArray = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

      // Check for "Any" or "any" role
      if (rolesArray.includes("Any") || rolesArray.includes("any") || rolesArray.includes("*")) {
        return next();
      }

      // Check if user role is in allowed roles
      if (!rolesArray.includes(userRole)) {
        if (isJsonRequest(req)) {
          return res.status(403).json(createErrorResponse(403, ErrorCodes.INSUFFICIENT_PERMISSIONS));
        }
        return renderError(res, req, {
          code: 403,
          error: "Access Denied",
          message: "You do not have permission to access this resource",
          pagename: "Home",
          page: `/${mbkautheVar.loginRedirectURL}`
        });
      }

      next();
    } catch (err) {
      console.error(`[mbkauthe] Permission check error:`, err);
      res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  };
};

const validateSessionAndRole = (requiredRole, notAllowed, strictTokenValidation = false) => {
  return async (req, res, next) => {
    await validateSession(req, res, async () => {
      await checkRolePermission(requiredRole, notAllowed)(req, res, next);
    }, strictTokenValidation);
  };
};

const authenticate = (authentication) => {
  return (req, res, next) => {
    const token = extractAuthorizationToken(req.headers?.authorization ?? req.headers?.["authorization"]);
    if (timingSafeTokenMatch(token, authentication)) {
      logAuth(`Authentication successful`);
      next();
    } else {
      logAuth(`Authentication failed`);
      res.status(401).send("Unauthorized");
    }
  };
};

// Strict validation helpers (reject token-based auth)
const strictValidateSession = (req, res, next) => validateSession(req, res, next, true);
const strictValidateSessionAndRole = (requiredRole, notAllowed) => validateSessionAndRole(requiredRole, notAllowed, true);

// Short aliases for convenience
const sessVal = validateSession;
const sessRole = validateSessionAndRole;
const roleChk = checkRolePermission;

// short strict validation aliases
const strictSessVal = strictValidateSession;
const strictSessRole = strictValidateSessionAndRole;

export {
  validateSession, validateApiSession, checkRolePermission,
  validateSessionAndRole, authenticate, reloadSessionUser,
  strictValidateSession, strictValidateSessionAndRole,
  sessVal, sessRole, roleChk, strictSessVal, strictSessRole
}