import { dblogin, dialect } from "#pool.js";
import { mbkautheVar, hashApiToken } from "#config.js";
import { renderError } from "#response.js";
import { clearSessionCookies, cachedCookieOptions, encryptSessionId } from "#cookies.js";
import { ErrorCodes, createErrorResponse } from "../utils/errors.js";
import { extractAuthorizationToken, timingSafeTokenMatch } from "../utils/timingSafeToken.js";
import { AuthRepository } from "../db/AuthRepository.js";
import { GlobalPermissions, hasPermission, resolvePermission } from "../permissions.js";
import { attachSessionPermissions } from "../permissionSession.js";
import { createLogger } from "../utils/logger.js";

const IS_DEV = process.env.env === 'dev' || process.env.test === 'dev' || process.env.NODE_ENV === 'development';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (val) => typeof val === 'string' && UUID_RE.test(val);
const MAX_API_TOKEN_LENGTH = 4096;
const API_TOKEN_LAST_USED_INTERVAL_MS = 15 * 60 * 1000;
const API_TOKEN_SESSION_RESTORE = Symbol('mbkauthe.apiTokenSessionRestore');
const apiTokenLastUsedCache = new Map();
const authRepo = new AuthRepository({ db: dblogin, dialect });
const logAuth = createLogger("auth");
const DEFAULT_PERMISSION = GlobalPermissions.basic.access;

/**
 * Build a human-readable "Required <label>: a or b" clause for 403 responses.
 * @param {Array<string>|string} values
 * @param {string} label
 * @returns {string}
 */
function describeRequirement(values, label) {
  const items = (Array.isArray(values) ? values : [values])
    .filter((value) => value !== undefined && value !== null && String(value).trim() !== "")
    .map((value) => String(value));
  return items.length ? `Required ${label}: ${items.join(" or ")}` : "";
}

function pruneApiTokenLastUsedCache(now) {
  if (apiTokenLastUsedCache.size < 10000) return;
  const staleBefore = now - (API_TOKEN_LAST_USED_INTERVAL_MS * 2);
  for (const [tokenId, lastTouchedAt] of apiTokenLastUsedCache) {
    if (lastTouchedAt < staleBefore) apiTokenLastUsedCache.delete(tokenId);
  }
}

function updateApiTokenLastUsedThrottled(tokenId) {
  if (!tokenId) return;
  const now = Date.now();
  const lastTouchedAt = apiTokenLastUsedCache.get(tokenId) || 0;
  if (now - lastTouchedAt < API_TOKEN_LAST_USED_INTERVAL_MS) return;

  pruneApiTokenLastUsedCache(now);
  apiTokenLastUsedCache.set(tokenId, now);
  authRepo.updateApiTokenLastUsed(tokenId).catch((e) => {
    apiTokenLastUsedCache.delete(tokenId);
    console.error(`[mbkauthe] Failed to update token usage:`, e);
  });
}

function isJsonRequest(req) {
  if (!req?.headers) return false;
  const accept = (req.headers.accept || "").toLowerCase();
  const userAgent = (req.headers["user-agent"] || "").toLowerCase();
  const url = (req.originalUrl || req.url || "").toLowerCase();
  const path = (req.path || "").toLowerCase();

  if (userAgent.trim() === "json") return true;
  if (url.startsWith("/mbkauthe/api/") || url.startsWith("/api/") || path.startsWith("/mbkauthe/api/") || path.startsWith("/api/")) return true;
  if ((req.headers["x-requested-with"] || "").toLowerCase() === "xmlhttprequest") return true;
  if ((accept.includes("application/json") || accept.includes("json") || accept.includes("*/*")) && !accept.includes("text/html")) return true;

  const nonBrowser = /curl|wget|httpie|python-requests|python|go-http-client|java\/|php|node-fetch|axios|postman|insomnia|okhttp/;
  const browser = /mozilla|applewebkit|chrome|safari|firefox|edg|msie|trident|opera/;
  return nonBrowser.test(userAgent) && !browser.test(userAgent);
}

async function validateTokenAuthentication(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
  const token = parts[1];

  if (!token.startsWith('mbk_')) return null;
  if (token.length > MAX_API_TOKEN_LENGTH) return { error: 'INVALID_TOKEN' };

  const row = await authRepo.getApiTokenByHash(hashApiToken(token));
  if (!row) return { error: 'INVALID_TOKEN' };
  const expiresAt = row.expires_at;
  if (expiresAt && new Date(expiresAt) <= new Date()) return { error: 'TOKEN_EXPIRED' };

  const permissions = row.permissions || {};

  updateApiTokenLastUsedThrottled(row.id);

  return {
    user_id: row.user_id || undefined,
    username: row.username,
    full_name: row.full_name,
    role: row.role,
    session_id: 'api-token-session',
    is_active: row.is_active,
    token_permissions: Array.isArray(permissions.permissions)
      ? permissions.permissions.map((p) => (typeof p === 'string' ? p.trim().toLowerCase() : '')).filter(Boolean)
      : [],
  };
}

function attachApiTokenUser(req, res, tokenUser) {
  const tokenPermissions = Array.isArray(tokenUser.token_permissions) && tokenUser.token_permissions.length > 0
    ? { allows: tokenUser.token_permissions, denies: [] }
    : null;

  const user = {
    user_id: tokenUser.user_id,
    username: tokenUser.username,
    full_name: tokenUser.full_name,
    role: tokenUser.role,
    session_id: tokenUser.session_id,
  };

  // A token only carries the permissions it was explicitly granted. Legacy
  // tokens (no stored permission list) keep their historical behaviour: no
  // effective permissions, so permission-gated routes stay closed to them.
  if (tokenPermissions) user.permissions = tokenPermissions;

  req.auth = {
    type: 'api-token',
    user,
    permissions: tokenPermissions,
  };

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

const hasAppAccess = (role, allowedApps) =>
  role === "superadmin" ||
  (Array.isArray(allowedApps) && allowedApps.length > 0 && allowedApps.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME));

function destroySessionCookies(req, res) {
  req.session?.destroy?.(() => {});
  clearSessionCookies(res);
}

function respondSessionFailure(req, res, { prefersJson, code, errorCode, error, message, page, pagename = "Login" }) {
  destroySessionCookies(req, res);
  if (prefersJson) return res.status(code).json(createErrorResponse(code, errorCode));
  return renderError(res, req, { code, error, message, pagename, page });
}

async function validateCookieSession(req, res, next, { prefersJson }) {
  if (!req.session.user) {
    if (IS_DEV) {
      logAuth(`User not authenticated`);
      logAuth(`req.session.user: %O`, req.session.user);
    }
    if (prefersJson) return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
    return res.redirect(302, `/mbkauthe/login?${new URLSearchParams({ redirect: req.originalUrl, reason: 'logged_out' }).toString()}`);
  }

  try {
    const { session_id } = req.session.user;
    const loginRedirect = `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`;

    if (!session_id || !isUuid(session_id)) {
      console.warn(`[mbkauthe] Missing session_id for user "${req.session.user.username}"`);
      return respondSessionFailure(req, res, {
        prefersJson, code: 401, errorCode: ErrorCodes.SESSION_EXPIRED,
        error: "Session Expired", message: "Your Session Has Expired. Please Log In Again.", page: loginRedirect,
      });
    }

    const sessionRow = await authRepo.getSessionAuthData(session_id, prefersJson ? 'validate-app-session-for-api' : 'validate-app-session');

    if (!sessionRow) {
      logAuth(`Session not found for user "${req.session.user.username}"`);
      return respondSessionFailure(req, res, {
        prefersJson, code: 401, errorCode: prefersJson ? ErrorCodes.SESSION_INVALID : ErrorCodes.SESSION_EXPIRED,
        error: "Session Expired", message: "Your Session Has Expired. Please Log In Again.", page: loginRedirect,
      });
    }

    if (sessionRow.expires_at) {
      const expiresMs = sessionRow.expires_at instanceof Date ? sessionRow.expires_at.getTime() : Date.parse(sessionRow.expires_at);
      if (!Number.isNaN(expiresMs) && expiresMs <= Date.now()) {
        logAuth(`Session invalidated (expired) for user "${sessionRow.username || req.session.user.username}"`);
        return respondSessionFailure(req, res, {
          prefersJson, code: 401, errorCode: ErrorCodes.SESSION_EXPIRED,
          error: "Session Expired", message: "Your Session Has Expired. Please Log In Again.", page: loginRedirect,
        });
      }
    }

    if (!sessionRow.is_active) {
      logAuth(`Account is inactive for user "${sessionRow.username || req.session.user.username}"`);
      return respondSessionFailure(req, res, {
        prefersJson, code: 401, errorCode: ErrorCodes.ACCOUNT_INACTIVE,
        error: "Account Inactive", message: "Your Account Is Inactive. Please Contact Support.",
        pagename: "Support", page: "https://mbktech.org/Support",
      });
    }

    if (!hasAppAccess(sessionRow.role, sessionRow.allowed_apps)) {
      console.warn(`[mbkauthe] User "${sessionRow.username || req.session.user.username}" is not authorized to use the application "${mbkautheVar.APP_NAME}"`);
      return respondSessionFailure(req, res, {
        prefersJson, code: 401, errorCode: ErrorCodes.APP_NOT_AUTHORIZED,
        error: "Unauthorized", message: `You Are Not Authorized To Use The Application "${mbkautheVar.APP_NAME}"`,
        pagename: "Home", page: mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard'
      });
    }

    req.userRole = sessionRow.role;
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
        if (!tokenUser.is_active) {
          return res.status(401).json(createErrorResponse(401, ErrorCodes.ACCOUNT_INACTIVE));
        }

        attachApiTokenUser(req, res, tokenUser);

        return next();
      }

      return res.status(401).json(createErrorResponse(401, tokenUser?.error === 'TOKEN_EXPIRED' ? ErrorCodes.API_TOKEN_EXPIRED : ErrorCodes.INVALID_AUTH_TOKEN));
    } catch (err) {
      console.error(`[mbkauthe] Token validation error:`, err);
      return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
    }
  }

  return validateCookieSession(req, res, next, { prefersJson: isJsonRequest(req) });
}

async function validateApiSession(req, res, next) {
  return req.headers.authorization ? validateSession(req, res, next) : validateCookieSession(req, res, next, { prefersJson: true });
}

async function reloadSessionUser(req, res) {
  if (!req.session?.user?.username) return false;
  try {
    const { session_id } = req.session.user;
    if (!session_id) {
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return false;
    }

    const row = await authRepo.getSessionWithUserForReload(String(session_id), 'reload-session-user');
    if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) {
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return false;
    }

    if (row.role !== 'superadmin') {
      const allowed = row.allowed_apps;
      if (!Array.isArray(allowed) || !allowed.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        req.session.destroy(() => {});
        clearSessionCookies(res);
        return false;
      }
    }

    req.session.user.username = row.username;
    req.session.user.role = row.role;
    req.session.user.allowed_apps = row.allowed_apps;
    req.session.user.user_id = row.user_id || undefined;

    if (typeof row.full_name === 'string' && row.full_name.trim() !== '') {
      req.session.user.full_name = row.full_name;
    } else if (typeof req.cookies?.full_name === 'string') {
      req.session.user.full_name = req.cookies.full_name;
    }

    // Recompute + refresh the session-cached effective permissions (login/session
    // refresh only — never on the per-request authorization path).
    await attachSessionPermissions(req.session.user, row.username);

    await new Promise((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));

    try {
      res.cookie('full_name', req.session.user.full_name || req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      const encryptedSid = encryptSessionId(req.session.user.session_id);
      if (encryptedSid) res.cookie('session_id', encryptedSid, cachedCookieOptions);
    } catch (cookieErr) {
      console.error(`[mbkauthe] Error syncing cookies during reload:`, cookieErr);
    }

    return true;
  } catch (err) {
    console.error(`[mbkauthe] reloadSessionUser error:`, err);
    return false;
  }
}

const checkRolePermission = (requiredRoles, notAllowed) => async (req, res, next) => {
  try {
    const authUser = req.auth?.user || req.session?.user;
    if (!authUser?.username) {
      logAuth(`User not authenticated`);
      if (isJsonRequest(req)) return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
      return renderError(res, req, {
        code: 401, error: "Not Logged In", message: "You Are Not Logged In. Please Log In To Continue.",
        pagename: "Login", page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    const userRole = (req.userRole || authUser.role || "").toLowerCase();
    if (userRole === "superadmin") return next();

    const homeRedirect = mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';
    const notAllowedNorm = typeof notAllowed === 'string' ? notAllowed.toLowerCase() : null;

    if (notAllowedNorm && userRole === notAllowedNorm) {
      const requirement = `Not permitted role: ${notAllowedNorm}`;
      if (isJsonRequest(req)) return res.status(403).json(createErrorResponse(403, ErrorCodes.ROLE_NOT_ALLOWED, {
        notAllowedRole: notAllowedNorm,
        message: `You are not allowed to access this resource. ${requirement}`,
      }));
      return renderError(res, req, {
        code: 403, error: "Access Denied", message: `You are not allowed to access this resource. ${requirement}`,
        pagename: "Home", page: homeRedirect
      });
    }

    const rolesArray = (Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles]).map((r) => (typeof r === 'string' ? r.toLowerCase() : r));
    if (rolesArray.includes("any") || rolesArray.includes("*") || rolesArray.includes(userRole)) {
      return next();
    }

    const requiredRoleNames = rolesArray.filter((r) => typeof r === "string" && r !== "any" && r !== "*");
    const requirement = describeRequirement(requiredRoleNames, "role");
    if (isJsonRequest(req)) return res.status(403).json(createErrorResponse(403, ErrorCodes.INSUFFICIENT_PERMISSIONS, {
      requiredRole: requiredRoleNames.length === 1 ? requiredRoleNames[0] : requiredRoleNames,
      message: `You do not have permission to access this resource${requirement ? `. ${requirement}` : ""}`,
    }));
    return renderError(res, req, {
      code: 403, error: "Access Denied",
      message: `You do not have permission to access this resource${requirement ? `. ${requirement}` : ""}`,
      pagename: "Home", page: homeRedirect
    });
  } catch (err) {
    console.error(`[mbkauthe] Permission check error:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

const validateSessionAndPermission = (permission = DEFAULT_PERMISSION, strictTokenValidation = false) => async (req, res, next) => {
  await validateSession(req, res, async () => {
    await checkPermission(permission)(req, res, next);
  }, strictTokenValidation);
};

const checkPermission = (permission = DEFAULT_PERMISSION) => async (req, res, next) => {
  try {
    const authUser = req.auth?.user || req.session?.user;
    if (!authUser?.username) {
      logAuth(`User not authenticated`);
      if (isJsonRequest(req)) return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
      return renderError(res, req, {
        code: 401, error: "Not Logged In", message: "You Are Not Logged In. Please Log In To Continue.",
        pagename: "Login", page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    // In-memory authorization decision (SuperAdmin bypass, deny beats allow,
    // wildcard-aware). No database access on this path.
    const resolvedPermission = resolvePermission(permission);
    if (hasPermission(authUser, resolvedPermission)) return next();

    const homeRedirect = mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';
    if (isJsonRequest(req)) return res.status(403).json(createErrorResponse(403, ErrorCodes.INSUFFICIENT_PERMISSIONS, {
      requiredPermission: resolvedPermission,
      message: `You do not have permission to access this resource. Required permission: ${resolvedPermission}`,
    }));
    return renderError(res, req, {
      code: 403, error: "Access Denied",
      message: `You do not have permission to access this resource. Required permission: ${resolvedPermission}`,
      pagename: "Home", page: homeRedirect
    });
  } catch (err) {
    console.error(`[mbkauthe] Permission check error:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

const validateSessionAndRole = (requiredRole, notAllowed, strictTokenValidation = false) => async (req, res, next) => {
  await validateSession(req, res, async () => {
    await checkRolePermission(requiredRole, notAllowed)(req, res, next);
  }, strictTokenValidation);
};

const authenticate = (authentication) => (req, res, next) => {
  const token = extractAuthorizationToken(req.headers?.authorization ?? req.headers?.["authorization"]);
  if (timingSafeTokenMatch(token, authentication)) {
    logAuth(`Authentication successful`);
    next();
  } else {
    logAuth(`Authentication failed`);
    res.status(401).send("Unauthorized");
  }
};

const strictValidateSession = (req, res, next) => validateSession(req, res, next, true);
const strictValidateSessionAndRole = (requiredRole, notAllowed) => validateSessionAndRole(requiredRole, notAllowed, true);

const sessVal = validateSession;
const sessRole = validateSessionAndRole;
const roleChk = checkRolePermission;
const strictSessVal = strictValidateSession;
const strictSessRole = strictValidateSessionAndRole;
const permChk = checkPermission;
const sessPerm = validateSessionAndPermission;

export {
  validateSession, validateApiSession, checkRolePermission,
  validateSessionAndRole, authenticate, reloadSessionUser,
  strictValidateSession, strictValidateSessionAndRole,
  sessVal, sessRole, roleChk, strictSessVal, strictSessRole,
  checkPermission, validateSessionAndPermission, permChk, sessPerm
};