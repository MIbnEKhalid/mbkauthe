import { dblogin } from "../database/pool.js";
import { mbkautheVar } from "../config/index.js";
import { renderError } from "../utils/response.js";
import { clearSessionCookies, cachedCookieOptions, readAccountListFromCookie } from "../config/cookies.js";

async function validateSession(req, res, next) {
  if (!req.session.user) {
    console.log("[mbkauthe] User not authenticated");
    const remembered = readAccountListFromCookie(req) || [];
    const hasRemembered = remembered.some(acct => acct && typeof acct.sessionId === 'string' && acct.sessionId.length > 0);
    const pageTarget = hasRemembered ? '/mbkauthe/accounts' : `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`;
    const message = hasRemembered
      ? "Another saved account is available. Open the switch page to continue."
      : "You Are Not Logged In. Please Log In To Continue.";
    return renderError(res, req, {
      code: 401,
      error: "Not Logged In",
      message,
      pagename: hasRemembered ? "Switch Account" : "Login",
      page: pageTarget,
    });
  }

  try {
    const { id, sessionId, role, allowedApps } = req.session.user;

    // Defensive checks for sessionId and allowedApps
    if (!sessionId) {
      console.warn(`[mbkauthe] Missing sessionId for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, req, {
        code: 401,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    // Normalize sessionId (DB id) for consistent comparison
    const normalizedSessionId = sessionId;

    // Validate session by DB primary key id and join to user
    const query = `SELECT s.id as sid, s.expires_at, u."Active", u."Role"
                   FROM "Sessions" s
                   JOIN "Users" u ON s."UserName" = u."UserName"
                   WHERE s.id = $1 LIMIT 1`;
    const result = await dblogin.query({ name: 'validate-app-session', text: query, values: [normalizedSessionId] });

    if (result.rows.length === 0) {
      console.log(`[mbkauthe] Session not found for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, req, {
        code: 401,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    const sessionRow = result.rows[0];

    // Check expired
    if (sessionRow.expires_at && new Date(sessionRow.expires_at) <= new Date()) {
      console.log(`[mbkauthe] Session invalidated (expired) for user "${req.session.user.username}"`);
      // destroy and clear cookies
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, req, {
        code: 401,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }


    if (!sessionRow.Active) {
      console.log(`[mbkauthe] Account is inactive for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, req, {
        code: 401,
        error: "Account Inactive",
        message: "Your Account Is Inactive. Please Contact Support.",
        pagename: "Support",
        page: "https://mbktech.org/Support",
      });
    }

    if (role !== "SuperAdmin") {
      // If allowedApps is not provided or not an array, treat as no access
      const hasAllowedApps = Array.isArray(allowedApps) && allowedApps.length > 0;
      if (!hasAllowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        console.warn(`[mbkauthe] User \"${req.session.user.username}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        req.session.destroy();
        clearSessionCookies(res);
        return renderError(res, req, {
          code: 401,
          error: "Unauthorized",
          message: `You Are Not Authorized To Use The Application \"${mbkautheVar.APP_NAME}\"`,
          pagename: "Home",
          page: `/${mbkautheVar.loginRedirectURL}`
        });
      }
    }

    // Store user role in request for checkRolePermission to use
    req.userRole = result.rows[0].Role;

    next();
  } catch (err) {
    console.error("[mbkauthe] Session validation error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

/**
 * API-friendly session validation middleware
 * Returns JSON error responses instead of rendering pages
 */
async function validateApiSession(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND));
  }

  try {
    const { id, sessionId, role, allowedApps } = req.session.user;

    // Defensive checks for sessionId and allowedApps
    if (!sessionId) {
      console.warn(`[mbkauthe] Missing sessionId for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_EXPIRED));
    }

    // Normalize sessionId (DB id) for consistent comparison
    const normalizedSessionId = sessionId;

    // Validate session by DB primary key id and join to user
    const query = `SELECT s.id as sid, s.expires_at, u."Active", u."Role"
                   FROM "Sessions" s
                   JOIN "Users" u ON s."UserName" = u."UserName"
                   WHERE s.id = $1 LIMIT 1`;
    const result = await dblogin.query({ name: 'validate-app-session-for-api', text: query, values: [normalizedSessionId] });

    if (result.rows.length === 0) {
      req.session.destroy();
      clearSessionCookies(res);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_INVALID));
    }

    const sessionRow = result.rows[0];

    // Check expired
    if (sessionRow.expires_at && new Date(sessionRow.expires_at) <= new Date()) {
      req.session.destroy();
      clearSessionCookies(res);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_EXPIRED));
    }


    if (!result.rows[0].Active) {
      console.log(`[mbkauthe] Account is inactive for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.ACCOUNT_INACTIVE));
    }

    if (role !== "SuperAdmin") {
      // If allowedApps is not provided or not an array, treat as no access
      const hasAllowedApps = Array.isArray(allowedApps) && allowedApps.length > 0;
      if (!hasAllowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        console.warn(`[mbkauthe] User \"${req.session.user.username}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        req.session.destroy();
        clearSessionCookies(res);
        return res.status(401).json(createErrorResponse(401, ErrorCodes.APP_NOT_AUTHORIZED));
      }
    }

    // Store user role in request for checkRolePermission to use
    req.userRole = result.rows[0].Role;

    next();
  } catch (err) {
    console.error("[mbkauthe] API session validation error:", err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
}

/**
 * Reload session user values from the database and refresh cookies.
 * - Validates sessionId and active status
 * - Updates `req.session.user` fields (username, role, allowedApps, fullname)
 * - Uses cached `fullName` cookie when available, otherwise queries `Users`
 * - Syncs `username`, `fullName` and `sessionId` cookies
 * Returns: true if session refreshed and valid, false if session invalidated
 */
export async function reloadSessionUser(req, res) {
  if (!req.session || !req.session.user || !req.session.user.id) return false;
  try {
    const { id, sessionId: currentSessionId } = req.session.user;

    if (!currentSessionId) {
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return false;
    }

    const normalizedSessionId = String(currentSessionId);
    const query = `SELECT s.id as sid, s.expires_at, u.id as uid, u."UserName", u."Active", u."Role", u."AllowedApps"
                   FROM "Sessions" s
                   JOIN "Users" u ON s."UserName" = u."UserName"
                   WHERE s.id = $1 LIMIT 1`;
    const result = await dblogin.query({ name: 'reload-session-user', text: query, values: [normalizedSessionId] });

    if (result.rows.length === 0) {
      // Session not found — invalidate session
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return false;
    }

    const row = result.rows[0];

    // Check expired
    if (row.expires_at && new Date(row.expires_at) <= new Date()) {
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return false;
    }

    if (!row.Active) {
      // Account is inactive
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return false;
    }

    // Authorization: ensure allowed for current app unless SuperAdmin
    if (row.Role !== 'SuperAdmin') {
      const allowedApps = row.AllowedApps;
      const hasAllowedApps = Array.isArray(allowedApps) && allowedApps.length > 0;
      if (!hasAllowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        req.session.destroy(() => {});
        clearSessionCookies(res);
        return false;
      }
    }

    // Update session fields
    req.session.user.username = row.UserName;
    req.session.user.role = row.Role;
    req.session.user.allowedApps = row.AllowedApps;

    // Obtain fullname from client cookie cache when present else DB
    if (req.cookies && req.cookies.fullName && typeof req.cookies.fullName === 'string') {
      req.session.user.fullname = req.cookies.fullName;
    } else {
      try {
        const prof = await dblogin.query({ name: 'reload-get-fullname', text: 'SELECT "FullName" FROM "USers" WHERE "UserName" = $1 LIMIT 1', values: [row.UserName] });
        if (prof.rows.length > 0 && prof.rows[0].FullName) req.session.user.fullname = prof.rows[0].FullName;
      } catch (profileErr) {
        console.error('[mbkauthe] Error fetching fullname during reload:', profileErr);
      }
    }

    // Persist session changes
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    // Sync cookies for client UI (non-httpOnly)
    try {
      res.cookie('username', req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('fullName', req.session.user.fullname || req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('sessionId', req.session.user.sessionId, cachedCookieOptions);
    } catch (cookieErr) {
      // Ignore cookie setting errors, session is still refreshed
      console.error('[mbkauthe] Error syncing cookies during reload:', cookieErr);
    }

    return true;
  } catch (err) {
    console.error('[mbkauthe] reloadSessionUser error:', err);
    return false;
  }
}

const checkRolePermission = (requiredRoles, notAllowed) => {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user || !req.session.user.id) {
        console.log("[mbkauthe] User not authenticated");
        return renderError(res, req, {
          code: 401,
          error: "Not Logged In",
          message: "You Are Not Logged In. Please Log In To Continue.",
          pagename: "Login",
          page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
        });
      }

      // Use role from validateSession to avoid additional DB query
      const userRole = req.userRole;

      // Check notAllowed role
      if (notAllowed && userRole === notAllowed) {
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
      if (rolesArray.includes("Any") || rolesArray.includes("any")) {
        return next();
      }

      // Check if user role is in allowed roles
      if (!rolesArray.includes(userRole)) {
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
      console.error("[mbkauthe] Permission check error:", err);
      res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  };
};

const validateSessionAndRole = (requiredRole, notAllowed) => {
  return async (req, res, next) => {
    await validateSession(req, res, async () => {
      await checkRolePermission(requiredRole, notAllowed)(req, res, next);
    });
  };
};

const authenticate = (authentication) => {
  return (req, res, next) => {
    const token = req.headers["authorization"];
    if (token === authentication) {
      console.log("[mbkauthe] Authentication successful");
      next();
    } else {
      console.log("[mbkauthe] Authentication failed");
      res.status(401).send("Unauthorized");
    }
  };
};

export { validateSession, validateApiSession, checkRolePermission, validateSessionAndRole, authenticate };
