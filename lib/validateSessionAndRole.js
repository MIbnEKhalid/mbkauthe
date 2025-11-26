import { dblogin } from "./pool.js";
import { mbkautheVar, renderError, clearSessionCookies } from "./config.js";

async function validateSession(req, res, next) {
  if (!req.session.user) {
    console.log("[mbkauthe] User not authenticated");
    console.log("[mbkauthe]: ", req.session.user);
    return renderError(res, {
      code: 401,
      error: "Not Logged In",
      message: "You Are Not Logged In. Please Log In To Continue.",
      pagename: "Login",
      page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
    });
  }

  try {
    const { id, sessionId, role, allowedApps } = req.session.user;

    // Defensive checks for sessionId and allowedApps
    if (!sessionId) {
      console.warn(`[mbkauthe] Missing sessionId for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, {
        code: 401,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    // Normalize sessionId to lowercase for consistent comparison
    const normalizedSessionId = sessionId.toLowerCase();

    // Single optimized query to validate session and get role
    const query = `SELECT "SessionId", "Active", "Role" FROM "Users" WHERE "id" = $1`;
    const result = await dblogin.query({ name: 'validate-user-session', text: query, values: [id] });

    const dbSessionId = result.rows.length > 0 && result.rows[0].SessionId ? String(result.rows[0].SessionId).toLowerCase() : null;
    if (!dbSessionId || dbSessionId !== normalizedSessionId) {
      if (result.rows.length > 0 && !result.rows[0].SessionId) {
        console.warn(`[mbkauthe] DB sessionId is null for user "${req.session.user.username}"`);
      }
      console.log(`[mbkauthe] Session invalidated for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, {
        code: 401,
        error: "Session Expired",
        message: "Your Session Has Expired. Please Log In Again.",
        pagename: "Login",
        page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
      });
    }

    if (!result.rows[0].Active) {
      console.log(`[mbkauthe] Account is inactive for user "${req.session.user.username}"`);
      req.session.destroy();
      clearSessionCookies(res);
      return renderError(res, {
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
        return renderError(res, {
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

const checkRolePermission = (requiredRoles, notAllowed) => {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user || !req.session.user.id) {
        console.log("[mbkauthe] User not authenticated");
        return renderError(res, {
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
        return renderError(res, {
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
        return renderError(res, {
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


export { validateSession, checkRolePermission, validateSessionAndRole, authenticate };