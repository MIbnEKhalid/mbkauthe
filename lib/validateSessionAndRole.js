import { dblogin } from "./pool.js";
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

const getCookieOptions = () => ({
  maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
  domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
  secure: mbkautheVar.IS_DEPLOYED === 'true',
  sameSite: 'lax',
  path: '/',
  httpOnly: true
});

const getClearCookieOptions = () => ({
  domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
  secure: mbkautheVar.IS_DEPLOYED === 'true',
  sameSite: 'lax',
  path: '/',
  httpOnly: true
});

async function validateSession(req, res, next) {
  if (!req.session.user) {
    console.log("[mbkauthe] User not authenticated");
    console.log("[mbkauthe]: ", req.session.user);
    return res.render("Error/dError.handlebars", {
      layout: false,
      code: 401,
      error: "Not Logged In",
      message: "You Are Not Logged In. Please Log In To Continue.",
      pagename: "Login",
      page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
    });
  }

  try {
    const { id, sessionId, role, allowedApps } = req.session.user;

    // Normalize sessionId to lowercase for consistent comparison
    const normalizedSessionId = sessionId.toLowerCase();

    // Single optimized query to validate session
    const query = `SELECT "SessionId", "Active" FROM "Users" WHERE "id" = $1`;
    const result = await dblogin.query({ name: 'validate-user-session', text: query, values: [id] });

    if (result.rows.length === 0 || result.rows[0].SessionId.toLowerCase() !== normalizedSessionId) {
      console.log(`[mbkauthe] Session invalidated for user "${req.session.user.username}"`);
      req.session.destroy();
      const cookieOptions = getClearCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);
      return res.render("Error/dError.handlebars", {
        layout: false,
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
      const cookieOptions = getClearCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);
      return res.render("Error/dError.handlebars", {
        layout: false,
        code: 401,
        error: "Account Inactive",
        message: "Your Account Is Inactive. Please Contact Support.",
        pagename: "Support",
        page: "https://mbktech.org/Support",
      });
    }

    if (role !== "SuperAdmin") {
      if (!allowedApps || !allowedApps.some(app => app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        console.warn(`[mbkauthe] User \"${req.session.user.username}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        req.session.destroy();
        const cookieOptions = getClearCookieOptions();
        res.clearCookie("mbkauthe.sid", cookieOptions);
        res.clearCookie("sessionId", cookieOptions);
        res.clearCookie("username", cookieOptions);
        return res.render("Error/dError.handlebars", {
          layout: false,
          code: 401,
          error: "Unauthorized",
          message: `You Are Not Authorized To Use The Application \"${mbkautheVar.APP_NAME}\"`,
          pagename: "Home",
          page: `/${mbkautheVar.loginRedirectURL}`
        });
      }
    }

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
        return res.render("Error/dError.handlebars", {
          layout: false,
          code: 401,
          error: "Not Logged In",
          message: "You Are Not Logged In. Please Log In To Continue.",
          pagename: "Login",
          page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
        });
      }

      const userId = req.session.user.id;

      const query = `SELECT "Role" FROM "Users" WHERE "id" = $1`;
      const result = await dblogin.query({ name: 'check-role-permission', text: query, values: [userId] });

      if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: "Authentication failed" });
      }

      const userRole = result.rows[0].Role;

      // Check notAllowed role
      if (notAllowed && userRole === notAllowed) {
        return res.render("Error/dError.handlebars", {
          layout: false,
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
        return res.render("Error/dError.handlebars", {
          layout: false,
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
    console.log(`[mbkauthe] Received token: ${token}`);
    if (token === authentication) {
      console.log("[mbkauthe] Authentication successful");
      next();
    } else {
      console.log("[mbkauthe] Authentication failed");
      res.status(401).send("Unauthorized");
    }
  };
};

const authapi = (requiredRole = []) => {
  return (req, res, next) => {
    const token = req.headers["authorization"];

    // Validate token
    if (!token) {
      console.warn("[mbkauthe] [authapi] No token provided in the request headers");
      return res.status(401).json({
        success: false,
        message: "Authorization token is required"
      });
    }

    if (typeof token !== 'string' || token.length === 0 || token.length > 512) {
      console.warn("[mbkauthe] [authapi] Invalid token format");
      return res.status(401).json({
        success: false,
        message: "Invalid authorization token format"
      });
    }

    if (typeof token === 'string' && token.length >= 64) {
      console.log("[mbkauthe] [authapi] Received request with token:", token.substring(0, 3) + ".....", token.charAt(63));
    } else {
      console.log("[mbkauthe] [authapi] Received request with short token");
    }

    // Single query to validate API key and fetch user in one DB round trip.
    (async () => {
      try {
        const jointQuery = `
          SELECT u.id, u."UserName", u."Active", u."Role", k."key" as apikey
          FROM "UserAuthApiKey" k
          JOIN "Users" u ON u."UserName" = k.username
          WHERE k."key" = $1 AND u."Active" = true
          LIMIT 1
        `;

        const result = await dblogin.query({ name: 'validate-api-key', text: jointQuery, values: [token] });

        if (result.rows.length === 0) {
          console.warn("[mbkauthe] [authapi] Invalid token or associated user inactive");
          return res.status(401).json({ success: false, message: "The AuthApiToken Is Invalid or user inactive" });
        }

        const user = result.rows[0];

        if (user.UserName === "demo") {
          console.warn("[mbkauthe] [authapi] Demo user attempted to access an endpoint. Access denied.");
          return res.status(401).json({ success: false, message: "Demo user is not allowed to access endpoints" });
        }

        // role check
        if ((requiredRole && user.Role !== requiredRole) && user.Role !== "SuperAdmin") {
          console.warn(`[mbkauthe] [authapi] User does not have the required role. Required: ${requiredRole}, User's role: ${user.Role}`);
          return res.status(403).json({ success: false, message: `Access denied. Required role: ${requiredRole}` });
        }

        req.user = {
          username: user.UserName,
          UserName: user.UserName,
          role: user.Role,
          Role: user.Role,
        };

        next();
      } catch (err) {
        console.error("[mbkauthe] [authapi] Database error while validating token/user:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }
    })();
  };
};

export { validateSession, checkRolePermission, validateSessionAndRole, authenticate, authapi };