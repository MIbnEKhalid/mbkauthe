import { dblogin } from "./pool.js";
const mbkautheVar = JSON.parse(process.env.mbkautheVar);
let pool = dblogin;

const getCookieOptions = () => ({
  maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
  domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
  secure: mbkautheVar.IS_DEPLOYED === 'true' ? 'auto' : false,
  sameSite: 'lax',
  path: '/',
  httpOnly: true
});

async function validateSession(req, res, next) {
  if (!req.session.user && req.cookies.sessionId) {
    try {
      const sessionId = req.cookies.sessionId;
      const query = `SELECT * FROM "Users" WHERE "SessionId" = $1`;
      const result = await dblogin.query(query, [sessionId]);
      const userResult = result.rows[0];

      if (result.rows.length > 0) {
        const user = result.rows[0];
        req.session.user = {
          id: user.id,
          username: user.UserName,
          sessionId,
        };
      }
    } catch (err) {
      console.error("[mbkauthe] Session validation error:", err);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  }

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
    const { id, sessionId } = req.session.user;
    const query = `SELECT "SessionId", "Active", "Role", "AllowedApps" FROM "Users" WHERE "id" = $1`;
    const result = await dblogin.query(query, [id]);
    const userResult = result.rows[0];

    if (result.rows.length === 0 || userResult.SessionId !== sessionId) {
      console.log(`[mbkauthe] Session invalidated for user "${req.session.user.username}"`);
      req.session.destroy();
      const cookieOptions = getCookieOptions();
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

    if (!userResult.Active) {
      console.log(`[mbkauthe] Account is inactive for user "${req.session.user.username}"`);
      req.session.destroy();
      const cookieOptions = getCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);
      return res.render("Error/dError.handlebars", {
        layout: false,
        code: 401,
        error: "Account Inactive",
        message: "Your Account Is Inactive. Please Contact Support.",
        pagename: "Support",
        page: "https://mbktechstudio.com/Support",
      });
    }

    if (userResult.Role !== "SuperAdmin") {
      const allowedApps = userResult.AllowedApps;
      if (!allowedApps || !allowedApps.some(app => app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        console.warn(`[mbkauthe] User \"${req.session.user.username}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        req.session.destroy();
        const cookieOptions = getCookieOptions();
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

const checkRolePermission = (requiredRole) => {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user || !req.session.user.id) {
        console.log("[mbkauthe] User not authenticated");
        console.log("[mbkauthe]: ", req.session);
        return res.render("Error/dError.handlebars", {
          layout: false,
          code: 401,
          error: "Not Logged In",
          message: "You Are Not Logged In. Please Log In To Continue.",
          pagename: "Login",
          page: `/mbkauthe/login?redirect=${encodeURIComponent(req.originalUrl)}`,
        });
      }

      if (requiredRole === "Any" || requiredRole === "any") {
        return next();
      }

      const userId = req.session.user.id;

      const query = `SELECT "Role" FROM "Users" WHERE "id" = $1`;
      const result = await dblogin.query(query, [userId]);

      if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: "User not found" });
      }

      const userRole = result.rows[0].Role;
      if (userRole !== requiredRole) {
        return res.render("Error/dError.handlebars", {
          layout: false,
          code: 403,
          error: "Access Denied",
          message: `You do not have permission to access this resource. Required role: ${requiredRole}`,
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

const validateSessionAndRole = (requiredRole) => {
  return async (req, res, next) => {
    await validateSession(req, res, async () => {
      await checkRolePermission(requiredRole)(req, res, next);
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

    if (typeof token === 'string') {
      console.log("[mbkauthe] [authapi] Received request with token:", token[0] + token[1] + token[2], ".....", token[63]);
    } else {
      console.log("[mbkauthe] [authapi] Token is not a valid string:", token);
    }

    if (!token) {
      console.log("[mbkauthe] [authapi] No token provided in the request headers");
      return res.status(401).json({
        success: false,
        message: "Authorization token is required"
      });
    }

    console.log("[mbkauthe] [authapi] Querying database to validate token");
    const tokenQuery = 'SELECT * FROM "UserAuthApiKey" WHERE "key" = $1';
    pool.query(tokenQuery, [token], (err, result) => {
      if (err) {
        console.error("[mbkauthe] [authapi] Database query error while validating token:", err);
        return res.status(500).json({
          success: false,
          message: "Internal Server Error"
        });
      }

      if (result.rows.length === 0) {
        console.log("[mbkauthe] [authapi] Invalid token provided:", token);
        return res.status(401).json({
          success: false,
          message: "The AuthApiToken Is Invalid"
        });
      }

      const username = result.rows[0].username;
      console.log("[mbkauthe] [authapi] Token is valid. Associated username:", username);

      console.log("[mbkauthe] [authapi] Querying database to validate user and role");
      const userQuery = `
                SELECT id, "UserName", "Active", "Role" FROM "Users"
                WHERE "UserName" = $1 AND "Active" = true
            `;

      pool.query(userQuery, [username], (err, userResult) => {
        if (err) {
          console.error("[mbkauthe] [authapi] Database query error while validating user:", err);
          return res.status(500).json({
            success: false,
            message: "Internal Server Error"
          });
        }

        if (userResult.rows.length === 0) {
          console.log("[mbkauthe] [authapi] User does not exist or is not active. Username:", username);
          return res.status(401).json({
            success: false,
            message: "User does not exist or is not active",
          });
        }

        if (username === "demo") {
          console.log("[mbkauthe] [authapi] Demo user attempted to access an endpoint. Access denied.");
          return res.status(401).json({
            success: false,
            message: "Demo user is not allowed to access endpoints",
          });
        }

        const user = userResult.rows[0];
        console.log("[mbkauthe] [authapi] User is valid. User details:", user);

        // Check if role is required and if user has it
        if ((requiredRole && user.Role !== requiredRole) && user.Role !== "SuperAdmin") {
          console.log(`[mbkauthe] [authapi] User does not have the required role. Required: ${requiredRole}, User's role: ${user.Role}`);
          return res.status(403).json({
            success: false,
            message: `Access denied. Required role: ${requiredRole}`,
          });
        }

        console.log("[mbkauthe] [authapi] User has the required role or no specific role is required. Proceeding to next middleware.");
        req.user = {
          username: user.UserName,
          role: user.Role,
          // Add other user properties you might need
        };

        console.log("[mbkauthe] [authapi] Token and user validation successful. Passing control to next middleware.");
        next();
      });
    });
  };
};

export { validateSession, checkRolePermission, validateSessionAndRole, authenticate, authapi };