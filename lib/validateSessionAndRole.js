import { dblogin } from "./pool.js";
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

// Get consistent cookie options
const getCookieOptions = () => ({
  maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
  domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
  secure: mbkautheVar.IS_DEPLOYED === 'true' ? 'auto' : false,
  sameSite: 'lax',
  path: '/',
  httpOnly: true
});

async function validateSession(req, res, next) {
  // First check if we have a session cookie
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
      console.error("Session validation error:", err);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  }

  if (!req.session.user) {
    console.log("User not authenticated");
    console.log(req.session.user);
    return res.render("templates/Error/NotLoggedIn.handlebars", {
      currentUrl: req.originalUrl,
    });
  }

  try {
    const { id, sessionId } = req.session.user;
    const query = `SELECT "SessionId", "Active", "Role", "AllowedApps" FROM "Users" WHERE "id" = $1`;
    const result = await dblogin.query(query, [id]);
    const userResult = result.rows[0];

    if (result.rows.length === 0 || userResult.SessionId !== sessionId) {
      console.log(`Session invalidated for user "${req.session.user.username}"`);
      req.session.destroy();
      const cookieOptions = getCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);
      return res.render("templates/Error/SessionExpire.handlebars", {
        currentUrl: req.originalUrl,
      });
    }

    if (!userResult.Active) {
      console.log(`Account is inactive for user "${req.session.user.username}"`);
      req.session.destroy();
      const cookieOptions = getCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);
      return res.render("templates/Error/AccountInactive.handlebars", {
        currentUrl: req.originalUrl,
      });
    }

    if (userResult.Role !== "SuperAdmin") {
      const allowedApps = userResult.AllowedApps;
      if (!allowedApps || !allowedApps.includes(mbkautheVar.APP_NAME)) {
        console.warn(`User \"${req.session.user.username}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        req.session.destroy();
        const cookieOptions = getCookieOptions();
        res.clearCookie("mbkauthe.sid", cookieOptions);
        res.clearCookie("sessionId", cookieOptions);
        res.clearCookie("username", cookieOptions);
        return res.render("templates/Error/Error.handlebars", {
          error: `You Are Not Authorized To Use The Application \"${mbkautheVar.APP_NAME}\"`,
        });
      }
    }

    next();
  } catch (err) {
    console.error("Session validation error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

const checkRolePermission = (requiredRole) => {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user || !req.session.user.id) {
        console.log("User not authenticated");
        console.log(req.session);
        return res.render("templates/Error/NotLoggedIn.handlebars", {
          currentUrl: req.originalUrl,
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
        return res.render("templates/Error/AccessDenied.handlebars", {
          currentRole: userRole,
          requiredRole: requiredRole,
        });
      }

      next();
    } catch (err) {
      console.error("Permission check error:", err);
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

async function getUserData(UserName, parameters) {
  try {
    if (!parameters || parameters.length === 0) {
      throw new Error("Parameters are required to fetch user data");
    }

    const userFields = [
      "Password", "UserName", "Role", "Active", "GuestRole", "HaveMailAccount", "AllowedApps",
    ];
    const profileFields = [
      "FullName", "email", "Image", "ProjectLinks", "SocialAccounts", "Bio", "Positions",
    ];

    let userParameters = [];
    let profileParameters = [];

    if (parameters === "profiledata") {
      userParameters = userFields.filter(field => field !== "Password");
      profileParameters = profileFields;
    } else {
      userParameters = userFields.filter(field => parameters.includes(field));
      profileParameters = profileFields.filter(field => parameters.includes(field));
    }

    let userResult = {};
    if (userParameters.length > 0) {
      const userQuery = `SELECT ${userParameters.map(field => `"${field}"`).join(", ")} 
                         FROM "Users" WHERE "UserName" = $1`;
      const userQueryResult = await dblogin.query(userQuery, [UserName]);
      if (userQueryResult.rows.length === 0) return { error: "User not found" };
      userResult = userQueryResult.rows[0];
    }

    let profileResult = {};
    if (profileParameters.length > 0) {
      const profileQuery = `SELECT ${profileParameters.map(field => `"${field}"`).join(", ")} 
                            FROM profiledata WHERE "UserName" = $1`;
      const profileQueryResult = await dblogin.query(profileQuery, [UserName]);
      if (profileQueryResult.rows.length === 0) return { error: "Profile data not found" };
      profileResult = profileQueryResult.rows[0];
    }

    const combinedResult = { ...userResult, ...profileResult };
    return combinedResult;
  } catch (err) {
    console.error("Error fetching user data:", err.message);
    throw err;
  }
}

const authenticate = (authentication) => {
  return (req, res, next) => {
    const token = req.headers["authorization"];
    console.log(`Received token: ${token}`);
    if (token === authentication) {
      console.log("Authentication successful");
      next();
    } else {
      console.log("Authentication failed");
      res.status(401).send("Unauthorized");
    }
  };
};

export { validateSession, checkRolePermission, validateSessionAndRole, getUserData, authenticate };