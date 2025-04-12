import { dblogin } from "./pool.js";

async function validateSession(req, res, next) {
  if (!req.session.user) {
    return res.render("templates/Error/NotLoggedIn.handlebars", {
      currentUrl: req.originalUrl,
    });
  }

  try {
    const { id, sessionId } = req.session.user;
    const query = `SELECT "SessionId", "Active" FROM "Users" WHERE "id" = $1`;
    const result = await dblogin.query(query, [id]);

    // Check if user exists and session ID matches
    if (result.rows.length === 0 || result.rows[0].SessionId !== sessionId) {
      console.log(
        `Session invalidated for user \"${req.session.user.username}\"`
      );
      req.session.destroy();
      // ...existing code...
      return res.render("templates/Error/SessionExpire.handlebars", {
        currentUrl: req.originalUrl,
      });
      // ...existing code...
    }

    // Check if the user account is inactive
    if (!result.rows[0].Active) {
      console.log(
        `Account is inactive for user \"${req.session.user.username}\"`
      );
      req.session.destroy();
      res.clearCookie("connect.sid");
      return res.render("templates/Error/AccountInactive.handlebars", {
        currentUrl: req.originalUrl,
      });
    }

    next(); // Proceed if everything is valid
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
        return res
          .status(401)
          .json({ success: false, message: "User not found" });
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
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
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

    // Dynamically select fields from Users table based on `parameters`
    const userFields = [
      "Password", "UserName", "Role", "Active", "GuestRole", "HaveMailAccount",
    ];
    const profileFields = [
      "FullName", "email", "Image", "ProjectLinks", "SocialAccounts", "Bio",
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

    // Prepare queries based on required fields
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

    // Combine results
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

export { validateSession, checkRolePermission, validateSessionAndRole, getUserData , authenticate};