import express from "express";
import crypto from "crypto";
import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import dotenv from "dotenv";
import { dblogin } from "./pool.js";
import { authenticate } from "./auth.js";
import fetch from 'node-fetch';
import cookieParser from "cookie-parser"; // Import cookie-parser

dotenv.config();
const router = express.Router();
let COOKIE_EXPIRE_TIME = 2 * 24 * 60 * 60 * 1000; //2 days

try {
  const parsedExpireTime = parseInt(process.env.COOKIE_EXPIRE_TIME, 10);
  if (!isNaN(parsedExpireTime) && parsedExpireTime > 0) {
    COOKIE_EXPIRE_TIME = parsedExpireTime * 24 * 60 * 60 * 1000; // Convert days to milliseconds
  } else {
    console.warn("Invalid COOKIE_EXPIRE_TIME in environment variables, using default value");
  }
  WriteConsoleLogs(`Cookie expiration time set to ${COOKIE_EXPIRE_TIME} days for deployed environment`);
} catch (error) {
  WriteConsoleLogs("Error parsing COOKIE_EXPIRE_TIME:", error);
}

async function WriteConsoleLogs(message) {
    const appName = process.env.AppName;
    try {
      const query = `
        INSERT INTO mbkauthlogs (app_name, message)
        VALUES ($1, $2)
      `;
      await dblogin.query(query, [appName, message]);
      console.log(`Logged message: ${message}`);
    } catch (error) {
      console.error("Error logging message:", error.message);
    }
  }

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

router.use(
  session({
    store: new PgSession({
      pool: dblogin, // Connection pool
      tableName: "session", // Use another table-name than the default "session" one
    }),
    secret: process.env.SESSION_SECRET_KEY, // Replace with your secret key
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: COOKIE_EXPIRE_TIME,
      DOMAIN: process.env.IS_DEPLOYED === 'true' ? `.${process.env.DOMAIN}` : undefined, // Use root DOMAIN for subDOMAIN sharing
      httpOnly: true,
      secure: process.env.IS_DEPLOYED === 'true', // Use secure cookies in production
    },
  })
);



router.use(cookieParser()); // Use cookie-parser middleware

router.use((req, res, next) => {
  if (req.session && req.session.user) {
    const userAgent = req.headers["user-agent"];
    const userIp =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const formattedIp = userIp === "::1" ? "127.0.0.1" : userIp;

    req.session.otherInfo = {
      ip: formattedIp,
      browser: userAgent,
    };

    next();
  } else {
    next();
  }
});

// Save the username in a cookie, the cookie user name is use
// for displaying user name in profile menu. This cookie is not use anyelse where.
// So it is safe to use.
router.use(async (req, res, next) => {
  if (req.session && req.session.user) {
    try {

      res.cookie("username", req.session.user.username, {
        maxAge: COOKIE_EXPIRE_TIME,
      });

      const query = `SELECT "Role" FROM "Users" WHERE "UserName" = $1`;
      const result = await dblogin.query(query, [req.session.user.username]);

      if (result.rows.length > 0) {
        req.session.user.role = result.rows[0].Role;
        res.cookie("userRole", req.session.user.role, {
          maxAge: COOKIE_EXPIRE_TIME,
        });
      } else {
        req.session.user.role = null;
      }
    } catch (error) {
      WriteConsoleLogs("Error fetching user role:", error.message);
      req.session.user.role = null; // Fallback to null role
    }
  }
  next();
});

router.use(async (req, res, next) => {
  // Check for sessionId cookie if session is not initialized
  if (!req.session.user && req.cookies && req.cookies.sessionId) {
    WriteConsoleLogs("Restoring session from sessionId cookie"); // Log session restoration
    const sessionId = req.cookies.sessionId;
    const query = `SELECT * FROM "Users" WHERE "SessionId" = $1`;
    const result = await dblogin.query(query, [sessionId]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      req.session.user = {
        id: user.id,
        username: user.UserName,
        sessionId,
      };
      WriteConsoleLogs(`Session restored for user: ${user.UserName}`); // Log successful session restoration
    } else {
      console.warn("No matching session found for sessionId"); // Log if no session is found
    }
  }
  next();
});

//Invoke-RestMethod -Uri http://localhost:3030/terminateAllSessions -Method POST
// Terminate all sessions route
router.post("/mbkauthe/api/terminateAllSessions", authenticate(process.env.Main_SECRET_TOKEN), async (req, res) => {
  try {
    await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL`);

    // Clear the session table
    await dblogin.query('DELETE FROM "session"');

    // Destroy all sessions on the server
    req.session.destroy((err) => {
      if (err) {
        WriteConsoleLogs("Error destroying session:", err);
        return res
          .status(500)
          .json({ success: false, message: "Failed to terminate sessions" });
      }
      WriteConsoleLogs("All sessions terminated successfully");
      res.status(200).json({
        success: true,
        message: "All sessions terminated successfully",
      });
    });
  } catch (err) {
    WriteConsoleLogs("Database query error during session termination:", err);
    res
      .status(500)
      .json({ success: false, message: "Internal Server Error" });
  }
}
);

router.post("/mbkauthe/api/login", async (req, res) => {
  WriteConsoleLogs("Login request received"); // Log when login is initiated

  const { username, password, token, recaptcha } = req.body;
  WriteConsoleLogs(`Login attempt for username: ${username}`); // Log username

  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptcha}`;

  // Bypass recaptcha for specific users
  if (username !== "ibnekhalid" && username !== "maaz.waheed" && username !== "support") {
    try {
      const response = await fetch(verificationUrl, { method: 'POST' });
      const body = await response.json();
      WriteConsoleLogs("reCAPTCHA verification response:", body); // Log reCAPTCHA response

      if (!body.success) {
        WriteConsoleLogs("Failed reCAPTCHA verification");
        return res.status(400).json({ success: false, message: "Failed reCAPTCHA verification" });
      }
    } catch (err) {
      WriteConsoleLogs("Error during reCAPTCHA verification:", err);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  }

  if (!username || !password) {
    WriteConsoleLogs("Missing username or password");
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  WriteConsoleLogs("RECAPTCHA_SECRET_KEY:", process.env.RECAPTCHA_SECRET_KEY); // Log reCAPTCHA secret key
  WriteConsoleLogs("SESSION_SECRET_KEY:", process.env.SESSION_SECRET_KEY); // Log reCAPTCHA secret key
  WriteConsoleLogs("LOGIN_DB:", process.env.LOGIN_DB); // Log reCAPTCHA secret key
  WriteConsoleLogs("COOKIE_EXPIRE_TIME:", process.env.COOKIE_EXPIRE_TIME); // Log reCAPTCHA secret key
  WriteConsoleLogs("DOMAIN:", process.env.DOMAIN); // Log reCAPTCHA secret key
  WriteConsoleLogs("IS_DEPLOYED:", process.env.IS_DEPLOYED); // Log reCAPTCHA secret key
  WriteConsoleLogs("MBKAUTH_TWO_FA_ENABLE:", process.env.MBKAUTH_TWO_FA_ENABLE); // Log reCAPTCHA secret key

  try {
    // Query to check if the username exists
    const userQuery = `SELECT * FROM "Users" WHERE "UserName" = $1`;
    const userResult = await dblogin.query(userQuery, [username]);
    WriteConsoleLogs("User query result:", userResult.rows); // Log user query result

    if (userResult.rows.length === 0) {
      WriteConsoleLogs(`Username does not exist: ${username}`);
      return res.status(404).json({ success: false, message: "Username does not exist" });
    }

    const user = userResult.rows[0];

    // Check if the password matches
    if (user.Password !== password) {
      WriteConsoleLogs(`Incorrect password for username: ${username}`);
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // Check if the account is inactive
    if (!user.Active) {
      WriteConsoleLogs(`Inactive account for username: ${username}`);
      return res.status(403).json({ success: false, message: "Account is inactive" });
    }

    if ((process.env.MBKAUTH_TWO_FA_ENABLE || "").toLocaleLowerCase() === "true") {
      let sharedSecret;
      const query = `SELECT "TwoFAStatus", "TwoFASecret" FROM "TwoFA" WHERE "UserName" = $1`;
      const twoFAResult = await dblogin.query(query, [username]);
      WriteConsoleLogs("TwoFA query result:", twoFAResult.rows); // Log TwoFA query result

      sharedSecret = twoFAResult.rows[0]?.TwoFASecret;
      if (twoFAResult.rows.length > 0 && twoFAResult.rows[0].TwoFAStatus && !token) {
        WriteConsoleLogs("2FA code required but not provided");
        return res.status(401).json({ success: false, message: "Please Enter 2FA code" });
      }

      if (token && twoFAResult.rows[0]?.TwoFAStatus) {
        const tokenValidates = speakeasy.totp.verify({
          secret: sharedSecret,
          encoding: "base32",
          token: token,
          window: 1, // Allows a margin for clock drift, optional
        });

        if (!tokenValidates) {
          WriteConsoleLogs(`Invalid 2FA code for username: ${username}`);
          return res.status(401).json({ success: false, message: "Invalid 2FA code" });
        }
      }
    }

    // Generate session ID
    const sessionId = crypto.randomBytes(256).toString("hex");
    WriteConsoleLogs(`Generated session ID for username: ${username}`); // Log session ID

    await dblogin.query(`UPDATE "Users" SET "SessionId" = $1 WHERE "id" = $2`, [
      sessionId,
      user.id,
    ]);

    // Store session ID in session
    req.session.user = {
      id: user.id,
      username: user.UserName,
      sessionId,
    };
    WriteConsoleLogs(`Session stored for user: ${user.UserName}, sessionId: ${sessionId}`); // Log session storage

    // Set a cookie accessible across subDOMAINs
    res.cookie("sessionId", sessionId, {
      maxAge: COOKIE_EXPIRE_TIME,
      DOMAIN: process.env.IS_DEPLOYED === 'true' ? `.${process.env.DOMAIN}` : undefined, // Use DOMAIN only in production
      httpOnly: true,
      secure: process.env.IS_DEPLOYED === 'true', // Use secure cookies in production
    });
    WriteConsoleLogs(`Cookie set for user: ${user.UserName}, sessionId: ${sessionId}`); // Log cookie setting

    WriteConsoleLogs(`User "${username}" logged in successfully`);
    res.status(200).json({
      success: true,
      message: "Login successful",
      sessionId,
    });
  } catch (err) {
    WriteConsoleLogs("Error during login process:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/mbkauthe/api/logout", async (req, res) => {
  if (req.session.user) {
    try {
      const { id, username } = req.session.user;
      const query = `SELECT "Active" FROM "Users" WHERE "id" = $1`;
      const result = await dblogin.query(query, [id]);

      if (result.rows.length > 0 && !result.rows[0].Active) {
        WriteConsoleLogs("Account is inactive during logout");
      }

      req.session.destroy((err) => {
        if (err) {
          WriteConsoleLogs("Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }
        // Clear both session cookies
        res.clearCookie("connect.sid");
        res.clearCookie("sessionId"); // Clear the sessionId cookie used for restoration
        WriteConsoleLogs(`User "${username}" logged out successfully`);
        res.status(200).json({ success: true, message: "Logout successful" });
      });
    } catch (err) {
      WriteConsoleLogs("Database query error during logout:", err);
      res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  } else {
    res.status(400).json({ success: false, message: "Not logged in" });
  }
});

export default router;