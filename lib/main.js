import express from "express";
import crypto from "crypto";
import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import { dblogin } from "./pool.js";
import { authenticate } from "./validateSessionAndRole.js";
import fetch from 'node-fetch';
import cookieParser from "cookie-parser";



import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);
if (!mbkautheVar) {
  throw new Error("mbkautheVar is not defined");
}
const requiredKeys = ["RECAPTCHA_SECRET_KEY", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];
requiredKeys.forEach(key => {
  if (!mbkautheVar[key]) {
    throw new Error(`mbkautheVar.${key} is required`);
  }
});
if (mbkautheVar.COOKIE_EXPIRE_TIME !== undefined) {
  const expireTime = parseFloat(mbkautheVar.COOKIE_EXPIRE_TIME);
  if (isNaN(expireTime) || expireTime <= 0) {
    throw new Error("mbkautheVar.COOKIE_EXPIRE_TIME must be a valid positive number");
  }
}


const router = express.Router();
let COOKIE_EXPIRE_TIME = 2 * 24 * 60 * 60 * 1000; // 2 days

try {
  const parsedExpireTime = parseInt(mbkautheVar.COOKIE_EXPIRE_TIME, 10);
  if (!isNaN(parsedExpireTime) && parsedExpireTime > 0) {
    COOKIE_EXPIRE_TIME = parsedExpireTime * 24 * 60 * 60 * 1000;
  } else {
    console.warn("Invalid COOKIE_EXPIRE_TIME, using default value");
  }
} catch (error) {
  console.log("Error parsing COOKIE_EXPIRE_TIME:", error);
}

// Enable CORS for subdomains
router.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && origin.endsWith(`.${mbkautheVar.DOMAIN}`)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  next();
});

router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());

// Configure session with proper domain settings
const sessionConfig = {
  store: new PgSession({
    pool: dblogin,
    tableName: "session",
  }),
  secret: mbkautheVar.SESSION_SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: COOKIE_EXPIRE_TIME,
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    httpOnly: true,
    secure: mbkautheVar.IS_DEPLOYED === 'true',
    sameSite: 'lax',
  },
  name: 'mbkauthe.sid' // Unique session cookie name
};

router.use(session(sessionConfig));

// Middleware to handle session restoration from sessionId cookie
router.use(async (req, res, next) => {
  if (!req.session.user && req.cookies.sessionId) {
    try {
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
        console.log(`Session restored for user: ${user.UserName}`);
      }
    } catch (err) {
      console.error("Session restoration error:", err);
    }
  }
  next();
});

//Invoke-RestMethod -Uri http://localhost:3030/terminateAllSessions -Method POST
// Terminate all sessions route
router.post("/mbkauthe/api/terminateAllSessions", authenticate(mbkautheVar.Main_SECRET_TOKEN), async (req, res) => {
  try {
    await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL`);

    // Clear the session table
    await dblogin.query('DELETE FROM "session"');

    // Destroy all sessions on the server
    req.session.destroy((err) => {
      if (err) {
        console.log("Error destroying session:", err);
        return res
          .status(500)
          .json({ success: false, message: "Failed to terminate sessions" });
      }
      console.log("All sessions terminated successfully");
      res.status(200).json({
        success: true,
        message: "All sessions terminated successfully",
      });
    });
  } catch (err) {
    console.log("Database query error during session termination:", err);
    res
      .status(500)
      .json({ success: false, message: "Internal Server Error" });
  }
}
);

router.post("/mbkauthe/api/login", async (req, res) => {
  console.log("Login request received"); // Log when login is initiated

  const { username, password, token, recaptcha } = req.body;
  console.log(`Login attempt for username: ${username}`); // Log username

  const secretKey = mbkautheVar.RECAPTCHA_SECRET_KEY;
  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptcha}`;

  let BypassUsers = ["ibnekhalid", "maaz.waheed", "support"];

  // Bypass recaptcha for specific users
  if (!BypassUsers.includes(username)) {
    if (!recaptcha) {
      console.log("Missing reCAPTCHA token");
      return res.status(400).json({ success: false, message: "Please complete the reCAPTCHA" });
    }
    try {
      const response = await fetch(verificationUrl, { method: 'POST' });
      const body = await response.json();
      console.log("reCAPTCHA verification response:", body); // Log reCAPTCHA response

      if (!body.success) {
        console.log("Failed reCAPTCHA verification");
        return res.status(400).json({ success: false, message: "Failed reCAPTCHA verification" });
      }
    } catch (err) {
      console.log("Error during reCAPTCHA verification:", err);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  }

  if (!username || !password) {
    console.log("Missing username or password");
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  try {
    // Query to check if the username exists
    const userQuery = `SELECT * FROM "Users" WHERE "UserName" = $1`;
    const userResult = await dblogin.query(userQuery, [username]);
    console.log("User query result:", userResult.rows); // Log user query result

    if (userResult.rows.length === 0) {
      console.log(`Username does not exist: ${username}`);
      return res.status(404).json({ success: false, message: "Username does not exist" });
    }

    const user = userResult.rows[0];

    // Check if the password matches
    if (user.Password !== password) {
      console.log(`Incorrect password for username: ${username}`);
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // Check if the account is inactive
    if (!user.Active) {
      console.log(`Inactive account for username: ${username}`);
      return res.status(403).json({ success: false, message: "Account is inactive" });
    }

    if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLocaleLowerCase() === "true") {
      let sharedSecret;
      const query = `SELECT "TwoFAStatus", "TwoFASecret" FROM "TwoFA" WHERE "UserName" = $1`;
      const twoFAResult = await dblogin.query(query, [username]);
      console.log("TwoFA query result:", twoFAResult.rows); // Log TwoFA query result

      sharedSecret = twoFAResult.rows[0]?.TwoFASecret;
      if (twoFAResult.rows.length > 0 && twoFAResult.rows[0].TwoFAStatus && !token) {
        console.log("2FA code required but not provided");
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
          console.log(`Invalid 2FA code for username: ${username}`);
          return res.status(401).json({ success: false, message: "Invalid 2FA code" });
        }
      }
    }

    // Generate session ID
    const sessionId = crypto.randomBytes(256).toString("hex");
    console.log(`Generated session ID for username: ${username}`); // Log session ID

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
    console.log(`Session stored for user: ${user.UserName}, sessionId: ${sessionId}`); // Log session storage

    // Set a cookie accessible across subDOMAINs
    res.cookie("sessionId", sessionId, {
      maxAge: COOKIE_EXPIRE_TIME,
      DOMAIN: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined, // Use DOMAIN only in production
      httpOnly: true,
      secure: mbkautheVar.IS_DEPLOYED === 'true', // Use secure cookies in production
    });
    console.log(`Cookie set for user: ${user.UserName}, sessionId: ${sessionId}`); // Log cookie setting

    console.log(`User "${username}" logged in successfully`);
    res.status(200).json({
      success: true,
      message: "Login successful",
      sessionId,
    });
  } catch (err) {
    console.log("Error during login process:", err);
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
        console.log("Account is inactive during logout");
      }

      req.session.destroy((err) => {
        if (err) {
          console.log("Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }
        // Clear both session cookies
        res.clearCookie("connect.sid");
        res.clearCookie("sessionId"); // Clear the sessionId cookie used for restoration
        console.log(`User "${username}" logged out successfully`);
        res.status(200).json({ success: true, message: "Logout successful" });
      });
    } catch (err) {
      console.log("Database query error during logout:", err);
      res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  } else {
    res.status(400).json({ success: false, message: "Not logged in" });
  }
});

export default router;