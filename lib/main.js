import express from "express";
import crypto from "crypto";
import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import { dblogin } from "./pool.js";
import { authenticate } from "./validateSessionAndRole.js";
import fetch from 'node-fetch';
import cookieParser from "cookie-parser";

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const packageJson = require("../package.json");
import fs from "fs";
import path from "path";

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

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

// Configure session with proper domain settings for cross-subdomain sharing
const sessionConfig = {
  store: new PgSession({
    pool: dblogin,
    tableName: "session",
    createTableIfMissing: true
  }),
  secret: mbkautheVar.SESSION_SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  proxy: true, // Trust the reverse proxy
  cookie: {
    maxAge: COOKIE_EXPIRE_TIME,
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    httpOnly: true,
    secure: mbkautheVar.IS_DEPLOYED === 'true' ? 'auto' : false, // 'auto' respects X-Forwarded-Proto
    sameSite: 'lax',
    path: '/'
  },
  name: 'mbkauthe.sid'
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
      }
    } catch (err) {
      console.error("Session restoration error:", err);
    }
  }
  next();
});

// Set consistent cookie options for all cookies
const getCookieOptions = () => ({
  maxAge: COOKIE_EXPIRE_TIME,
  domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
  secure: mbkautheVar.IS_DEPLOYED === 'true' ? 'auto' : false,
  sameSite: 'lax',
  path: '/',
  httpOnly: true
});

router.use(async (req, res, next) => {
  if (req.session && req.session.user) {
    const cookieOptions = getCookieOptions();
    res.cookie("username", req.session.user.username, { ...cookieOptions, httpOnly: false });
    res.cookie("sessionId", req.session.user.sessionId, cookieOptions);
  }
  next();
});

router.post("/mbkauthe/api/terminateAllSessions", authenticate(mbkautheVar.Main_SECRET_TOKEN), async (req, res) => {
  try {
    await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL`);
    await dblogin.query('DELETE FROM "session"');

    req.session.destroy((err) => {
      if (err) {
        console.log("Error destroying session:", err);
        return res.status(500).json({ success: false, message: "Failed to terminate sessions" });
      }

      // Clear all cookies with proper domain
      const cookieOptions = getCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);

      console.log("All sessions terminated successfully");
      res.status(200).json({
        success: true,
        message: "All sessions terminated successfully",
      });
    });
  } catch (err) {
    console.log("Database query error during session termination:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/mbkauthe/api/login", async (req, res) => {
  console.log("Login request received");

  const { username, password, token, recaptcha } = req.body;
  console.log(`Login attempt for username: ${username}`);

  const secretKey = mbkautheVar.RECAPTCHA_SECRET_KEY;
  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptcha}`;

  let BypassUsers = Array.isArray(mbkautheVar.BypassUsers) ? mbkautheVar.BypassUsers : JSON.parse(mbkautheVar.BypassUsers);

  if (mbkautheVar.RECAPTCHA_Enabled === "true") {
    if (!BypassUsers.includes(username)) {
      if (!recaptcha) {
        console.log("Missing reCAPTCHA token");
        return res.status(400).json({ success: false, message: "Please complete the reCAPTCHA" });
      }
      try {
        const response = await fetch(verificationUrl, { method: 'POST' });
        const body = await response.json();
        console.log("reCAPTCHA verification response:", body);

        if (!body.success) {
          console.log("Failed reCAPTCHA verification");
          return res.status(400).json({ success: false, message: "Failed reCAPTCHA verification" });
        }
      } catch (err) {
        console.log("Error during reCAPTCHA verification:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }
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
    const userQuery = `SELECT * FROM "Users" WHERE "UserName" = $1`;
    const userResult = await dblogin.query(userQuery, [username]);

    if (userResult.rows.length === 0) {
      console.log(`Username does not exist: ${username}`);
      return res.status(404).json({ success: false, message: "Incorrect Username Or Password" });
    }

    const user = userResult.rows[0];

    if (user.Password !== password) {
      console.log(`Incorrect password for username: ${username}`);
      return res.status(401).json({ success: false, message: "Incorrect Username Or Password" });
    }

    if (!user.Active) {
      console.log(`Inactive account for username: ${username}`);
      return res.status(403).json({ success: false, message: "Account is inactive" });
    }

    if (user.Role !== "SuperAdmin") {
      const allowedApps = user.AllowedApps;
      if (!allowedApps || !allowedApps.includes(mbkautheVar.APP_NAME)) {
        console.warn(`User \"${user.UserName}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        return res.status(403).json({ success: false, message: `You Are Not Authorized To Use The Application \"${mbkautheVar.APP_NAME}\"` });
      }
    }

    if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLocaleLowerCase() === "true") {
      let sharedSecret;
      const query = `SELECT "TwoFAStatus", "TwoFASecret" FROM "TwoFA" WHERE "UserName" = $1`;
      const twoFAResult = await dblogin.query(query, [username]);
      console.log("TwoFA query result:", twoFAResult.rows);

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
          window: 1,
        });

        if (!tokenValidates) {
          console.log(`Invalid 2FA code for username: ${username}`);
          return res.status(401).json({ success: false, message: "Invalid 2FA code" });
        }
      }
    }

    const sessionId = crypto.randomBytes(256).toString("hex");
    console.log(`Generated session ID for username: ${username}`);

    await dblogin.query(`UPDATE "Users" SET "SessionId" = $1 WHERE "id" = $2`, [
      sessionId,
      user.id,
    ]);

    req.session.user = {
      id: user.id,
      username: user.UserName,
      role: user.Role,
      sessionId,
    };

    const cookieOptions = getCookieOptions();
    res.cookie("sessionId", sessionId, cookieOptions);
    console.log(req.session.user);

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

      // Clear the SessionId in the database first
      await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL WHERE "id" = $1`, [id]);

      // Remove the session from the session table
      if (req.sessionID) {
        await dblogin.query('DELETE FROM "session" WHERE sid = $1', [req.sessionID]);
      }

      req.session.destroy((err) => {
        if (err) {
          console.log("Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }

        // Clear all cookies with proper domain
        const cookieOptions = getCookieOptions();
        res.clearCookie("mbkauthe.sid", cookieOptions);
        res.clearCookie("sessionId", cookieOptions);
        res.clearCookie("username", cookieOptions);

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

// Return package.json data of mbkauthe
router.get("/mbkauthe/package", (_, res) => {
  res.status(200).json({ version: packageJson });
});

// Return version number of mbkauthe
router.get(["/mbkauthe/version", "/mbkauthe/v"], (_, res) => {
  res.status(200).json({ version: packageJson.version });
});

// Return package-lock.json data of mbkauthe from project the package is installed in
router.get("/mbkauthe/package-lock", (_, res) => {
  console.log("Request for package-lock.json received");
  const packageLockPath = path.resolve(process.cwd(), "package-lock.json");
  fs.readFile(packageLockPath, "utf8", (err, data) => {
    if (err) {
      console.error("Error reading package-lock.json:", err);
      return res.status(500).json({ success: false, message: "Failed to read package-lock.json" });
    }
    try {
      const packageLock = JSON.parse(data);
      const mbkautheData = {
        name: 'mbkauthe',
        version: packageLock.packages['node_modules/mbkauthe'].version,
        resolved: packageLock.packages['node_modules/mbkauthe'].resolved,
        integrity: packageLock.packages['node_modules/mbkauthe'].integrity,
        license: packageLock.packages['node_modules/mbkauthe'].license,
        dependencies: packageLock.packages['node_modules/mbkauthe'].dependencies
      };
      const rootDependency = packageLock.packages[''].dependencies.mbkauthe;
      console.log('mbkauthe package data:', mbkautheData);
      console.log('Root dependency version:', rootDependency);
      res.status(200).json({ mbkautheData, rootDependency });
    } catch (parseError) {
      console.error("Error parsing package-lock.json:", parseError);
      res.status(500).json({ success: false, message: "Failed to parse package-lock.json" });
    }
  });
});

export default router;