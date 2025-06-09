import express from "express";
import crypto from "crypto";
import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import { dblogin } from "./pool.js";
import { authenticate } from "./validateSessionAndRole.js";
import fetch from 'node-fetch';
import cookieParser from "cookie-parser";
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import mbkautheinfo from "./info.js";
import speakeasy from "speakeasy";

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());

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

const LoginLimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 8,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => {
    return !!req.session.user;
  }
});

const sessionConfig = {
  store: new PgSession({
    pool: dblogin,
    tableName: "session",
    createTableIfMissing: true
  }),
  secret: mbkautheVar.SESSION_SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    httpOnly: true,
    secure: mbkautheVar.IS_DEPLOYED === 'true' ? 'auto' : false,
    sameSite: 'lax',
    path: '/'
  },
  name: 'mbkauthe.sid'
};

router.use(session(sessionConfig));

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

const getCookieOptions = () => ({
  maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
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

router.post("/mbkauthe/api/login", LoginLimit, async (req, res) => {
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

    if (mbkautheVar.EncryptedPassword === "true") {
      try {
        const result = await bcrypt.compare(password, user.Password);
        if (!result) {
          console.log("Incorrect password.");
          return res.status(401).json({ success: false, errorCode: 603, message: "Incorrect Username Or Password." });
        }
        console.log("Password matches!");
      } catch (err) {
        console.error("Error comparing password:", err);
        return res.status(500).json({ success: false, errorCode: 605, message: `Internal Server Error` });
      }
    } else {
      if (user.Password !== password) {
        console.log(`Incorrect password for username: ${username}`);
        return res.status(401).json({ success: false, errorCode: 603, message: "Incorrect Username Or Password" });
      }
    }

    if (!user.Active) {
      console.log(`Inactive account for username: ${username}`);
      return res.status(403).json({ success: false, message: "Account is inactive" });
    }

    if (user.Role !== "SuperAdmin") {
      const allowedApps = user.AllowedApps;
      if (!allowedApps || !allowedApps.some(app => app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
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

    // Delete old session record for this user
    if (user.SessionId) {
      await dblogin.query('DELETE FROM "session" WHERE username = $1', [user.UserName]);
    }

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


    // Save session and update username in session table
    req.session.save(async (err) => {
      if (err) {
        console.log("Session save error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }
      try {
        await dblogin.query(
          'UPDATE "session" SET username = $1 WHERE sid = $2',
          [user.UserName, req.sessionID]
        );
      } catch (e) {
        console.log("Failed to update username in session table:", e);
      }

      const cookieOptions = getCookieOptions();
      res.cookie("sessionId", sessionId, cookieOptions);
      console.log(req.session.user);

      console.log(`User "${username}" logged in successfully`);
      res.status(200).json({
        success: true,
        message: "Login successful",
        sessionId,
      });
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

      await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL WHERE "id" = $1`, [id]);

      if (req.sessionID) {
        await dblogin.query('DELETE FROM "session" WHERE sid = $1', [req.sessionID]);
      }

      req.session.destroy((err) => {
        if (err) {
          console.log("Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }

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

router.use(mbkautheinfo);

export default router;