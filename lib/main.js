import express from "express";
import csurf from "csurf";
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
import speakeasy from "speakeasy";
//import passport from 'passport';
//import GitHubStrategy from 'passport-github2';

import { createRequire } from "module";
import fs from "fs";
import path from "path";

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

const router = express.Router();

const require = createRequire(import.meta.url);
const packageJson = require("../package.json");

router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());

router.get('/mbkauthe/main.js', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'main.js'));
});

// CSRF protection middleware
const csrfProtection = csurf({ cookie: false });

// CORS and security headers
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

const LogoutLimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many logout attempts, please try again later" }
});

const TwoFALimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: { success: false, message: "Too many 2FA attempts, please try again later" }
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
  // Only restore session if not already present and sessionId cookie exists
  if (!req.session.user && req.cookies.sessionId) {
    try {
      const sessionId = req.cookies.sessionId;

      // Validate sessionId format (should be 64 hex characters)
      if (typeof sessionId !== 'string' || !/^[a-f0-9]{64}$/i.test(sessionId)) {
        console.warn("[mbkauthe] Invalid sessionId format detected");
        return next();
      }

      const query = `SELECT id, "UserName", "Active", "Role", "SessionId", "AllowedApps" FROM "Users" WHERE "SessionId" = $1 AND "Active" = true`;
      const result = await dblogin.query({ name: 'get-user-by-sessionid', text: query, values: [sessionId] });

      if (result.rows.length > 0) {
        const user = result.rows[0];
        req.session.user = {
          id: user.id,
          username: user.UserName,
          UserName: user.UserName,
          role: user.Role,
          Role: user.Role,
          sessionId,
          allowedApps: user.AllowedApps,
        };
      }
    } catch (err) {
      console.error("[mbkauthe] Session restoration error:", err);
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

const getClearCookieOptions = () => ({
  domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
  secure: mbkautheVar.IS_DEPLOYED === 'true' ? 'auto' : false,
  sameSite: 'lax',
  path: '/',
  httpOnly: true
});

async function completeLoginProcess(req, res, user, redirectUrl = null) {
  try {
    // smaller session id is sufficient and faster to generate/serialize
    const sessionId = crypto.randomBytes(32).toString("hex");
    console.log(`[mbkauthe] Generated session ID for username: ${user.username}`);

    // Delete old session record for this user
    await dblogin.query('DELETE FROM "session" WHERE username = $1', [user.username]);

    await dblogin.query(`UPDATE "Users" SET "SessionId" = $1 WHERE "id" = $2`, [
      sessionId,
      user.id,
    ]);

    req.session.user = {
      id: user.id,
      username: user.username,
      UserName: user.UserName,
      role: user.role,
      Role: user.role,
      sessionId,
    };

    if (req.session.preAuthUser) {
      delete req.session.preAuthUser;
    }

    req.session.save(async (err) => {
      if (err) {
        console.error("[mbkauthe] Session save error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }
      // avoid writing back into the session table here to reduce DB writes;
      // the pg session store will already persist the session data.

      const cookieOptions = getCookieOptions();
      res.cookie("sessionId", sessionId, cookieOptions);
      console.log(`[mbkauthe] User "${user.username}" logged in successfully`);

      const responsePayload = {
        success: true,
        message: "Login successful",
        sessionId,
      };

      if (redirectUrl) {
        responsePayload.redirectUrl = redirectUrl;
      }

      res.status(200).json(responsePayload);
    });
  } catch (err) {
    console.error("[mbkauthe] Error during login completion:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

router.use(async (req, res, next) => {
  if (req.session && req.session.user) {
    const cookieOptions = getCookieOptions();
    // Only set cookies if they're missing or different
    if (req.cookies.sessionId !== req.session.user.sessionId) {
      res.cookie("username", req.session.user.username, { ...cookieOptions, httpOnly: false });
      res.cookie("sessionId", req.session.user.sessionId, cookieOptions);
    }
  }
  next();
});

router.post("/mbkauthe/api/terminateAllSessions", authenticate(mbkautheVar.Main_SECRET_TOKEN), async (req, res) => {
  try {
    await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL`);
    await dblogin.query('DELETE FROM "session"');

    req.session.destroy((err) => {
      if (err) {
        console.log("[mbkauthe] Error destroying session:", err);
        return res.status(500).json({ success: false, message: "Failed to terminate sessions" });
      }

      const cookieOptions = getClearCookieOptions();
      res.clearCookie("mbkauthe.sid", cookieOptions);
      res.clearCookie("sessionId", cookieOptions);
      res.clearCookie("username", cookieOptions);

      console.log("[mbkauthe] All sessions terminated successfully");
      res.status(200).json({
        success: true,
        message: "All sessions terminated successfully",
      });
    });
  } catch (err) {
    console.error("[mbkauthe] Database query error during session termination:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/mbkauthe/api/login", LoginLimit, async (req, res) => {
  console.log("[mbkauthe] Login request received");

  const { username, password } = req.body;

  // Input validation
  if (!username || !password) {
    console.log("[mbkauthe] Missing username or password");
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  // Validate username format and length
  if (typeof username !== 'string' || username.trim().length === 0 || username.length > 255) {
    console.warn("[mbkauthe] Invalid username format");
    return res.status(400).json({
      success: false,
      message: "Invalid username format",
    });
  }

  // Validate password length
  if (typeof password !== 'string' || password.length < 8 || password.length > 255) {
    console.warn("[mbkauthe] Invalid password length");
    return res.status(400).json({
      success: false,
      message: "Password must be at least 8 characters long",
    });
  }

  console.log(`[mbkauthe] Login attempt for username: ${username.trim()}`);

  const trimmedUsername = username.trim();

  try {
    const userQuery = `SELECT id, "UserName", "Password", "Active", "Role", "AllowedApps" FROM "Users" WHERE "UserName" = $1`;
    const userResult = await dblogin.query({ name: 'get-user-by-username', text: userQuery, values: [trimmedUsername] });

    if (userResult.rows.length === 0) {
      console.log(`[mbkauthe] Username does not exist: ${trimmedUsername}`);
      return res.status(404).json({ success: false, message: "Incorrect Username Or Password" });
    }

    const user = userResult.rows[0];

    // Validate user has password field
    if (!user.Password) {
      console.error("[mbkauthe] User account has no password set");
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }

    if (mbkautheVar.EncryptedPassword === "true") {
      try {
        const result = await bcrypt.compare(password, user.Password);
        if (!result) {
          console.log("[mbkauthe] Incorrect password.");
          return res.status(401).json({ success: false, errorCode: 603, message: "Incorrect Username Or Password." });
        }
        console.log("[mbkauthe] Password matches!");
      } catch (err) {
        console.error("[mbkauthe] Error comparing password:", err);
        return res.status(500).json({ success: false, errorCode: 605, message: `Internal Server Error` });
      }
    } else {
      if (user.Password !== password) {
        console.log(`[mbkauthe] Incorrect password for username: ${trimmedUsername}`);
        return res.status(401).json({ success: false, errorCode: 603, message: "Incorrect Username Or Password" });
      }
    }

    if (!user.Active) {
      console.log(`[mbkauthe] Inactive account for username: ${trimmedUsername}`);
      return res.status(403).json({ success: false, message: "Account is inactive" });
    }

    if (user.Role !== "SuperAdmin") {
      const allowedApps = user.AllowedApps;
      if (!allowedApps || !allowedApps.some(app => app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        console.warn(`[mbkauthe] User \"${user.UserName}\" is not authorized to use the application \"${mbkautheVar.APP_NAME}\"`);
        return res.status(403).json({ success: false, message: `You Are Not Authorized To Use The Application \"${mbkautheVar.APP_NAME}\"` });
      }
    }

    if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLocaleLowerCase() === "true") {
      const query = `SELECT "TwoFAStatus" FROM "TwoFA" WHERE "UserName" = $1`;
      const twoFAResult = await dblogin.query({ name: 'get-2fa-status', text: query, values: [trimmedUsername] });

      if (twoFAResult.rows.length > 0 && twoFAResult.rows[0].TwoFAStatus) {
        // 2FA is enabled, prompt for token on a separate page
        req.session.preAuthUser = {
          id: user.id,
          username: user.UserName,
          role: user.Role,
          Role: user.Role,
        };
        console.log(`[mbkauthe] 2FA required for user: ${trimmedUsername}`);
        return res.json({ success: true, twoFactorRequired: true });
      }
    }

    // If 2FA is not enabled, proceed with login
    const userForSession = {
      id: user.id,
      username: user.UserName,
      role: user.Role,
      Role: user.Role,
    };
    await completeLoginProcess(req, res, userForSession);

  } catch (err) {
    console.error("[mbkauthe] Error during login process:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get("/mbkauthe/2fa", csrfProtection, (req, res) => {
  if (!req.session.preAuthUser) {
    return res.redirect("/mbkauthe/login");
  }
  res.render("2fa.handlebars", {
    layout: false,
    customURL: mbkautheVar.loginRedirectURL || '/home',
    csrfToken: req.csrfToken(),
  });
});

router.post("/mbkauthe/api/verify-2fa", TwoFALimit, csrfProtection, async (req, res) => {
  if (!req.session.preAuthUser) {
    return res.status(401).json({ success: false, message: "Not authorized. Please login first." });
  }

  const { token } = req.body;
  const { username, id, role } = req.session.preAuthUser;

  // Validate 2FA token
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ success: false, message: "2FA token is required" });
  }

  // Validate token format (should be 6 digits)
  const sanitizedToken = token.trim();
  if (!/^\d{6}$/.test(sanitizedToken)) {
    return res.status(400).json({ success: false, message: "Invalid 2FA token format" });
  }

  try {
    const query = `SELECT "TwoFASecret" FROM "TwoFA" WHERE "UserName" = $1`;
    const twoFAResult = await dblogin.query(query, [username]);

    if (twoFAResult.rows.length === 0 || !twoFAResult.rows[0].TwoFASecret) {
      return res.status(500).json({ success: false, message: "2FA is not configured correctly." });
    }

    const sharedSecret = twoFAResult.rows[0].TwoFASecret;
    const tokenValidates = speakeasy.totp.verify({
      secret: sharedSecret,
      encoding: "base32",
      token: sanitizedToken,
      window: 1,
    });

    if (!tokenValidates) {
      console.log(`[mbkauthe] Invalid 2FA code for username: ${username}`);
      return res.status(401).json({ success: false, message: "Invalid 2FA code" });
    }

    // 2FA successful, complete login
    const userForSession = { id, username, role };
    const redirectUrl = mbkautheVar.loginRedirectURL || '/home';
    await completeLoginProcess(req, res, userForSession, redirectUrl);

  } catch (err) {
    console.error("[mbkauthe] Error during 2FA verification:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/mbkauthe/api/logout", LogoutLimit, csrfProtection, async (req, res) => {
  if (req.session.user) {
    try {
      const { id, username } = req.session.user;

      await dblogin.query(`UPDATE "Users" SET "SessionId" = NULL WHERE "id" = $1`, [id]);

      if (req.sessionID) {
        await dblogin.query('DELETE FROM "session" WHERE sid = $1', [req.sessionID]);
      }

      req.session.destroy((err) => {
        if (err) {
          console.error("[mbkauthe] Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }

        const cookieOptions = getClearCookieOptions();
        res.clearCookie("mbkauthe.sid", cookieOptions);
        res.clearCookie("sessionId", cookieOptions);
        res.clearCookie("username", cookieOptions);

        console.log(`[mbkauthe] User "${username}" logged out successfully`);
        res.status(200).json({ success: true, message: "Logout successful" });
      });
    } catch (err) {
      console.error("[mbkauthe] Database query error during logout:", err);
      res.status(500).json({ success: false, message: "Internal Server Error" });
    }
  } else {
    res.status(400).json({ success: false, message: "Not logged in" });
  }
});

router.get("/mbkauthe/login", LoginLimit, csrfProtection, (req, res) => {
  return res.render("loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: mbkautheVar.GITHUB_LOGIN_ENABLED,
    customURL: mbkautheVar.loginRedirectURL || '/home',
    userLoggedIn: !!req.session?.user,
    username: req.session?.user?.username || '',
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME.toUpperCase(),
    csrfToken: req.csrfToken(),
  });
});

async function getLatestVersion() {
  try {
    const response = await fetch('https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/main/package.json');
    if (!response.ok) {
      console.error(`GitHub API responded with status ${response.status}`);
      return "0.0.0";
    }
    const latestPackageJson = await response.json();
    return latestPackageJson.version;
  } catch (error) {
    console.error('[mbkauthe] Error fetching latest version from GitHub:', error);
    return null;
  }
}

router.get(["/mbkauthe/info", "/mbkauthe/i"], LoginLimit, async (_, res) => {
  let latestVersion;

  try {
    latestVersion = await getLatestVersion();
    //latestVersion = "Under Development"; // Placeholder for the latest version
  } catch (err) {
    console.error("[mbkauthe] Error fetching package-lock.json:", err);
  }

  try {
    res.render("info.handlebars", {
      layout: false,
      mbkautheVar: mbkautheVar,
      version: packageJson.version,
      latestVersion,
    });
  } catch (err) {
    console.error("[mbkauthe] Error fetching version information:", err);
    res.status(500).send(`
            <html>
                <head>
                    <title>Error</title>
                </head>
                <body>
                    <h1>Error</h1>
                    <p>Failed to fetch version information. Please try again later.</p>
                </body>
            </html>
        `);
  }
});
/*
// Configure GitHub Strategy for login
passport.use('github-login', new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: '/mbkauthe/api/github/login/callback',
    scope: ['user:email']
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            // Check if this GitHub account is linked to any user
            const githubUser = await dblogin.query(
                'SELECT ug.*, u."UserName", u."Role", u."Active", u."AllowedApps" FROM user_github ug JOIN "Users" u ON ug.user_name = u."UserName" WHERE ug.github_id = $1',
                [profile.id]
            );

            if (githubUser.rows.length === 0) {
                // GitHub account is not linked to any user
                return done(new Error('GitHub account not linked to any user'));
            }

            const user = githubUser.rows[0];
            
            // Check if the user account is active
            if (!user.Active) {
                return done(new Error('Account is inactive'));
            }

            // Check if user is authorized for this app (same logic as regular login)
            if (user.Role !== "SuperAdmin") {
                const allowedApps = user.AllowedApps;
                if (!allowedApps || !allowedApps.some(app => app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
                    return done(new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`));
                }
            }

            // Return user data for login
            return done(null, {
                id: user.id, // This should be the user ID from the Users table
                username: user.UserName,
                role: user.Role,
                githubId: user.github_id,
                githubUsername: user.github_username
            });
        } catch (err) {
            console.error('[mbkauthe] GitHub login error:', err);
            return done(err);
        }
    }
));

// Serialize/Deserialize user for GitHub login
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Initialize passport
router.use(passport.initialize());
router.use(passport.session());

// GitHub login initiation
router.get('/mbkauthe/api/github/login', passport.authenticate('github-login'));

// GitHub login callback
router.get('/mbkauthe/api/github/login/callback',
    passport.authenticate('github-login', { 
        failureRedirect: '/mbkauthe/login?error=github_auth_failed',
        session: false // We'll handle session manually
    }),
    async (req, res) => {
        try {
            const githubUser = req.user;
            
            // Find the actual user record
            const userQuery = `SELECT * FROM "Users" WHERE "UserName" = $1`;
            const userResult = await dblogin.query(userQuery, [githubUser.username]);

            if (userResult.rows.length === 0) {
                console.log(`[mbkauthe] GitHub login: User not found: ${githubUser.username}`);
                return res.redirect('/mbkauthe/login?error=user_not_found');
            }

            const user = userResult.rows[0];

            // Check 2FA if enabled
            if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true") {
                const twoFAQuery = `SELECT "TwoFAStatus" FROM "TwoFA" WHERE "UserName" = $1`;
                const twoFAResult = await dblogin.query(twoFAQuery, [githubUser.username]);

                if (twoFAResult.rows.length > 0 && twoFAResult.rows[0].TwoFAStatus) {
                    // 2FA is enabled, store pre-auth user and redirect to 2FA
                    req.session.preAuthUser = {
                        id: user.id,
                        username: user.UserName,
                        role: user.Role,
                        loginMethod: 'github'
                    };
                    console.log(`[mbkauthe] GitHub login: 2FA required for user: ${githubUser.username}`);
                    return res.redirect('/mbkauthe/2fa');
                }
            }

            // Complete login process
            const userForSession = {
                id: user.id,
                username: user.UserName,
                role: user.Role,
            };

            // Generate session and complete login
            const sessionId = crypto.randomBytes(32).toString("hex");
            console.log(`[mbkauthe] GitHub login: Generated session ID for username: ${user.UserName}`);

            // Delete old session record for this user
            await dblogin.query('DELETE FROM "session" WHERE username = $1', [user.UserName]);

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

            req.session.save(async (err) => {
                if (err) {
                    console.log("[mbkauthe] GitHub login session save error:", err);
                    return res.redirect('/mbkauthe/login?error=session_error');
                }
                
                try {
                    await dblogin.query(
                        'UPDATE "session" SET username = $1 WHERE sid = $2',
                        [user.UserName, req.sessionID]
                    );
                } catch (e) {
                    console.log("[mbkauthe] GitHub login: Failed to update username in session table:", e);
                }

                const cookieOptions = getCookieOptions();
                res.cookie("sessionId", sessionId, cookieOptions);
                console.log(`[mbkauthe] GitHub login: User "${user.UserName}" logged in successfully`);

                // Redirect to the configured URL or home
                const redirectUrl = mbkautheVar.loginRedirectURL || '/home';
                res.redirect(redirectUrl);
            });

        } catch (err) {
            console.error('[mbkauthe] GitHub login callback error:', err);
            res.redirect('/mbkauthe/login?error=internal_error');
        }
    }
);
*/
export { getLatestVersion };
export default router;