import express from "express";
import csurf from "csurf";
import crypto from "crypto";
import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import { dblogin } from "./pool.js";
import { authenticate, validateSession, validateSessionAndRole } from "./validateSessionAndRole.js";
import fetch from 'node-fetch';
import cookieParser from "cookie-parser";
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import speakeasy from "speakeasy";
import passport from 'passport';
import GitHubStrategy from 'passport-github2';

import { createRequire } from "module";
import { fileURLToPath } from "url";
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));

router.get('/mbkauthe/main.js', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'main.js'));
});

router.get("/mbkauthe/bg.avif", (req, res) => {
  const imgPath = path.join(__dirname, "..", "public", "bg.avif");
  res.setHeader('Content-Type', 'image/avif');
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  const stream = fs.createReadStream(imgPath);
  stream.on('error', (err) => {
    console.error('[mbkauthe] Error streaming bg.avif:', err);
    res.status(404).send('Image not found');
  });
  stream.pipe(res);
});

// CSRF protection middleware
const csrfProtection = csurf({ cookie: true });

// CORS and security headers
router.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    try {
      const originUrl = new URL(origin);
      const allowedDomain = `.${mbkautheVar.DOMAIN}`;
      // Exact match or subdomain match (must end with .domain.com, not just domain.com)
      if (originUrl.hostname === mbkautheVar.DOMAIN ||
        (originUrl.hostname.endsWith(allowedDomain) && originUrl.hostname.charAt(originUrl.hostname.length - allowedDomain.length - 1) !== '.')) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      }
    } catch (err) {
      // Invalid origin URL, skip CORS headers
    }
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

const GitHubOAuthLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: "Too many GitHub login attempts, please try again later"
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
    secure: mbkautheVar.IS_DEPLOYED === 'true',
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

      // Validate sessionId format (should be 64 hex characters) and normalize to lowercase
      if (typeof sessionId !== 'string' || !/^[a-f0-9]{64}$/i.test(sessionId)) {
        console.warn("[mbkauthe] Invalid sessionId format detected");
        return next();
      }

      const normalizedSessionId = sessionId.toLowerCase();

      const query = `SELECT id, "UserName", "Active", "Role", "SessionId", "AllowedApps" FROM "Users" WHERE LOWER("SessionId") = $1 AND "Active" = true`;
      const result = await dblogin.query({ name: 'restore-user-session', text: query, values: [normalizedSessionId] });

      if (result.rows.length > 0) {
        const user = result.rows[0];
        req.session.user = {
          id: user.id,
          username: user.UserName,
          UserName: user.UserName,
          role: user.Role,
          Role: user.Role,
          sessionId: normalizedSessionId,
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

router.get('/mbkauthe/test', validateSession, LoginLimit, async (req, res) => {
  if (req.session?.user) {
    return res.send(`
      <head> <script src="/mbkauthe/main.js"></script> </head>
      <p>if you are seeing this page than User is logged in.</p>
      <p>id: '${req.session.user.id}', UserName: '${req.session.user.username}', Role: '${req.session.user.role}', SessionId: '${req.session.user.sessionId}'</p>
      <button onclick="logout()">Logout</button><br>
      <a href="/mbkauthe/info">Info Page</a><br>
      <a href="/mbkauthe/login">Login Page</a><br>
      `);
  }
});

async function completeLoginProcess(req, res, user, redirectUrl = null) {
  try {
    // Ensure both username formats are available for compatibility
    const username = user.username || user.UserName;
    if (!username) {
      throw new Error('Username is required in user object');
    }

    // smaller session id is sufficient and faster to generate/serialize
    const sessionId = crypto.randomBytes(32).toString("hex");
    console.log(`[mbkauthe] Generated session ID for username: ${username}`);

    // Regenerate session to prevent session fixation attacks
    const oldSessionId = req.sessionID;
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Delete all old sessions for this user from session table
    await dblogin.query({
      name: 'login-delete-old-user-sessions',
      text: 'DELETE FROM "session" WHERE sess::text LIKE $1',
      values: [`%"username":"${username}"%`]
    });

    await dblogin.query({
      name: 'login-update-session-id', text: `UPDATE "Users" SET "SessionId" = $1 WHERE "id" = $2`, values: [
        sessionId,
        user.id,
      ]
    });

    req.session.user = {
      id: user.id,
      username: username,
      UserName: username,
      role: user.role || user.Role,
      Role: user.role || user.Role,
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
      console.log(`[mbkauthe] User "${username}" logged in successfully`);

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
    await dblogin.query({ name: 'terminate-all-user-sessions', text: `UPDATE "Users" SET "SessionId" = NULL` });
    await dblogin.query({ name: 'terminate-all-db-sessions', text: 'DELETE FROM "session"' });

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
    const userResult = await dblogin.query({ name: 'login-get-user', text: userQuery, values: [trimmedUsername] });

    if (userResult.rows.length === 0) {
      console.log(`[mbkauthe] Login failed: invalid credentials`);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
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
          console.log("[mbkauthe] Login failed: invalid credentials");
          return res.status(401).json({ success: false, errorCode: 603, message: "Invalid credentials" });
        }
        console.log("[mbkauthe] Password validated successfully");
      } catch (err) {
        console.error("[mbkauthe] Error comparing password:", err);
        return res.status(500).json({ success: false, errorCode: 605, message: `Internal Server Error` });
      }
    } else {
      if (user.Password !== password) {
        console.log(`[mbkauthe] Login failed: invalid credentials`);
        return res.status(401).json({ success: false, errorCode: 603, message: "Invalid credentials" });
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
      const twoFAResult = await dblogin.query({ name: 'login-check-2fa-status', text: query, values: [trimmedUsername] });

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
    appName: mbkautheVar.APP_NAME.toLowerCase(),
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
    const twoFAResult = await dblogin.query({ name: 'verify-2fa-secret', text: query, values: [username] });

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

router.post("/mbkauthe/api/logout", LogoutLimit, async (req, res) => {
  if (req.session.user) {
    try {
      const { id, username } = req.session.user;

      await dblogin.query({ name: 'logout-clear-session', text: `UPDATE "Users" SET "SessionId" = NULL WHERE "id" = $1`, values: [id] });

      if (req.sessionID) {
        await dblogin.query({ name: 'logout-delete-session', text: 'DELETE FROM "session" WHERE sid = $1', values: [req.sessionID] });
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
    appName: mbkautheVar.APP_NAME.toLowerCase(),
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

router.get(["/mbkauthe/info", "/mbkauthe/i"], LoginLimit, async (req, res) => {
  let latestVersion;
  const parameters = req.query;
  let authorized = false;

  if (parameters.password && mbkautheVar.Main_SECRET_TOKEN) {
    authorized = String(parameters.password) === String(mbkautheVar.Main_SECRET_TOKEN);
  }

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
      authorized: authorized,
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

// Configure GitHub Strategy for login
passport.use('github-login', new GitHubStrategy({
  clientID: mbkautheVar.GITHUB_CLIENT_ID,
  clientSecret: mbkautheVar.GITHUB_CLIENT_SECRET,
  callbackURL: '/mbkauthe/api/github/login/callback',
  scope: ['user:email']
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if this GitHub account is linked to any user
      const githubUser = await dblogin.query({
        name: 'github-login-get-user',
        text: 'SELECT ug.*, u."UserName", u."Role", u."Active", u."AllowedApps", u."id" FROM user_github ug JOIN "Users" u ON ug.user_name = u."UserName" WHERE ug.github_id = $1',
        values: [profile.id]
      });

      if (githubUser.rows.length === 0) {
        // GitHub account is not linked to any user
        const error = new Error('GitHub account not linked to any user');
        error.code = 'GITHUB_NOT_LINKED';
        return done(error);
      }

      const user = githubUser.rows[0];

      // Check if the user account is active
      if (!user.Active) {
        const error = new Error('Account is inactive');
        error.code = 'ACCOUNT_INACTIVE';
        return done(error);
      }

      // Check if user is authorized for this app (same logic as regular login)
      if (user.Role !== "SuperAdmin") {
        const allowedApps = user.AllowedApps;
        if (!allowedApps || !allowedApps.some(app => app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
          const error = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
          error.code = 'NOT_AUTHORIZED';
          return done(error);
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
      err.code = err.code || 'GITHUB_AUTH_ERROR';
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
router.get('/mbkauthe/api/github/login', GitHubOAuthLimit, (req, res, next) => {
  if (mbkautheVar.GITHUB_LOGIN_ENABLED) {
    // Store redirect parameter in session before OAuth flow (validate to prevent open redirect)
    const redirect = req.query.redirect;
    if (redirect && typeof redirect === 'string') {
      // Only allow relative URLs or same-origin URLs to prevent open redirect attacks
      if (redirect.startsWith('/') && !redirect.startsWith('//')) {
        req.session.oauthRedirect = redirect;
      } else {
        console.warn(`[mbkauthe] Invalid redirect parameter rejected: ${redirect}`);
      }
    }
    passport.authenticate('github-login')(req, res, next);
  }
  else {
    res.status(403).render('Error/dError.handlebars', {
      layout: false,
      code: '403',
      error: 'GitHub Login Disabled',
      message: 'GitHub login is currently disabled. Please use your username and password to log in.',
      page: '/mbkauthe/login',
      pagename: 'Login',
      version: packageJson.version,
      app: mbkautheVar.APP_NAME
    });
  }
});

// GitHub login callback
router.get('/mbkauthe/api/github/login/callback',
  GitHubOAuthLimit,
  (req, res, next) => {
    passport.authenticate('github-login', {
      session: false // We'll handle session manually
    }, (err, user, info) => {
      // Custom error handling for passport authentication
      if (err) {
        console.error('[mbkauthe] GitHub authentication error:', err);

        // Map error codes to user-friendly messages
        switch (err.code) {
          case 'GITHUB_NOT_LINKED':
            return res.status(403).render('Error/dError.handlebars', {
              layout: false,
              code: '403',
              error: 'GitHub Account Not Linked',
              message: 'Your GitHub account is not linked to any user in our system. To link your GitHub account, a User must connect their GitHub account to mbktech account through the user settings.',
              page: '/mbkauthe/login',
              pagename: 'Login',
              version: packageJson.version,
              app: mbkautheVar.APP_NAME
            });

          case 'ACCOUNT_INACTIVE':
            return res.status(403).render('Error/dError.handlebars', {
              layout: false,
              code: '403',
              error: 'Account Inactive',
              message: 'Your account has been deactivated. Please contact your administrator.',
              page: '/mbkauthe/login',
              pagename: 'Login',
              version: packageJson.version,
              app: mbkautheVar.APP_NAME
            });

          case 'NOT_AUTHORIZED':
            return res.status(403).render('Error/dError.handlebars', {
              layout: false,
              code: '403',
              error: 'Not Authorized',
              message: `You are not authorized to access ${mbkautheVar.APP_NAME}. Please contact your administrator.`,
              page: '/mbkauthe/login',
              pagename: 'Login',
              version: packageJson.version,
              app: mbkautheVar.APP_NAME
            });

          default:
            return res.status(500).render('Error/dError.handlebars', {
              layout: false,
              code: '500',
              error: 'Authentication Error',
              message: 'An error occurred during GitHub authentication. Please try again.',
              page: '/mbkauthe/login',
              pagename: 'Login',
              version: packageJson.version,
              app: mbkautheVar.APP_NAME,
              details: process.env.NODE_ENV === 'development' ? `${err.message}\n${err.stack}` : 'Error details hidden in production'
            });
        }
      }

      if (!user) {
        console.error('[mbkauthe] GitHub callback: No user data received');
        return res.status(401).render('Error/dError.handlebars', {
          layout: false,
          code: '401',
          error: 'Authentication Failed',
          message: 'GitHub authentication failed. Please try again.',
          page: '/mbkauthe/login',
          pagename: 'Login',
          version: packageJson.version,
          app: mbkautheVar.APP_NAME
        });
      }

      // Authentication successful, attach user to request
      req.user = user;
      next();
    })(req, res, next);
  },
  async (req, res) => {
    try {
      const githubUser = req.user;

      // Find the actual user record with named query
      const userQuery = `SELECT id, "UserName", "Active", "Role", "AllowedApps" FROM "Users" WHERE "UserName" = $1`;
      const userResult = await dblogin.query({
        name: 'github-callback-get-user',
        text: userQuery,
        values: [githubUser.username]
      });

      if (userResult.rows.length === 0) {
        console.error(`[mbkauthe] GitHub login: User not found: ${githubUser.username}`);
        return res.status(404).render('Error/dError.handlebars', {
          layout: false,
          code: '404',
          error: 'User Not Found',
          message: 'Your GitHub account is linked, but the user account no longer exists in our system.',
          page: '/mbkauthe/login',
          pagename: 'Login',
          version: packageJson.version,
          app: mbkautheVar.APP_NAME,
          details: `GitHub username: ${githubUser.username}\nPlease contact your administrator.`
        });
      }

      const user = userResult.rows[0];

      // Check 2FA if enabled
      if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true") {
        const twoFAQuery = `SELECT "TwoFAStatus" FROM "TwoFA" WHERE "UserName" = $1`;
        const twoFAResult = await dblogin.query({
          name: 'github-check-2fa-status',
          text: twoFAQuery,
          values: [githubUser.username]
        });

        if (twoFAResult.rows.length > 0 && twoFAResult.rows[0].TwoFAStatus) {
          // 2FA is enabled, store pre-auth user and redirect to 2FA
          req.session.preAuthUser = {
            id: user.id,
            username: user.UserName,
            UserName: user.UserName,
            role: user.Role,
            Role: user.Role,
            loginMethod: 'github'
          };
          console.log(`[mbkauthe] GitHub login: 2FA required for user: ${githubUser.username}`);
          return res.redirect('/mbkauthe/2fa');
        }
      }

      // Complete login process using the shared function
      const userForSession = {
        id: user.id,
        username: user.UserName,
        UserName: user.UserName,
        role: user.Role,
        Role: user.Role
      };

      // For OAuth redirect flow, we need to handle redirect differently
      // Store the redirect URL before calling completeLoginProcess
      const oauthRedirect = req.session.oauthRedirect;
      delete req.session.oauthRedirect;

      // Custom response handler for OAuth flow - wrap the response object
      const originalJson = res.json.bind(res);
      const originalStatus = res.status.bind(res);
      let statusCode = 200;

      res.status = function (code) {
        statusCode = code;
        return originalStatus(code);
      };

      res.json = function (data) {
        if (data.success && statusCode === 200) {
          // If login successful, redirect instead of sending JSON
          const redirectUrl = oauthRedirect || mbkautheVar.loginRedirectURL || '/home';
          console.log(`[mbkauthe] GitHub login: Redirecting to ${redirectUrl}`);
          // Restore original methods before redirect
          res.json = originalJson;
          res.status = originalStatus;
          return res.redirect(redirectUrl);
        }
        // Restore original methods for error responses
        res.json = originalJson;
        res.status = originalStatus;
        return originalJson(data);
      };

      await completeLoginProcess(req, res, userForSession);

    } catch (err) {
      console.error('[mbkauthe] GitHub login callback error:', err);
      return res.status(500).render('Error/dError.handlebars', {
        layout: false,
        code: '500',
        error: 'Internal Server Error',
        message: 'An error occurred during GitHub authentication. Please try again.',
        page: '/mbkauthe/login',
        pagename: 'Login',
        version: packageJson.version,
        app: mbkautheVar.APP_NAME,
        details: process.env.NODE_ENV === 'development' ? `${err.message}\n${err.stack}` : 'Error details hidden in production'
      });
    }
  }
);

export { getLatestVersion };
export default router;