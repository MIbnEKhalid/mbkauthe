import express from "express";
import crypto from "crypto";
import csurf from "csurf";
import speakeasy from "speakeasy";
import rateLimit from 'express-rate-limit';
import { dblogin } from "../database/pool.js";
import { mbkautheVar } from "../config/index.js";
import {
  cachedCookieOptions, cachedClearCookieOptions, clearSessionCookies,
  generateDeviceToken, getDeviceTokenCookieOptions, DEVICE_TRUST_DURATION_MS
} from "../config/cookies.js";
import { packageJson } from "../config/index.js";
import { hashPassword } from "../config/security.js";
import { ErrorCodes, createErrorResponse, logError } from "../utils/errors.js";

const router = express.Router();

// Rate limiters for auth routes
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

// CSRF protection middleware
const csrfProtection = csurf({ cookie: true });

/**
 * Check if the device is trusted for the given username
 */
export async function checkTrustedDevice(req, username) {
  const deviceToken = req.cookies.device_token;

  if (!deviceToken || typeof deviceToken !== 'string') {
    return null;
  }

  try {
    const deviceQuery = `
      SELECT td."UserName", td."LastUsed", td."ExpiresAt", u."id", u."Active", u."Role", u."AllowedApps"
      FROM "TrustedDevices" td
      JOIN "Users" u ON td."UserName" = u."UserName"
      WHERE td."DeviceToken" = $1 AND td."UserName" = $2 AND td."ExpiresAt" > NOW()
    `;
    const deviceResult = await dblogin.query({
      name: 'check-trusted-device',
      text: deviceQuery,
      values: [deviceToken, username]
    });

    if (deviceResult.rows.length > 0) {
      const deviceUser = deviceResult.rows[0];

      if (!deviceUser.Active) {
        console.log(`[mbkauthe] Trusted device check: inactive account for username: ${username}`);
        return null;
      }

      if (deviceUser.Role !== "SuperAdmin") {
        const allowedApps = deviceUser.AllowedApps;
        if (!allowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
          console.warn(`[mbkauthe] Trusted device check: User "${username}" is not authorized to use the application "${mbkautheVar.APP_NAME}"`);
          return null;
        }
      }

      // Update last used timestamp
      await dblogin.query({
        name: 'update-device-last-used',
        text: 'UPDATE "TrustedDevices" SET "LastUsed" = NOW() WHERE "DeviceToken" = $1',
        values: [deviceToken]
      });

      console.log(`[mbkauthe] Trusted device validated for user: ${username}`);
      return {
        id: deviceUser.id,
        username: username,
        role: deviceUser.Role,
        Role: deviceUser.Role,
        allowedApps: deviceUser.AllowedApps,
      };
    }
  } catch (deviceErr) {
    console.error("[mbkauthe] Error checking trusted device:", deviceErr);
  }

  return null;
}

/**
 * Complete the login process by creating session and cookies
 */
export async function completeLoginProcess(req, res, user, redirectUrl = null, trustDevice = false) {
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

    // Run both queries in parallel for better performance
    await Promise.all([
      // Delete old sessions using indexed lookup on sess->'user'->>'id'
      dblogin.query({
        name: 'login-delete-old-user-sessions',
        text: 'DELETE FROM "session" WHERE (sess->\'user\'->>\'id\')::int = $1',
        values: [user.id]
      }),
      // Update session ID and last login time in Users table
      dblogin.query({
        name: 'login-update-session-and-last-login',
        text: `UPDATE "Users" SET "SessionId" = $1, "last_login" = NOW() WHERE "id" = $2`,
        values: [sessionId, user.id]
      })
    ]);

    req.session.user = {
      id: user.id,
      username: username,
      UserName: username,
      role: user.role || user.Role,
      Role: user.role || user.Role,
      sessionId,
      allowedApps: user.allowedApps || user.AllowedApps,
    };

    if (req.session.preAuthUser) {
      delete req.session.preAuthUser;
    }

    req.session.save(async (err) => {
      if (err) {
        console.error("[mbkauthe] Session save error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      res.cookie("sessionId", sessionId, cachedCookieOptions);

      // Handle trusted device if requested
      if (trustDevice) {
        try {
          const deviceToken = generateDeviceToken();
          const deviceName = req.headers['user-agent'] ?
            req.headers['user-agent'].substring(0, 255) : 'Unknown Device';
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';
          const expiresAt = new Date(Date.now() + DEVICE_TRUST_DURATION_MS);

          await dblogin.query({
            name: 'insert-trusted-device',
            text: `INSERT INTO "TrustedDevices" ("UserName", "DeviceToken", "DeviceName", "UserAgent", "IpAddress", "ExpiresAt") 
                   VALUES ($1, $2, $3, $4, $5, $6)`,
            values: [username, deviceToken, deviceName, userAgent, ipAddress, expiresAt]
          });

          res.cookie("device_token", deviceToken, getDeviceTokenCookieOptions());
          console.log(`[mbkauthe] Trusted device token created for user: ${username}`);
        } catch (deviceErr) {
          console.error("[mbkauthe] Error creating trusted device:", deviceErr);
          // Continue with login even if device trust fails
        }
      }

      console.log(`[mbkauthe] User "${username}" logged in successfully (last_login updated)`);

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

// POST /mbkauthe/api/login
router.post("/api/login", LoginLimit, async (req, res) => {
  console.log("[mbkauthe] Login request received");

  const { username, password, redirect } = req.body;

  // Input validation
  if (!username || !password) {
    logError('Login attempt', ErrorCodes.MISSING_REQUIRED_FIELD, { username: username || 'missing' });
    return res.status(400).json(
      createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, {
        message: "Username and password are required"
      })
    );
  }

  // Validate username format and length
  if (typeof username !== 'string' || username.trim().length === 0 || username.length > 255) {
    logError('Login attempt', ErrorCodes.INVALID_USERNAME_FORMAT, { username });
    return res.status(400).json(
      createErrorResponse(400, ErrorCodes.INVALID_USERNAME_FORMAT)
    );
  }

  // Validate password length
  if (typeof password !== 'string' || password.length < 8 || password.length > 255) {
    logError('Login attempt', ErrorCodes.INVALID_PASSWORD_LENGTH, { username: username.trim() });
    return res.status(400).json(
      createErrorResponse(400, ErrorCodes.INVALID_PASSWORD_LENGTH)
    );
  }

  console.log(`[mbkauthe] Login attempt for username: ${username.trim()}`);

  const trimmedUsername = username.trim();

  try {
    // Combined query: fetch user data and 2FA status in one query
    const userQuery = `
      SELECT u.id, u."UserName", u."Password", u."PasswordEnc", u."Active", u."Role", u."AllowedApps",
             tfa."TwoFAStatus"
      FROM "Users" u
      LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
      WHERE u."UserName" = $1
    `;
    const userResult = await dblogin.query({ name: 'login-get-user', text: userQuery, values: [trimmedUsername] });

    if (userResult.rows.length === 0) {
      logError('Login attempt', ErrorCodes.USER_NOT_FOUND, { username: trimmedUsername });
      return res.status(401).json(
        createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS)
      );
    }

    const user = userResult.rows[0];

    // Validate user has password field
    if (!user.Password && !user.PasswordEnc) {
      console.error("[mbkauthe] User account has no password set");
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }

    // Check password based on EncPass configuration - ALWAYS validate password first
    let passwordMatches = false;
    if (mbkautheVar.EncPass === "true" || mbkautheVar.EncPass === true) {
      // Use encrypted password comparison
      if (user.PasswordEnc) {
        const hashedInputPassword = hashPassword(password, user.UserName);
        passwordMatches = user.PasswordEnc === hashedInputPassword;
      }
    } else {
      // Use raw password comparison
      if (user.Password) {
        passwordMatches = user.Password === password;
      }
    }

    if (!passwordMatches) {
      logError('Login attempt', ErrorCodes.INCORRECT_PASSWORD, { username: trimmedUsername });
      return res.status(401).json(
        createErrorResponse(401, ErrorCodes.INCORRECT_PASSWORD)
      );
    }

    if (!user.Active) {
      logError('Login attempt', ErrorCodes.ACCOUNT_INACTIVE, { username: trimmedUsername });
      return res.status(403).json(
        createErrorResponse(403, ErrorCodes.ACCOUNT_INACTIVE)
      );
    }

    if (user.Role !== "SuperAdmin") {
      const allowedApps = user.AllowedApps;
      if (!allowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
        logError('Login attempt', ErrorCodes.APP_NOT_AUTHORIZED, { 
          username: user.UserName, 
          app: mbkautheVar.APP_NAME 
        });
        return res.status(403).json(
          createErrorResponse(403, ErrorCodes.APP_NOT_AUTHORIZED, {
            message: `You are not authorized to access ${mbkautheVar.APP_NAME}`,
            app: mbkautheVar.APP_NAME
          })
        );
      }
    }

    // Check for trusted device AFTER password validation
    const trustedDeviceUser = await checkTrustedDevice(req, trimmedUsername);
    if (trustedDeviceUser && (mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLocaleLowerCase() === "true" && user.TwoFAStatus) {
      console.log(`[mbkauthe] Trusted device login for user: ${trimmedUsername}, skipping 2FA only`);

      const userForSession = {
        id: user.id,
        username: user.UserName,
        role: user.Role,
        Role: user.Role,
        allowedApps: user.AllowedApps,
      };
      const requestedRedirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : null;
      return await completeLoginProcess(req, res, userForSession, requestedRedirect);
    }

    if ((mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLocaleLowerCase() === "true" && user.TwoFAStatus) {
      // 2FA is enabled, prompt for token on a separate page
      const requestedRedirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : null;
      req.session.preAuthUser = {
        id: user.id,
        username: user.UserName,
        role: user.Role,
        Role: user.Role,
        redirectUrl: requestedRedirect
      };
      console.log(`[mbkauthe] 2FA required for user: ${trimmedUsername}`);
      return res.json({ success: true, twoFactorRequired: true, redirectUrl: requestedRedirect });
    }

    // If 2FA is not enabled, proceed with login
    const userForSession = {
      id: user.id,
      username: user.UserName,
      role: user.Role,
      Role: user.Role,
      allowedApps: user.AllowedApps,
    };
    const requestedRedirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : null;
    await completeLoginProcess(req, res, userForSession, requestedRedirect);

  } catch (err) {
    console.error("[mbkauthe] Error during login process:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// GET /mbkauthe/2fa
router.get("/2fa", csrfProtection, (req, res) => {
  if (!req.session.preAuthUser) {
    return res.redirect("/mbkauthe/login");
  }

  // Prefer explicit redirect from query string, else from session preAuthUser redirectUrl, else fallback value
  let redirectFromQuery = req.query && typeof req.query.redirect === 'string' ? req.query.redirect : null;
  let redirectToUse = redirectFromQuery || req.session.preAuthUser.redirectUrl || (mbkautheVar.loginRedirectURL || '/dashboard');

  // Validate redirectToUse to prevent open redirect attacks
  if (redirectToUse && !(typeof redirectToUse === 'string' && redirectToUse.startsWith('/') && !redirectToUse.startsWith('//'))) {
    redirectToUse = mbkautheVar.loginRedirectURL || '/dashboard';
  }

  res.render("2fa.handlebars", {
    layout: false,
    customURL: redirectToUse,
    csrfToken: req.csrfToken(),
    appName: mbkautheVar.APP_NAME.toLowerCase(),
    version: packageJson.version,
    DEVICE_TRUST_DURATION_DAYS: mbkautheVar.DEVICE_TRUST_DURATION_DAYS
  });
});

// POST /mbkauthe/api/verify-2fa
router.post("/api/verify-2fa", TwoFALimit, csrfProtection, async (req, res) => {
  if (!req.session.preAuthUser) {
    return res.status(401).json(
      createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, {
        message: "Please log in first"
      })
    );
  }

  const { token, trustDevice } = req.body;
  const { username, id, role } = req.session.preAuthUser;

  // Validate 2FA token
  if (!token || typeof token !== 'string') {
    return res.status(400).json(
      createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, {
        message: "2FA token is required"
      })
    );
  }

  // Validate token format (should be 6 digits)
  const sanitizedToken = token.trim();
  if (!/^\d{6}$/.test(sanitizedToken)) {
    return res.status(400).json(
      createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT)
    );
  }

  // Validate trustDevice parameter if provided
  const shouldTrustDevice = trustDevice === true || trustDevice === 'true';

  try {
    const query = `SELECT tfa."TwoFASecret", u."AllowedApps" FROM "TwoFA" tfa JOIN "Users" u ON tfa."UserName" = u."UserName" WHERE tfa."UserName" = $1`;
    const twoFAResult = await dblogin.query({ name: 'verify-2fa-secret', text: query, values: [username] });

    if (twoFAResult.rows.length === 0 || !twoFAResult.rows[0].TwoFASecret) {
      return res.status(500).json(
        createErrorResponse(500, ErrorCodes.TWO_FA_NOT_CONFIGURED)
      );
    }

    const sharedSecret = twoFAResult.rows[0].TwoFASecret;
    const allowedApps = twoFAResult.rows[0].AllowedApps;
    const tokenValidates = speakeasy.totp.verify({
      secret: sharedSecret,
      encoding: "base32",
      token: sanitizedToken,
      window: 1,
    });

    if (!tokenValidates) {
      logError('2FA verification', ErrorCodes.TWO_FA_INVALID_TOKEN, { username });
      return res.status(401).json(
        createErrorResponse(401, ErrorCodes.TWO_FA_INVALID_TOKEN)
      );
    }

    // 2FA successful, complete login with optional device trust
    const userForSession = { id, username, role, allowedApps };
    // Prefer redirect stored in preAuthUser or in query/body, fallback to configured default
    let redirectFromSession = req.session.preAuthUser && req.session.preAuthUser.redirectUrl ? req.session.preAuthUser.redirectUrl : null;
    if (redirectFromSession && (!(typeof redirectFromSession === 'string') || !redirectFromSession.startsWith('/') || redirectFromSession.startsWith('//'))) {
      redirectFromSession = null;
    }
    const redirectUrl = redirectFromSession || mbkautheVar.loginRedirectURL || '/dashboard';
    // Clear preAuthUser after successful login
    if (req.session.preAuthUser) delete req.session.preAuthUser;
    await completeLoginProcess(req, res, userForSession, redirectUrl, shouldTrustDevice);

  } catch (err) {
    console.error("[mbkauthe] Error during 2FA verification:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// POST /mbkauthe/api/logout
router.post("/api/logout", LogoutLimit, async (req, res) => {
  if (req.session.user) {
    try {
      const { id, username } = req.session.user;

      // Run both database operations in parallel
      const operations = [
        dblogin.query({ name: 'logout-clear-session', text: `UPDATE "Users" SET "SessionId" = NULL WHERE "id" = $1`, values: [id] })
      ];

      if (req.sessionID) {
        operations.push(
          dblogin.query({ name: 'logout-delete-session', text: 'DELETE FROM "session" WHERE sid = $1', values: [req.sessionID] })
        );
      }

      await Promise.all(operations);

      req.session.destroy((err) => {
        if (err) {
          console.error("[mbkauthe] Error destroying session:", err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }

        clearSessionCookies(res);

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

// GET /mbkauthe/login
router.get("/login", LoginLimit, csrfProtection, (req, res) => {
  return res.render("loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: mbkautheVar.GITHUB_LOGIN_ENABLED,
    customURL: mbkautheVar.loginRedirectURL || '/dashboard',
    userLoggedIn: !!req.session?.user,
    username: req.session?.user?.username || '',
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME.toLowerCase(),
    csrfToken: req.csrfToken(),
  });
});

export default router;