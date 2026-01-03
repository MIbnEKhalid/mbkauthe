import express from "express";
import crypto from "crypto";
import csurf from "csurf";
import speakeasy from "speakeasy";
import rateLimit from 'express-rate-limit';
import { dblogin } from "../database/pool.js";
import { mbkautheVar } from "../config/index.js";
import {
  cachedCookieOptions, cachedClearCookieOptions, clearSessionCookies,
  generateDeviceToken, getDeviceTokenCookieOptions, DEVICE_TRUST_DURATION_MS, hashDeviceToken,
  upsertAccountListCookie, readAccountListFromCookie, removeAccountFromCookie, clearAccountListCookie
} from "../config/cookies.js";
import { packageJson } from "../config/index.js";
import { hashPassword } from "../config/security.js";
import { ErrorCodes, createErrorResponse, logError } from "../utils/errors.js";

const router = express.Router();

// Helper function to clear profile picture cache
function clearProfilePicCache(req, username) {
  if (req.session && username) {
    const cacheKey = `profilepic_${username}`;
    delete req.session[cacheKey];
  }
}

// Rate limiters for auth routes
const LoginLimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 8,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => {
    return !!req.session.user;
  },
  validate: {
    trustProxy: false,
    xForwardedForHeader: false
  }
});

const LogoutLimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many logout attempts, please try again later" },
  validate: {
    trustProxy: false,
    xForwardedForHeader: false
  }
});

const TwoFALimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: { success: false, message: "Too many 2FA attempts, please try again later" },
  validate: {
    trustProxy: false,
    xForwardedForHeader: false
  }
});

// CSRF protection middleware
const csrfProtection = csurf({ cookie: true });

// Helper: load a session by DB id and validate basics
async function fetchActiveSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') return null;
  const query = `SELECT s.id as sid, s.expires_at, u.id as uid, u."UserName", u."Active", u."Role", u."AllowedApps"
                 FROM "Sessions" s
                 JOIN "Users" u ON s."UserName" = u."UserName"
                 WHERE s.id = $1 LIMIT 1`;
  const result = await dblogin.query({ name: 'multi-session-fetch', text: query, values: [sessionId] });
  if (result.rows.length === 0) return null;
  const row = result.rows[0];
  if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) return null;
  if (row.Role !== 'SuperAdmin') {
    const allowedApps = row.AllowedApps;
    const hasAllowedApps = Array.isArray(allowedApps) && allowedApps.length > 0;
    if (!hasAllowedApps || !allowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase())) {
      return null;
    }
  }
  return row;
}

const isUuid = (val) => typeof val === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);

async function invalidateDbSession(sessionId) {
  if (!isUuid(sessionId)) return;
  try {
    await dblogin.query({ name: 'invalidate-app-session', text: 'DELETE FROM "Sessions" WHERE id = $1', values: [sessionId] });
  } catch (err) {
    console.error('[mbkauthe] Error invalidating session:', err);
  }
}

/**
 * Check if the device is trusted for the given username
 */
export async function checkTrustedDevice(req, username) {
  const deviceToken = req.cookies.device_token;

  if (!deviceToken || typeof deviceToken !== 'string') {
    return null;
  }

  try {
    // Hash the provided device token before querying DB (we store token hashes in DB)
    const deviceTokenHash = hashDeviceToken(deviceToken);
    const deviceQuery = `
      SELECT td."UserName", td."LastUsed", td."ExpiresAt", u."id", u."Active", u."Role", u."AllowedApps"
      FROM "TrustedDevices" td
      JOIN "Users" u ON td."UserName" = u."UserName"
      WHERE td."DeviceToken" = $1 AND td."UserName" = $2 AND td."ExpiresAt" > NOW()
    `;
    const deviceResult = await dblogin.query({
      name: 'check-trusted-device',
      text: deviceQuery,
      values: [deviceTokenHash, username]
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
        values: [deviceTokenHash]
      });

      console.log(`[mbkauthe] Trusted device validated for user: ${username}`);
      return {
        id: deviceUser.id,
        username: username,
        role: deviceUser.Role,
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

    // Fix session fixation: Delete old session BEFORE regenerating to prevent timing window
    const oldSessionId = req.sessionID;

    // Delete old session first to prevent session fixation attacks
    await dblogin.query({
      name: 'login-delete-old-session-before-regen',
      text: 'DELETE FROM "session" WHERE sid = $1',
      values: [oldSessionId]
    });

    // Now regenerate with new session ID (timing window closed)
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Enforce max sessions per user (configurable via mbkautheVar.MAX_SESSIONS_PER_USER) and persist a new application session record (keyed by username)
    const configuredMax = parseInt(mbkautheVar.MAX_SESSIONS_PER_USER, 10);
    const MAX_SESSIONS = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : 5;

    // Clean up expired sessions first to prevent accumulation
    await dblogin.query({
      name: 'cleanup-expired-sessions',
      text: `DELETE FROM "Sessions" WHERE "UserName" = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()`,
      values: [username]
    });

    // Count active sessions for this user (by username)
    const countRes = await dblogin.query({
      name: 'count-user-sessions',
      text: `SELECT id FROM "Sessions" WHERE "UserName" = $1 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at ASC`,
      values: [username]
    });

    const currentSessions = countRes.rows.length;
    // If we have MAX_SESSIONS or more, delete oldest to make room for exactly 1 new session
    if (currentSessions >= MAX_SESSIONS) {
      const sessionsToDelete = currentSessions - MAX_SESSIONS + 1; // +1 to make room for new session
      console.log(`[mbkauthe] User "${username}" has ${currentSessions} active sessions, exceeding max of ${MAX_SESSIONS}. Deleting ${sessionsToDelete} oldest sessions.`);

      await dblogin.query({
        name: 'prune-oldest-user-session',
        text: `DELETE FROM "Sessions" WHERE id IN (SELECT id FROM "Sessions" WHERE "UserName" = $1 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at ASC LIMIT $2)`,
        values: [username, sessionsToDelete]
      });
    }

    const expiresAt = new Date(Date.now() + (cachedCookieOptions.maxAge || 0));

    // Insert new session record for the user (store username) and return the DB id
    const insertRes = await dblogin.query({
      name: 'insert-app-session',
      text: `INSERT INTO "Sessions" ("UserName", expires_at, meta) VALUES ($1, $2, $3) RETURNING id`,
      values: [username, expiresAt, JSON.stringify({ ip: req.ip, ua: req.headers['user-agent'] || null })]
    });
    const dbSessionId = insertRes.rows[0].id;

    // Update last_login timestamp for the user
    await dblogin.query({
      name: 'login-update-last-login',
      text: `UPDATE "Users" SET "last_login" = NOW() WHERE "id" = $1`,
      values: [user.id]
    });

    req.session.user = {
      id: user.id,
      username: username,
      role: user.role || user.Role,
      sessionId: dbSessionId,
      allowedApps: user.allowedApps || user.AllowedApps,
    };

    // Clear profile picture cache to fetch fresh data
    clearProfilePicCache(req, username);

    // Attempt to fetch FullName from Users and store it in session for display purposes
    try {
      const profileResult = await dblogin.query({
        name: 'login-get-fullname',
        text: 'SELECT "FullName" FROM "Users" WHERE "UserName" = $1 LIMIT 1',
        values: [username]
      });
      if (profileResult.rows.length > 0 && profileResult.rows[0].FullName) {
        req.session.user.fullname = profileResult.rows[0].FullName;
      }
    } catch (profileErr) {
      console.error("[mbkauthe] Error fetching FullName for user:", profileErr);
    }

    if (req.session.preAuthUser) {
      delete req.session.preAuthUser;
    }

    req.session.save(async (err) => {
      if (err) {
        console.error("[mbkauthe] Session save error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      // Expose DB session id and display name to client for UI (fullName falls back to username)
      res.cookie("sessionId", dbSessionId, cachedCookieOptions);
      res.cookie("fullName", req.session.user.fullname || username, { ...cachedCookieOptions, httpOnly: false });

      // Remember this account on the device for quick switching (server-trusted list)
      upsertAccountListCookie(req, res, {
        sessionId: dbSessionId,
        username,
        fullName: req.session.user.fullname || username
      });

      // Handle trusted device if requested (token no longer stored in DB as token_hash)
      if (trustDevice) {
        try {
          const deviceToken = generateDeviceToken();
          const deviceName = req.headers['user-agent'] ?
            req.headers['user-agent'].substring(0, 255) : 'Unknown Device';
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';
          const expiresAt = new Date(Date.now() + DEVICE_TRUST_DURATION_MS);

          // Store only the HASH of the device token in DB; send the raw token to the client (httpOnly cookie)
          const deviceTokenHash = hashDeviceToken(deviceToken);
          await dblogin.query({
            name: 'insert-trusted-device',
            text: `INSERT INTO "TrustedDevices" ("UserName", "DeviceToken", "DeviceName", "UserAgent", "IpAddress", "ExpiresAt") 
                   VALUES ($1, $2, $3, $4, $5, $6)`,
            values: [username, deviceTokenHash, deviceName, userAgent, ipAddress, expiresAt]
          });

          // Send raw token to client as httpOnly cookie only
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
        sessionId: dbSessionId,
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
        allowedApps: user.AllowedApps,
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
    // Use cached allowedApps from preAuthUser to avoid extra database join
    const cachedAllowedApps = req.session.preAuthUser?.allowedApps;

    const query = `SELECT tfa."TwoFASecret" FROM "TwoFA" tfa WHERE tfa."UserName" = $1`;
    const twoFAResult = await dblogin.query({ name: 'verify-2fa-secret', text: query, values: [username] });

    if (twoFAResult.rows.length === 0 || !twoFAResult.rows[0].TwoFASecret) {
      return res.status(500).json(
        createErrorResponse(500, ErrorCodes.TWO_FA_NOT_CONFIGURED)
      );
    }

    const sharedSecret = twoFAResult.rows[0].TwoFASecret;
    const allowedApps = cachedAllowedApps;
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

      // Clear profile picture cache
      clearProfilePicCache(req, username);

      // Remove the application session record for this token (if present)
      const operations = [];
      if (req.session && req.session.user && req.session.user.sessionId) {
        operations.push(dblogin.query({ name: 'logout-delete-app-session', text: 'DELETE FROM "Sessions" WHERE id = $1', values: [req.session.user.sessionId] }));
      }

      if (req.sessionID) {
        operations.push(dblogin.query({ name: 'logout-delete-session', text: 'DELETE FROM "session" WHERE sid = $1', values: [req.sessionID] }));
      }

      await Promise.all(operations);

      // Remove this account from the remembered list for the device
      if (req.session?.user?.sessionId) {
        removeAccountFromCookie(req, res, req.session.user.sessionId);
      }

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

// List remembered accounts for this device (validates each against DB)
router.get("/api/account-sessions", LoginLimit, async (req, res) => {
  const storedAccounts = readAccountListFromCookie(req);
  if (!storedAccounts.length) {
    return res.json({ accounts: [], currentSessionId: req.session?.user?.sessionId || null });
  }

  const validated = [];
  const currentSessionId = req.session?.user?.sessionId || null;

  for (const acct of storedAccounts) {
    if (!isUuid(acct.sessionId)) {
      removeAccountFromCookie(req, res, acct.sessionId);
      continue;
    }

    try {
      const row = await fetchActiveSession(acct.sessionId);
      if (!row) {
        await invalidateDbSession(acct.sessionId);
        removeAccountFromCookie(req, res, acct.sessionId);
        continue;
      }

      let fullName = acct.fullName || acct.username;
      if (!acct.fullName) {
        try {
          const prof = await dblogin.query({
            name: 'multi-session-fullname',
            text: 'SELECT "FullName" FROM "Users" WHERE "UserName" = $1 LIMIT 1',
            values: [row.UserName]
          });
          if (prof.rows.length > 0 && prof.rows[0].FullName) {
            fullName = prof.rows[0].FullName;
          }
        } catch (profileErr) {
          console.error('[mbkauthe] Error fetching fullname for account list:', profileErr);
        }
      }

      validated.push({
        sessionId: row.sid,
        username: row.UserName,
        fullName,
        isCurrent: currentSessionId && row.sid === currentSessionId
      });
    } catch (err) {
      console.error('[mbkauthe] Error validating remembered account:', err);
    }
  }

  return res.json({ accounts: validated, currentSessionId });
});

// Switch active session to another remembered account
router.post("/api/switch-session", LoginLimit, async (req, res) => {
  const { sessionId, redirect } = req.body || {};

  if (!isUuid(sessionId)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT, { message: 'Invalid session id' }));
  }

  const storedAccounts = readAccountListFromCookie(req);
  if (!storedAccounts.some(acct => acct.sessionId === sessionId)) {
    return res.status(403).json(createErrorResponse(403, ErrorCodes.SESSION_NOT_FOUND, { message: 'Account not available on this device' }));
  }

  try {
    const row = await fetchActiveSession(sessionId);
    if (!row) {
      await invalidateDbSession(sessionId);
      removeAccountFromCookie(req, res, sessionId);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_EXPIRED));
    }

    let fullName = row.UserName;
    try {
      const prof = await dblogin.query({
        name: 'multi-session-switch-fullname',
        text: 'SELECT "FullName" FROM "Users" WHERE "UserName" = $1 LIMIT 1',
        values: [row.UserName]
      });
      if (prof.rows.length > 0 && prof.rows[0].FullName) fullName = prof.rows[0].FullName;
    } catch (profileErr) {
      console.error('[mbkauthe] Error fetching fullname during switch:', profileErr);
    }

    // Regenerate session to avoid fixation
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => err ? reject(err) : resolve());
    });

    req.session.user = {
      id: row.uid,
      username: row.UserName,
      role: row.Role,
      sessionId: row.sid,
      allowedApps: row.AllowedApps,
      fullname: fullName
    };

    // Clear profile picture cache to fetch fresh data for new user
    clearProfilePicCache(req, row.UserName);

    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    // Sync cookies for client UI and remember list
    res.cookie('username', row.UserName, { ...cachedCookieOptions, httpOnly: false });
    res.cookie('fullName', fullName, { ...cachedCookieOptions, httpOnly: false });
    res.cookie('sessionId', row.sid, cachedCookieOptions);
    upsertAccountListCookie(req, res, { sessionId: row.sid, username: row.UserName, fullName });

    const safeRedirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')
      ? redirect
      : mbkautheVar.loginRedirectURL || '/dashboard';

    return res.json({
      success: true,
      username: row.UserName,
      fullName,
      redirect: safeRedirect
    });
  } catch (err) {
    console.error('[mbkauthe] Error during session switch:', err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

// Logout all remembered accounts on this device and clear session
router.post("/api/logout-all", LoginLimit, async (req, res) => {
  try {
    const storedAccounts = readAccountListFromCookie(req);
    const sessionIds = storedAccounts.map(a => a.sessionId).filter(Boolean);
    const currentSessionId = req.session?.user?.sessionId;
    if (currentSessionId) sessionIds.push(currentSessionId);

    if (sessionIds.length) {
      await dblogin.query({
        name: 'logout-all-app-sessions',
        text: 'DELETE FROM "Sessions" WHERE id = ANY($1)',
        values: [sessionIds]
      });
    }

    if (req.sessionID) {
      await dblogin.query({ name: 'logout-all-delete-session', text: 'DELETE FROM "session" WHERE sid = $1', values: [req.sessionID] });
    }

    clearAccountListCookie(res);
    clearSessionCookies(res);

    req.session.destroy(() => { });

    return res.json({ success: true, message: 'All accounts logged out' });
  } catch (err) {
    console.error('[mbkauthe] Error during logout-all:', err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

// GET /mbkauthe/login
router.get("/login", LoginLimit, csrfProtection, (req, res) => {
  return res.render("loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: mbkautheVar.GITHUB_LOGIN_ENABLED,
    googleLoginEnabled: mbkautheVar.GOOGLE_LOGIN_ENABLED,
    customURL: mbkautheVar.loginRedirectURL || '/dashboard',
    userLoggedIn: !!req.session?.user,
    username: req.session?.user?.username || '',
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME.toLowerCase(),
    csrfToken: req.csrfToken(),
  });
});

// Dedicated account switch page (lists remembered accounts and allows switching)
router.get("/accounts", LoginLimit, csrfProtection, (req, res) => {
  const redirectFromQuery = typeof req.query.redirect === 'string' ? req.query.redirect : null;
  const safeRedirect = redirectFromQuery && redirectFromQuery.startsWith('/') && !redirectFromQuery.startsWith('//')
    ? redirectFromQuery
    : (mbkautheVar.loginRedirectURL || '/dashboard');

  return res.render("accountSwitch.handlebars", {
    layout: false,
    customURL: safeRedirect,
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME.toLowerCase(),
    csrfToken: req.csrfToken(),
    userLoggedIn: !!req.session?.user,
    username: req.session?.user?.username,
    fullname: req.session?.user?.fullname,
    role: req.session?.user?.role,
  });
});

export default router;