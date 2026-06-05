import express from "express";
import crypto from "crypto";
import csurf from "csurf";
import speakeasy from "speakeasy";
import rateLimit from 'express-rate-limit';
import { dblogin } from "#pool.js";
import { mbkautheVar } from "#config.js";
import {
  cachedCookieOptions, cachedClearCookieOptions, clearSessionCookies,
  generateDeviceToken, getDeviceTokenCookieOptions, DEVICE_TRUST_DURATION_MS, hashDeviceToken,
  upsertAccountListCookie, readAccountListFromCookie, removeAccountFromCookie, clearAccountListCookie,
  encryptSessionId
} from "#cookies.js";
import { packageJson } from "#config.js";
import { hashPassword } from "#config.js";
import { ErrorCodes, createErrorResponse, logError } from "../utils/errors.js";
import { AuthRepository } from "../db/AuthRepository.js";

const router = express.Router();
const authRepo = new AuthRepository({ db: dblogin });

// Helper function to clear profile picture cache
function clearProfilePicCache(req, username) {
  if (!req || !req.res || !username) return;

  const cookieUsername = req.cookies?.profileImageUser;
  if (cookieUsername && cookieUsername !== username) return;

  req.res.clearCookie('profileImageUrl', cachedClearCookieOptions);
  req.res.clearCookie('profileImageUser', cachedClearCookieOptions);
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
  const row = await authRepo.fetchActiveSession(sessionId);
  if (!row) return null;
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
    await authRepo.deleteAppSessionById(sessionId);
  } catch (err) {
    console.error(`[mbkauthe] Error invalidating session:`, err);
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
    // Single round-trip: validate trusted device AND refresh LastUsed.
    const deviceUser = await authRepo.touchTrustedDevice(deviceTokenHash, username);

    if (deviceUser) {

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

      console.log(`[mbkauthe] Trusted device validated for user: ${username}`);
      return {
        id: deviceUser.id,
        username: username,
        role: deviceUser.Role,
        allowedApps: deviceUser.AllowedApps,
      };
    }
  } catch (deviceErr) {
    console.error(`[mbkauthe] Error checking trusted device:`, deviceErr);
  }

  return null;
}

/**
 * Complete the login process by creating session and cookies
 */
export async function completeLoginProcess(req, res, user, redirectUrl = null, trustDevice = false, method = null) {
  try {
    // Ensure both username formats are available for compatibility
    const username = user.username || user.UserName;
    if (!username) {
      throw new Error('Username is required in user object');
    }

    // Fix session fixation: Delete old session BEFORE regenerating to prevent timing window
    const oldSessionId = req.sessionID;

    // Delete old session first to prevent session fixation attacks
    await authRepo.deleteSessionBySid(oldSessionId);

    // Now regenerate with new session ID (timing window closed)
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Enforce max sessions per user (configurable via mbkautheVar.MAX_SESSIONS_PER_USER)
    // Use a transaction and lock the Sessions table to prevent concurrent logins from exceeding the configured limit.
    const configuredMax = parseInt(mbkautheVar.MAX_SESSIONS_PER_USER, 10);
    const MAX_SESSIONS = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : 5;

    let dbSessionId;
    try {
      await authRepo.withTransaction(async (txRepo) => {
        await txRepo.advisoryTransactionLock(`sessions:${username}`, "lock-user-sessions");
        const currentSessions = await txRepo.cleanupAndCountUserSessions(username);
        if (currentSessions >= MAX_SESSIONS) {
          const sessionsToDelete = currentSessions - MAX_SESSIONS + 1; // +1 to make room for new session
          console.log(`[mbkauthe] User "${username}" has ${currentSessions} active sessions, exceeding max of ${MAX_SESSIONS}. Deleting ${sessionsToDelete} oldest sessions.`);

          await txRepo.deleteOldestSessionsForUser(username, sessionsToDelete, "prune-oldest-user-session");
        }

        const expiresAt = new Date(Date.now() + (cachedCookieOptions.maxAge || 0));
        const insertedSession = await txRepo.insertAppSession(
          username,
          expiresAt,
          JSON.stringify({ ip: req.ip, ua: req.headers['user-agent'] || null })
        );

        if (!insertedSession?.id) {
          throw new Error('Failed to insert app session');
        }

        dbSessionId = insertedSession.id;
      });
    } catch (err) {
      console.error(`[mbkauthe] Error enforcing session limit or inserting app session:`, err);
      throw err;
    }

    // Update last_login and fetch FullName/Image in a single query.
    let profileRow = null;
    try {
      profileRow = await authRepo.updateLastLoginReturnProfile(user.id);
    } catch (profileUpdateErr) {
      console.error(`[mbkauthe] Error updating last_login/returning profile:`, profileUpdateErr);
    }

    req.session.user = {
      id: user.id,
      username: username,
      role: user.role || user.Role,
      sessionId: dbSessionId,
      allowedApps: user.allowedApps || user.AllowedApps,
    };

    // Clear profile picture cache to fetch fresh data
    clearProfilePicCache(req, username);

    // Store FullName/Image in session and cache cookie values.
    let loginProfileImage = null;
    if (profileRow) {
      if (profileRow.FullName) req.session.user.fullname = profileRow.FullName;
      if (typeof profileRow.Image === 'string' && profileRow.Image.trim() !== '') loginProfileImage = profileRow.Image;
    } else {
      // Fallback: try a read query if UPDATE...RETURNING failed unexpectedly.
      try {
        const profileResult = await authRepo.getUserProfileByUsername(username);
        if (profileResult) {
          if (profileResult.FullName) req.session.user.fullname = profileResult.FullName;
          if (profileResult.Image && profileResult.Image.trim() !== '') loginProfileImage = profileResult.Image;
        }
      } catch (profileErr) {
        console.error(`[mbkauthe] Error fetching FullName/Image for user:`, profileErr);
      }
    }

    if (req.session.preAuthUser) {
      delete req.session.preAuthUser;
    }

    req.session.save(async (err) => {
      if (err) {
        console.error(`[mbkauthe] Session save error:`, err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      // Expose DB session id to client
      const encryptedSessionId = encryptSessionId(dbSessionId);
      if (encryptedSessionId) {
        res.cookie("sessionId", encryptedSessionId, cachedCookieOptions);
      }
      // Cache display name client-side to avoid extra DB lookups
      res.cookie("fullName", req.session.user.fullname || username, { ...cachedCookieOptions, httpOnly: false });
      const profileImageForCookie = loginProfileImage && typeof loginProfileImage === 'string' ? loginProfileImage : 'default';
      res.cookie('profileImageUrl', profileImageForCookie, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
      // Record which method was used to login (client-visible badge)
      if (method && typeof method === 'string') {
        try {
          res.cookie('lastLoginMethod', method, { ...cachedCookieOptions, httpOnly: false });
        } catch (err) {
          console.error(`[mbkauthe] Failed to set lastLoginMethod cookie:`, err);
        }
      }

      // Remember this account on the device for quick switching (server-trusted list)
      upsertAccountListCookie(req, res, {
        sessionId: dbSessionId,
        username,
        fullName: req.session.user.fullname || username,
        image: loginProfileImage || null
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
          await authRepo.insertTrustedDevice({
            username,
            deviceTokenHash,
            deviceName,
            userAgent,
            ipAddress,
            expiresAt
          });

          // Send raw token to client as httpOnly cookie only
          res.cookie("device_token", deviceToken, getDeviceTokenCookieOptions());
          console.log(`[mbkauthe] Trusted device token created for user: ${username}`);
        } catch (deviceErr) {
          console.error(`[mbkauthe] Error creating trusted device:`, deviceErr);
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
    console.error(`[mbkauthe] Error during login completion:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

// POST /mbkauthe/api/login
router.post("/api/login", LoginLimit, async (req, res) => {
  console.log(`[mbkauthe] Login request received`);

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
    const user = await authRepo.getUserWithTwoFA(trimmedUsername);

    if (!user) {
      logError('Login attempt', ErrorCodes.USER_NOT_FOUND, { username: trimmedUsername });
      return res.status(401).json(
        createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS)
      );
    }

    // Password verification (hash-only). We never read/compare plaintext passwords.
    let passwordMatches = false;
    if (user.PasswordEnc) {
      const hashedInputPassword = hashPassword(password, user.UserName);
      const stored = Buffer.from(String(user.PasswordEnc), 'utf8');
      const computed = Buffer.from(String(hashedInputPassword), 'utf8');
      passwordMatches = stored.length === computed.length && crypto.timingSafeEqual(stored, computed);
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
      return await completeLoginProcess(req, res, userForSession, requestedRedirect, false, 'password');
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
    await completeLoginProcess(req, res, userForSession, requestedRedirect, false, 'password');

  } catch (err) {
    console.error(`[mbkauthe] Error during login process:`, err);
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

  res.render("pages/2fa.handlebars", {
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
    const twoFARecord = await authRepo.getTwoFASecret(username);

    if (!twoFARecord || !twoFARecord.TwoFASecret) {
      return res.status(500).json(
        createErrorResponse(500, ErrorCodes.TWO_FA_NOT_CONFIGURED)
      );
    }

    const sharedSecret = twoFARecord.TwoFASecret;
    const allowedApps = req.session.preAuthUser?.allowedApps;
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
    // Capture login method from preAuthUser if present (e.g., OAuth path)
    const methodToUse = req.session.preAuthUser && req.session.preAuthUser.loginMethod ? req.session.preAuthUser.loginMethod : 'password';
    // Clear preAuthUser after successful login
    if (req.session.preAuthUser) delete req.session.preAuthUser;
    await completeLoginProcess(req, res, userForSession, redirectUrl, shouldTrustDevice, methodToUse);

  } catch (err) {
    console.error(`[mbkauthe] Error during 2FA verification:`, err);
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
        operations.push(authRepo.deleteAppSessionById(req.session.user.sessionId, "logout-delete-app-session"));
      }

      if (req.sessionID) {
        operations.push(authRepo.deleteSessionBySid(req.sessionID, "logout-delete-session"));
      }

      await Promise.all(operations);

      // Remove this account from the remembered list for the device
      if (req.session?.user?.sessionId) {
        removeAccountFromCookie(req, res, req.session.user.sessionId);
      }

      req.session.destroy((err) => {
        if (err) {
          console.error(`[mbkauthe] Error destroying session:`, err);
          return res.status(500).json({ success: false, message: "Logout failed" });
        }

        clearSessionCookies(res);

        console.log(`[mbkauthe] User "${username}" logged out successfully`);
        res.status(200).json({ success: true, message: "Logout successful" });
      });
    } catch (err) {
      console.error(`[mbkauthe] Database query error during logout:`, err);
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

  const currentSessionId = req.session?.user?.sessionId || null;

  const validAccountEntries = [];
  for (const acct of storedAccounts) {
    if (!isUuid(acct.sessionId)) {
      removeAccountFromCookie(req, res, acct.sessionId);
      continue;
    }
    validAccountEntries.push(acct);
  }

  const sessionIds = validAccountEntries.map((acct) => acct.sessionId);

  try {
    const sessionRows = await authRepo.getSessionsWithUsersByIds(sessionIds, "multi-session-fetch-many");
    const sessionMap = new Map(sessionRows.map((row) => [row.sid, row]));
    const validated = [];

    for (const acct of validAccountEntries) {
      const row = sessionMap.get(acct.sessionId);
      const expired = row?.expires_at && new Date(row.expires_at) <= new Date();
      const authorized = row && row.Active && (
        row.Role === "SuperAdmin" ||
        (Array.isArray(row.AllowedApps) && row.AllowedApps.some(app => app && app.toLowerCase() === mbkautheVar.APP_NAME.toLowerCase()))
      );

      if (!row || expired || !authorized) {
        await invalidateDbSession(acct.sessionId);
        removeAccountFromCookie(req, res, acct.sessionId);
        continue;
      }

      validated.push({
        sessionId: row.sid,
        username: row.UserName,
        fullName: acct.fullName || row.FullName || acct.username || row.UserName,
        image: acct.image || (typeof row.Image === 'string' && row.Image.trim() !== '' ? row.Image : null),
        isCurrent: currentSessionId && row.sid === currentSessionId
      });
    }

    return res.json({ accounts: validated, currentSessionId });
  } catch (err) {
    console.error(`[mbkauthe] Error validating remembered accounts:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

// Switch active session to another remembered account
router.post("/api/switch-session", LoginLimit, async (req, res) => {
  const { sessionId, redirect } = req.body || {};

  if (!isUuid(sessionId)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT, { message: 'Invalid session id' }));
  }

  const storedAccounts = readAccountListFromCookie(req);
  const acct = storedAccounts.find(a => a.sessionId === sessionId);
  if (!acct) {
    return res.status(403).json(createErrorResponse(403, ErrorCodes.SESSION_NOT_FOUND, { message: 'Account not available on this device' }));
  }

  try {
    const row = await fetchActiveSession(sessionId);
    if (!row) {
      await invalidateDbSession(sessionId);
      removeAccountFromCookie(req, res, sessionId);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_EXPIRED));
    }

    const fullName = row.FullName || row.UserName;
    const switchProfileImage = typeof row.Image === 'string' && row.Image.trim() !== '' ? row.Image : null;

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

    // Sync sessionId cookie and remember list
    res.cookie('fullName', fullName, { ...cachedCookieOptions, httpOnly: false });
    const switchProfileForCookie = switchProfileImage && typeof switchProfileImage === 'string' ? switchProfileImage : 'default';
    res.cookie('profileImageUrl', switchProfileForCookie, { ...cachedCookieOptions, httpOnly: false });
    res.cookie('profileImageUser', row.UserName, { ...cachedCookieOptions, httpOnly: false });
    const encryptedSid = encryptSessionId(row.sid);
    if (encryptedSid) {
      res.cookie('sessionId', encryptedSid, cachedCookieOptions);
    }
    upsertAccountListCookie(req, res, { sessionId: row.sid, username: row.UserName, fullName, image: switchProfileImage || null });

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
    console.error(`[mbkauthe] Error during session switch:`, err);
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
      await authRepo.deleteSessionsByIds(sessionIds, "logout-all-app-sessions");
    }

    if (req.sessionID) {
      await authRepo.deleteSessionBySid(req.sessionID, "logout-all-delete-session");
    }

    clearAccountListCookie(res);
    clearSessionCookies(res);

    req.session.destroy(() => { });

    return res.json({ success: true, message: 'All accounts logged out' });
  } catch (err) {
    console.error(`[mbkauthe] Error during logout-all:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

// GET /mbkauthe/login
router.get("/login", LoginLimit, csrfProtection, (req, res) => {
  const lastLogin = req.cookies && typeof req.cookies.lastLoginMethod === 'string' ? req.cookies.lastLoginMethod : null;
  const reason = req.query.reason;
  const redirectTarget = req.query.redirect || null;
  
  return res.render("pages/loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: mbkautheVar.GITHUB_LOGIN_ENABLED,
    googleLoginEnabled: mbkautheVar.GOOGLE_LOGIN_ENABLED,
    customURL: mbkautheVar.loginRedirectURL || '/dashboard',
    userLoggedIn: !!req.session?.user,
    username: req.session?.user?.username || '',
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME.toLowerCase(),
    csrfToken: req.csrfToken(),
    // Last-login method flags for immediate server-side badge rendering
    lastLoginMethod: lastLogin,
    lastLoginPassword: lastLogin === 'password',
    lastLoginGithub: lastLogin === 'github',
    lastLoginGoogle: lastLogin === 'google',
    showLoggedOutMessage: reason === 'logged_out',
    redirectTarget: redirectTarget
  });
});

// Dedicated account switch page (lists remembered accounts and allows switching)
router.get("/accounts", LoginLimit, csrfProtection, (req, res) => {
  const redirectFromQuery = typeof req.query.redirect === 'string' ? req.query.redirect : null;
  const safeRedirect = redirectFromQuery && redirectFromQuery.startsWith('/') && !redirectFromQuery.startsWith('//')
    ? redirectFromQuery
    : (mbkautheVar.loginRedirectURL || '/dashboard');

  return res.render("pages/accountSwitch.handlebars", {
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
