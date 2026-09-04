import express from "express";
import csurf from "csurf";
import speakeasy from "speakeasy";
import rateLimit from 'express-rate-limit';
import { dblogin, dialect } from "#pool.js";
import { mbkautheVar, packageJson, verifyPassword } from "#config.js";
import {
  cachedCookieOptions, cachedClearCookieOptions, clearSessionCookies,
  generateDeviceToken, getDeviceTokenCookieOptions, DEVICE_TRUST_DURATION_MS, hashDeviceToken,
  upsertAccountListCookie, readAccountListFromCookie, removeAccountFromCookie, clearAccountListCookie,
  encryptSessionId, getCookieDomain
} from "#cookies.js";
import { ErrorCodes, createErrorResponse, logError } from "../utils/errors.js";
import { AuthRepository } from "../db/AuthRepository.js";
import { createLogger } from "../utils/logger.js";

const router = express.Router();
const authRepo = new AuthRepository({ db: dblogin, dialect });
const logAuth = createLogger("auth");
const csrfProtection = csurf({ cookie: true });
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (val) => typeof val === 'string' && UUID_REGEX.test(val);

function clearProfilePicCache(req, username) {
  if (!req?.res || !username) return;
  if (req.cookies?.profileImageUser && req.cookies.profileImageUser !== username) return;
  req.res.clearCookie('profileImageUrl', cachedClearCookieOptions);
  req.res.clearCookie('profileImageUser', cachedClearCookieOptions);
}

const LoginLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => Boolean(req.session?.user),
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const LogoutLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many logout attempts, please try again later" },
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const TwoFALimit = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { success: false, message: "Too many 2FA attempts, please try again later" },
  validate: { trustProxy: false, xForwardedForHeader: false }
});

async function fetchActiveSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') return null;
  const row = await authRepo.fetchActiveSession(sessionId);
  if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) return null;
  if (row.Role !== 'SuperAdmin') {
    const allowed = row.AllowedApps;
    if (!Array.isArray(allowed) || !allowed.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) return null;
  }
  return row;
}

async function invalidateDbSession(sessionId) {
  if (!isUuid(sessionId)) return;
  try {
    await authRepo.deleteAppSessionById(sessionId);
  } catch (err) {
    console.error(`[mbkauthe] Error invalidating session:`, err);
  }
}

export async function checkTrustedDevice(req, username) {
  const deviceToken = req.cookies.device_token;
  if (!deviceToken || typeof deviceToken !== 'string') return null;

  try {
    const deviceUser = await authRepo.touchTrustedDevice(hashDeviceToken(deviceToken), username);
    if (!deviceUser || !deviceUser.Active) return null;

    if (deviceUser.Role !== "SuperAdmin") {
      const allowed = deviceUser.AllowedApps;
      if (!Array.isArray(allowed) || !allowed.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        console.warn(`[mbkauthe] Trusted device check: User "${username}" is not authorized to use the application "${mbkautheVar.APP_NAME}"`);
        return null;
      }
    }

    logAuth(`Trusted device validated for user: ${username}`);
    return {
      userId: deviceUser.UserId || undefined,
      username,
      role: deviceUser.Role,
      allowedApps: deviceUser.AllowedApps,
    };
  } catch (deviceErr) {
    console.error(`[mbkauthe] Error checking trusted device:`, deviceErr);
    return null;
  }
}

export async function completeLoginProcess(req, res, user, redirectUrl = null, trustDevice = false, method = null) {
  try {
    const username = user.username || user.UserName;
    if (!username) throw new Error('Username is required in user object');

    await authRepo.deleteSessionBySid(req.sessionID);
    await new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));

    const configuredMax = parseInt(mbkautheVar.MAX_SESSIONS_PER_USER, 10);
    const MAX_SESSIONS = Number.isInteger(configuredMax) && configuredMax > 0 ? configuredMax : 5;

    let dbSessionId;
    await authRepo.withTransaction(async (txRepo) => {
      await txRepo.advisoryTransactionLock(`sessions:${username}`, "lock-user-sessions");
      const currentSessions = await txRepo.cleanupAndCountUserSessions(username);
      if (currentSessions >= MAX_SESSIONS) {
        const sessionsToDelete = currentSessions - MAX_SESSIONS + 1;
        logAuth(`User "${username}" has ${currentSessions} active sessions, exceeding max of ${MAX_SESSIONS}. Deleting ${sessionsToDelete} oldest sessions.`);
        await txRepo.deleteOldestSessionsForUser(username, sessionsToDelete, "prune-oldest-user-session");
      }

      const expiresAt = new Date(Date.now() + (cachedCookieOptions.maxAge || 0));
      const inserted = await txRepo.insertAppSession(username, expiresAt, JSON.stringify({ ip: req.ip, ua: req.headers['user-agent'] || null }));
      if (!inserted?.id) throw new Error('Failed to insert app session');
      dbSessionId = inserted.id;
    });

    let profileRow = null;
    try {
      profileRow = await authRepo.updateLastLoginReturnProfile(username);
    } catch (profileUpdateErr) {
      console.error(`[mbkauthe] Error updating last_login/returning profile:`, profileUpdateErr);
    }

    req.session.user = {
      userId: user.userId || user.UserId || undefined,
      username,
      role: user.role || user.Role,
      sessionId: dbSessionId,
      allowedApps: user.allowedApps || user.AllowedApps,
    };

    clearProfilePicCache(req, username);

    let loginProfileImage = null;
    if (profileRow) {
      if (profileRow.FullName) req.session.user.fullname = profileRow.FullName;
      if (profileRow.Image?.trim()) loginProfileImage = profileRow.Image;
    } else {
      try {
        const profileResult = await authRepo.getUserProfileByUsername(username);
        if (profileResult?.FullName) req.session.user.fullname = profileResult.FullName;
        if (profileResult?.Image?.trim()) loginProfileImage = profileResult.Image;
      } catch (profileErr) {
        console.error(`[mbkauthe] Error fetching FullName/Image for user:`, profileErr);
      }
    }

    if (req.session.preAuthUser) delete req.session.preAuthUser;

    req.session.save(async (err) => {
      if (err) {
        console.error(`[mbkauthe] Session save error:`, err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      const encryptedSessionId = encryptSessionId(dbSessionId);
      if (encryptedSessionId) res.cookie("sessionId", encryptedSessionId, cachedCookieOptions);

      res.cookie("fullName", req.session.user.fullname || username, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUrl', loginProfileImage?.trim() ? loginProfileImage : 'default', { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });

      if (typeof method === 'string') {
        try { res.cookie('lastLoginMethod', method, { ...cachedCookieOptions, httpOnly: false }); } catch {}
      }

      upsertAccountListCookie(req, res, {
        sessionId: dbSessionId,
        username,
        fullName: req.session.user.fullname || username,
        image: loginProfileImage || null
      });

      if (trustDevice) {
        try {
          const deviceToken = generateDeviceToken();
          await authRepo.insertTrustedDevice({
            username,
            deviceTokenHash: hashDeviceToken(deviceToken),
            deviceName: req.headers['user-agent'] ? req.headers['user-agent'].substring(0, 255) : 'Unknown Device',
            userAgent: req.headers['user-agent'] || 'Unknown',
            ipAddress: req.ip || req.connection?.remoteAddress || 'Unknown',
            expiresAt: new Date(Date.now() + DEVICE_TRUST_DURATION_MS)
          });
          res.cookie("device_token", deviceToken, getDeviceTokenCookieOptions());
          logAuth(`Trusted device token created for user: ${username}`);
        } catch (deviceErr) {
          console.error(`[mbkauthe] Error creating trusted device:`, deviceErr);
        }
      }

      logAuth(`User "${username}" logged in successfully (last_login updated)`);

      const responsePayload = { success: true, message: "Login successful" };
      if (redirectUrl) responsePayload.redirectUrl = redirectUrl;
      res.status(200).json(responsePayload);
    });
  } catch (err) {
    console.error(`[mbkauthe] Error during login completion:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

router.post("/api/login", LoginLimit, async (req, res) => {
  logAuth(`Login request received`);
  const { username, password, redirect } = req.body || {};

  if (!username || !password) {
    logError('Login attempt', ErrorCodes.MISSING_REQUIRED_FIELD, { username: username || 'missing' });
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "Username and password are required" }));
  }

  if (typeof username !== 'string' || username.trim().length === 0 || username.length > 255) {
    logError('Login attempt', ErrorCodes.INVALID_USERNAME_FORMAT, { username });
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_USERNAME_FORMAT));
  }

  if (typeof password !== 'string' || password.length < 8 || password.length > 255) {
    logError('Login attempt', ErrorCodes.INVALID_PASSWORD_LENGTH, { username: username.trim() });
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_PASSWORD_LENGTH));
  }

  const trimmedUsername = username.trim();
  logAuth(`Login attempt for username: ${trimmedUsername}`);

  try {
    const user = await authRepo.getUserWithTwoFA(trimmedUsername);
    if (!user) {
      logError('Login attempt', ErrorCodes.USER_NOT_FOUND, { username: trimmedUsername });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.INVALID_CREDENTIALS));
    }

    const passwordMatches = user.PasswordEnc ? await verifyPassword(password, user.UserName, user.PasswordEnc) : false;
    if (!passwordMatches) {
      logError('Login attempt', ErrorCodes.INCORRECT_PASSWORD, { username: trimmedUsername });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.INCORRECT_PASSWORD));
    }

    if (!user.Active) {
      logError('Login attempt', ErrorCodes.ACCOUNT_INACTIVE, { username: trimmedUsername });
      return res.status(403).json(createErrorResponse(403, ErrorCodes.ACCOUNT_INACTIVE));
    }

    if (user.Role !== "SuperAdmin") {
      const allowed = user.AllowedApps;
      if (!Array.isArray(allowed) || !allowed.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        logError('Login attempt', ErrorCodes.APP_NOT_AUTHORIZED, { username: user.UserName, app: mbkautheVar.APP_NAME });
        return res.status(403).json(createErrorResponse(403, ErrorCodes.APP_NOT_AUTHORIZED, {
          message: `You are not authorized to access ${mbkautheVar.APP_NAME}`,
          app: mbkautheVar.APP_NAME
        }));
      }
    }

    const is2faEnabled = String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && user.TwoFAStatus;
    const requestedRedirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : null;
    const userForSession = { userId: user.UserId || undefined, username: user.UserName, role: user.Role, allowedApps: user.AllowedApps };

    const trustedDeviceUser = await checkTrustedDevice(req, trimmedUsername);
    if (trustedDeviceUser && is2faEnabled) {
      logAuth(`Trusted device login for user: ${trimmedUsername}, skipping 2FA only`);
      return completeLoginProcess(req, res, userForSession, requestedRedirect, false, 'password');
    }

    if (is2faEnabled) {
      req.session.preAuthUser = { ...userForSession, redirectUrl: requestedRedirect };
      logAuth(`2FA required for user: ${trimmedUsername}`);
      return res.json({ success: true, twoFactorRequired: true, redirectUrl: requestedRedirect });
    }

    return completeLoginProcess(req, res, userForSession, requestedRedirect, false, 'password');
  } catch (err) {
    console.error(`[mbkauthe] Error during login process:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get("/2fa", csrfProtection, (req, res) => {
  if (!req.session.preAuthUser) return res.redirect("/mbkauthe/login");

  let redirectToUse = req.query?.redirect || req.session.preAuthUser.redirectUrl || mbkautheVar.loginRedirectURL || '/dashboard';
  if (!(typeof redirectToUse === 'string' && redirectToUse.startsWith('/') && !redirectToUse.startsWith('//'))) {
    redirectToUse = mbkautheVar.loginRedirectURL || '/dashboard';
  }

  res.render("pages/2fa.handlebars", {
    layout: false,
    customURL: redirectToUse,
    csrfToken: req.csrfToken(),
    appName: mbkautheVar.APP_NAME,
    version: packageJson.version,
    DEVICE_TRUST_DURATION_DAYS: mbkautheVar.DEVICE_TRUST_DURATION_DAYS
  });
});

router.post("/api/verify-2fa", TwoFALimit, csrfProtection, async (req, res) => {
  if (!req.session.preAuthUser) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Please log in first" }));
  }

  const { token, trustDevice } = req.body || {};
  const { username, role, userId, allowedApps } = req.session.preAuthUser;

  if (!token || typeof token !== 'string') {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "2FA token is required" }));
  }

  const sanitizedToken = token.trim();
  if (!/^\d{6}$/.test(sanitizedToken)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT));
  }

  try {
    const twoFARecord = await authRepo.getTwoFASecret(username);
    if (!twoFARecord?.TwoFASecret) {
      return res.status(500).json(createErrorResponse(500, ErrorCodes.TWO_FA_NOT_CONFIGURED));
    }

    const tokenValidates = speakeasy.totp.verify({
      secret: twoFARecord.TwoFASecret,
      encoding: "base32",
      token: sanitizedToken,
      window: 1,
    });

    if (!tokenValidates) {
      logError('2FA verification', ErrorCodes.TWO_FA_INVALID_TOKEN, { username });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.TWO_FA_INVALID_TOKEN));
    }

    let redirectFromSession = req.session.preAuthUser.redirectUrl;
    if (!(typeof redirectFromSession === 'string' && redirectFromSession.startsWith('/') && !redirectFromSession.startsWith('//'))) {
      redirectFromSession = null;
    }
    const redirectUrl = redirectFromSession || mbkautheVar.loginRedirectURL || '/dashboard';
    const methodToUse = req.session.preAuthUser.loginMethod || 'password';

    delete req.session.preAuthUser;
    await completeLoginProcess(req, res, { userId, username, role, allowedApps }, redirectUrl, trustDevice === true || trustDevice === 'true', methodToUse);
  } catch (err) {
    console.error(`[mbkauthe] Error during 2FA verification:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/api/logout", LogoutLimit, async (req, res) => {
  if (!req.session.user) return res.status(400).json({ success: false, message: "Not logged in" });

  try {
    const { username, sessionId } = req.session.user;
    clearProfilePicCache(req, username);

    const operations = [];
    if (sessionId) operations.push(authRepo.deleteAppSessionById(sessionId, "logout-delete-app-session"));
    if (req.sessionID) operations.push(authRepo.deleteSessionBySid(req.sessionID, "logout-delete-session"));
    await Promise.all(operations);

    if (sessionId) removeAccountFromCookie(req, res, sessionId);

    req.session.destroy((err) => {
      if (err) {
        console.error(`[mbkauthe] Error destroying session:`, err);
        return res.status(500).json({ success: false, message: "Logout failed" });
      }
      clearSessionCookies(res);
      logAuth(`User "${username}" logged out successfully`);
      res.status(200).json({ success: true, message: "Logout successful" });
    });
  } catch (err) {
    console.error(`[mbkauthe] Database query error during logout:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get("/api/account-sessions", LoginLimit, async (req, res) => {
  const storedAccounts = readAccountListFromCookie(req);
  const currentSessionId = req.session?.user?.sessionId || null;
  if (!storedAccounts.length) return res.json({ accounts: [], currentSessionId });

  const validAccountEntries = storedAccounts.filter((acct) => {
    if (!isUuid(acct.sessionId)) {
      removeAccountFromCookie(req, res, acct.sessionId);
      return false;
    }
    return true;
  });

  try {
    const sessionRows = await authRepo.getSessionsWithUsersByIds(validAccountEntries.map((a) => a.sessionId), "multi-session-fetch-many");
    const sessionMap = new Map(sessionRows.map((row) => [row.sid, row]));
    const validated = [];

    for (const acct of validAccountEntries) {
      const row = sessionMap.get(acct.sessionId);
      const expired = row?.expires_at && new Date(row.expires_at) <= new Date();
      const authorized = Boolean(row?.Active && (
        row.Role === "SuperAdmin" ||
        (Array.isArray(row.AllowedApps) && row.AllowedApps.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME))
      ));

      if (!row || expired || !authorized) {
        await invalidateDbSession(acct.sessionId);
        removeAccountFromCookie(req, res, acct.sessionId);
        continue;
      }

      validated.push({
        sessionId: row.sid,
        username: row.UserName,
        fullName: acct.fullName || row.FullName || acct.username || row.UserName,
        image: acct.image || (row.Image?.trim() ? row.Image : null),
        isCurrent: Boolean(currentSessionId && row.sid === currentSessionId)
      });
    }

    return res.json({ accounts: validated, currentSessionId });
  } catch (err) {
    console.error(`[mbkauthe] Error validating remembered accounts:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post("/api/switch-session", LoginLimit, async (req, res) => {
  const { sessionId, redirect } = req.body || {};

  if (!isUuid(sessionId)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT, { message: 'Invalid session id' }));
  }

  const storedAccounts = readAccountListFromCookie(req);
  if (!storedAccounts.some((a) => a.sessionId === sessionId)) {
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
    const switchProfileImage = row.Image?.trim() ? row.Image : null;

    await new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));

    req.session.user = {
      userId: row.UserId || undefined,
      username: row.UserName,
      role: row.Role,
      sessionId: row.sid,
      allowedApps: row.AllowedApps,
      fullname: fullName
    };

    clearProfilePicCache(req, row.UserName);
    await new Promise((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));

    res.cookie('fullName', fullName, { ...cachedCookieOptions, httpOnly: false });
    res.cookie('profileImageUrl', switchProfileImage || 'default', { ...cachedCookieOptions, httpOnly: false });
    res.cookie('profileImageUser', row.UserName, { ...cachedCookieOptions, httpOnly: false });
    const encryptedSid = encryptSessionId(row.sid);
    if (encryptedSid) res.cookie('sessionId', encryptedSid, cachedCookieOptions);

    upsertAccountListCookie(req, res, { sessionId: row.sid, username: row.UserName, fullName, image: switchProfileImage });

    const safeRedirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')
      ? redirect
      : mbkautheVar.loginRedirectURL || '/dashboard';

    return res.json({ success: true, username: row.UserName, fullName, redirect: safeRedirect });
  } catch (err) {
    console.error(`[mbkauthe] Error during session switch:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post("/api/logout-all", LoginLimit, async (req, res) => {
  try {
    const sessionIds = readAccountListFromCookie(req).map((a) => a.sessionId).filter(Boolean);
    if (req.session?.user?.sessionId) sessionIds.push(req.session.user.sessionId);

    if (sessionIds.length) await authRepo.deleteSessionsByIds(sessionIds, "logout-all-app-sessions");
    if (req.sessionID) await authRepo.deleteSessionBySid(req.sessionID, "logout-all-delete-session");

    clearAccountListCookie(res);
    clearSessionCookies(res);
    req.session.destroy(() => {});

    return res.json({ success: true, message: 'All accounts logged out' });
  } catch (err) {
    console.error(`[mbkauthe] Error during logout-all:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.get("/login", LoginLimit, csrfProtection, (req, res) => {
  const lastLogin = typeof req.cookies?.lastLoginMethod === 'string' ? req.cookies.lastLoginMethod : null;
  return res.render("pages/loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: mbkautheVar.GITHUB_LOGIN_ENABLED,
    googleLoginEnabled: mbkautheVar.GOOGLE_LOGIN_ENABLED,
    customURL: mbkautheVar.loginRedirectURL || '/dashboard',
    cookieDomain: getCookieDomain() || '',
    userLoggedIn: Boolean(req.session?.user),
    username: req.session?.user?.username || '',
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME,
    csrfToken: req.csrfToken(),
    lastLoginMethod: lastLogin,
    lastLoginPassword: lastLogin === 'password',
    lastLoginGithub: lastLogin === 'github',
    lastLoginGoogle: lastLogin === 'google',
    showLoggedOutMessage: req.query.reason === 'logged_out',
    redirectTarget: req.query.redirect || null
  });
});

router.get("/accounts", LoginLimit, csrfProtection, (req, res) => {
  const redirectFromQuery = typeof req.query.redirect === 'string' ? req.query.redirect : null;
  const safeRedirect = redirectFromQuery && redirectFromQuery.startsWith('/') && !redirectFromQuery.startsWith('//')
    ? redirectFromQuery
    : mbkautheVar.loginRedirectURL || '/dashboard';

  return res.render("pages/accountSwitch.handlebars", {
    layout: false,
    customURL: safeRedirect,
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME,
    csrfToken: req.csrfToken(),
    userLoggedIn: Boolean(req.session?.user),
    username: req.session?.user?.username,
    fullname: req.session?.user?.fullname,
    role: req.session?.user?.role,
  });
});

export default router;