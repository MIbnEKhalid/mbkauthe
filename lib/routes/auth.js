import express from "express";
import csurf from "csurf";
import speakeasy from "speakeasy";
import rateLimit from 'express-rate-limit';
import { dblogin, dialect } from "#pool.js";
import { mbkautheVar, packageJson, verifyPassword } from "#config.js";
import { cachedCookieOptions, cachedClearCookieOptions, clearSessionCookies, generateDeviceToken, getDeviceTokenCookieOptions, DEVICE_TRUST_DURATION_MS, hashDeviceToken, upsertAccountListCookie, readAccountListFromCookie, removeAccountFromCookie, clearAccountListCookie, encryptSessionId, getCookieDomain } from "#cookies.js";
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
  if (req.cookies?.profile_image_user && req.cookies.profile_image_user !== username) return;
  req.res.clearCookie('profile_image_url', cachedClearCookieOptions);
  req.res.clearCookie('profile_image_user', cachedClearCookieOptions);
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

async function fetchActiveSession(session_id) {
  if (!session_id || typeof session_id !== 'string') return null;
  const row = await authRepo.fetchActiveSession(session_id);
  if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.is_active) return null;
  if (row.role !== 'superadmin') {
    const allowed = row.allowed_apps;
    if (!Array.isArray(allowed) || !allowed.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) return null;
  }
  return row;
}

async function invalidateDbSession(session_id) {
  if (!isUuid(session_id)) return;
  try {
    await authRepo.deleteAppSessionById(session_id);
  } catch (err) {
    console.error(`[mbkauthe] Error invalidating session:`, err);
  }
}

export async function checkTrustedDevice(req, username) {
  const device_token = req.cookies.device_token;
  if (!device_token || typeof device_token !== 'string') return null;

  try {
    const deviceUser = await authRepo.touchTrustedDevice(hashDeviceToken(device_token), username);
    if (!deviceUser || !deviceUser.is_active) return null;

    if (deviceUser.role !== "superadmin") {
      const allowed = deviceUser.allowed_apps;
      if (!Array.isArray(allowed) || !allowed.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        console.warn(`[mbkauthe] Trusted device check: User "${username}" is not authorized to use the application "${mbkautheVar.APP_NAME}"`);
        return null;
      }
    }

    logAuth(`Trusted device validated for user: ${username}`);
    return {
      user_id: deviceUser.user_id || undefined,
      username,
      role: deviceUser.role,
      allowed_apps: deviceUser.allowed_apps,
    };
  } catch (deviceErr) {
    console.error(`[mbkauthe] Error checking trusted device:`, deviceErr);
    return null;
  }
}

export async function completeLoginProcess(req, res, user, redirect_url = null, trust_device = false, method = null) {
  try {
    const username = user.username;
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
      session_id: dbSessionId,
      user_id: user.user_id || undefined,
      username,
      full_name: username,
      role: user.role,
      allowed_apps: user.allowed_apps,
    };

    clearProfilePicCache(req, username);

    let loginProfileImage = null;
    if (profileRow) {
      const fullName = profileRow.full_name;
      const image = profileRow.image;
      if (fullName) req.session.user.full_name = fullName;
      if (image?.trim()) loginProfileImage = image;
    } else {
      try {
        const profileResult = await authRepo.getUserProfileByUsername(username);
        const fullName = profileResult?.full_name;
        const image = profileResult?.image;
        if (fullName) req.session.user.full_name = fullName;
        if (image?.trim()) loginProfileImage = image;
      } catch (profileErr) {
        console.error(`[mbkauthe] Error fetching FullName/Image for user:`, profileErr);
      }
    }

    if (req.session.pre_auth_user) delete req.session.pre_auth_user;

    req.session.save(async (saveErr) => {
      if (saveErr) {
        console.error(`[mbkauthe] Session save error:`, saveErr);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      const encryptedSessionId = encryptSessionId(dbSessionId);
      if (encryptedSessionId) res.cookie("session_id", encryptedSessionId, cachedCookieOptions);

      res.cookie("full_name", req.session.user.full_name || username, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profile_image_url', loginProfileImage?.trim() ? loginProfileImage : 'default', { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profile_image_user', username, { ...cachedCookieOptions, httpOnly: false });

      if (typeof method === 'string') {
        try { res.cookie('last_login_method', method, { ...cachedCookieOptions, httpOnly: false }); } catch {}
      }

      upsertAccountListCookie(req, res, {
        session_id: dbSessionId,
        username,
        full_name: req.session.user.full_name || username,
        image: loginProfileImage || null
      });

      req.session.pre_auth_user = null;

      try {
        await authRepo.touchUserLastLogin(username);
      } catch (lastLoginErr) {
        console.error(`[mbkauthe] Error updating last_login:`, lastLoginErr);
      }

      if (trust_device) {
        try {
          const deviceToken = generateDeviceToken();
          await authRepo.insertTrustedDevice({
            username,
            device_token_hash: hashDeviceToken(deviceToken),
            device_name: req.headers['user-agent'] ? req.headers['user-agent'].substring(0, 255) : 'Unknown Device',
            user_agent: req.headers['user-agent'] || 'Unknown',
            ip_address: req.ip || req.connection?.remoteAddress || 'Unknown',
            expires_at: new Date(Date.now() + DEVICE_TRUST_DURATION_MS)
          });
          res.cookie("device_token", deviceToken, getDeviceTokenCookieOptions());
          logAuth(`Trusted device token created for user: ${username}`);
        } catch (deviceErr) {
          console.error(`[mbkauthe] Error creating trusted device:`, deviceErr);
        }
      }

      logAuth(`User "${username}" logged in successfully (last_login updated)`);

      const responsePayload = { success: true, message: "Login successful" };
      if (redirect_url) responsePayload.redirect_url = redirect_url;
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

    const password_hash = user.password_hash;
    const auth_username = user.username;
    const password_matches = password_hash ? await verifyPassword(password, auth_username, password_hash) : false;

    if (!password_matches) {
      logError('Login attempt', ErrorCodes.INCORRECT_PASSWORD, { username: trimmedUsername });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.INCORRECT_PASSWORD));
    }

    const is_active = user.is_active;
    if (!is_active) {
      logError('Login attempt', ErrorCodes.ACCOUNT_INACTIVE, { username: trimmedUsername });
      return res.status(403).json(createErrorResponse(403, ErrorCodes.ACCOUNT_INACTIVE));
    }

    const role = user.role;
    const allowed_apps = user.allowed_apps;
    if (role !== "superadmin") {
      if (!Array.isArray(allowed_apps) || !allowed_apps.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME)) {
        logError('Login attempt', ErrorCodes.APP_NOT_AUTHORIZED, { username: auth_username, app: mbkautheVar.APP_NAME });
        return res.status(403).json(createErrorResponse(403, ErrorCodes.APP_NOT_AUTHORIZED, {
          message: `You are not authorized to access ${mbkautheVar.APP_NAME}`,
          app: mbkautheVar.APP_NAME
        }));
      }
    }

    const is_2fa_enabled = String(mbkautheVar.MBKAUTH_TWO_FA_ENABLE || "").toLowerCase() === "true" && Boolean(user.is_enabled);
    const requested_redirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : null;
    const user_for_session = { user_id: user.user_id || undefined, username: auth_username, role, allowed_apps };

    const trustedDeviceUser = await checkTrustedDevice(req, trimmedUsername);
    if (trustedDeviceUser && is_2fa_enabled) {
      logAuth(`Trusted device login for user: ${trimmedUsername}, skipping 2FA only`);
      return completeLoginProcess(req, res, user_for_session, requested_redirect, false, 'password');
    }

    if (is_2fa_enabled) {
      req.session.pre_auth_user = { ...user_for_session, redirect_url: requested_redirect };
      logAuth(`2FA required for user: ${trimmedUsername}`);
      return res.json({ success: true, two_factor_required: true, redirect_url: requested_redirect });
    }

    return completeLoginProcess(req, res, user_for_session, requested_redirect, false, 'password');
  } catch (err) {
    console.error(`[mbkauthe] Error during login process:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get("/2fa", csrfProtection, (req, res) => {
  if (!req.session.pre_auth_user) return res.redirect("/mbkauthe/login");

  let redirectToUse = req.query?.redirect || req.session.pre_auth_user.redirect_url || mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';
  if (!(typeof redirectToUse === 'string' && redirectToUse.startsWith('/') && !redirectToUse.startsWith('//'))) {
    redirectToUse = mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';
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
  if (!req.session.pre_auth_user) {
    return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_NOT_FOUND, { message: "Please log in first" }));
  }

  const { token, trust_device } = req.body || {};
  const { username, role, user_id, allowed_apps } = req.session.pre_auth_user;

  if (!token || typeof token !== 'string') {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD, { message: "2FA token is required" }));
  }

  const sanitized_token = token.trim();
  if (!/^\d{6}$/.test(sanitized_token)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT));
  }

  try {
    const two_fa_record = await authRepo.getTwoFASecret(username);
    if (!two_fa_record?.two_fa_secret) {
      return res.status(500).json(createErrorResponse(500, ErrorCodes.TWO_FA_NOT_CONFIGURED));
    }

    const token_validates = speakeasy.totp.verify({
      secret: two_fa_record.two_fa_secret,
      encoding: "base32",
      token: sanitized_token,
      window: 1,
    });

    if (!token_validates) {
      logError('2FA verification', ErrorCodes.TWO_FA_INVALID_TOKEN, { username });
      return res.status(401).json(createErrorResponse(401, ErrorCodes.TWO_FA_INVALID_TOKEN));
    }

    let redirect_from_session = req.session.pre_auth_user.redirect_url;
    if (!(typeof redirect_from_session === 'string' && redirect_from_session.startsWith('/') && !redirect_from_session.startsWith('//'))) {
      redirect_from_session = null;
    }
    const redirect_url = redirect_from_session || mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';
    const method_to_use = req.session.pre_auth_user.login_method || 'password';

    delete req.session.pre_auth_user;
    await completeLoginProcess(req, res, { user_id, username, role, allowed_apps }, redirect_url, trust_device === true || trust_device === 'true', method_to_use);
  } catch (err) {
    console.error(`[mbkauthe] Error during 2FA verification:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/api/logout", LogoutLimit, async (req, res) => {
  if (!req.session.user) return res.status(400).json({ success: false, message: "Not logged in" });

  try {
    const { username, session_id } = req.session.user;
    clearProfilePicCache(req, username);

    const operations = [];
    if (session_id) operations.push(authRepo.deleteAppSessionById(session_id, "logout-delete-app-session"));
    if (req.sessionID) operations.push(authRepo.deleteSessionBySid(req.sessionID, "logout-delete-session"));
    await Promise.all(operations);

    if (session_id) removeAccountFromCookie(req, res, session_id);

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
  const current_session_id = req.session?.user?.session_id || null;
  if (!storedAccounts.length) return res.json({ accounts: [], current_session_id });

  const validAccountEntries = storedAccounts.filter((acct) => {
    const sid = acct.session_id;
    if (!isUuid(sid)) {
      removeAccountFromCookie(req, res, sid);
      return false;
    }
    return true;
  });

  try {
    const sessionRows = await authRepo.getSessionsWithUsersByIds(validAccountEntries.map((a) => a.session_id), "multi-session-fetch-many");
    const sessionMap = new Map(sessionRows.map((row) => [row.sid, row]));
    const validated = [];

    for (const acct of validAccountEntries) {
      const sid = acct.session_id;
      const row = sessionMap.get(sid);
      const expired = row?.expires_at && new Date(row.expires_at) <= new Date();
      const authorized = Boolean(row?.is_active && (
        row.role === "superadmin" ||
        (Array.isArray(row.allowed_apps) && row.allowed_apps.some((app) => app?.toLowerCase() === mbkautheVar.APP_NAME))
      ));

      if (!row || expired || !authorized) {
        await invalidateDbSession(sid);
        removeAccountFromCookie(req, res, sid);
        continue;
      }

      validated.push({
        session_id: row.sid,
        username: row.username,
        full_name: acct.full_name || row.full_name || acct.username || row.username,
        image: acct.image || (row.image?.trim() ? row.image : null),
        is_current: Boolean(current_session_id && row.sid === current_session_id)
      });
    }

    return res.json({ accounts: validated, current_session_id });
  } catch (err) {
    console.error(`[mbkauthe] Error validating remembered accounts:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post("/api/switch-session", LoginLimit, async (req, res) => {
  const { session_id, redirect } = req.body || {};
  const target_session_id = session_id;

  if (!isUuid(target_session_id)) {
    return res.status(400).json(createErrorResponse(400, ErrorCodes.INVALID_TOKEN_FORMAT, { message: 'Invalid session id' }));
  }

  const storedAccounts = readAccountListFromCookie(req);
  if (!storedAccounts.some((a) => a.session_id === target_session_id)) {
    return res.status(403).json(createErrorResponse(403, ErrorCodes.SESSION_NOT_FOUND, { message: 'Account not available on this device' }));
  }

  try {
    const row = await fetchActiveSession(target_session_id);
    if (!row) {
      await invalidateDbSession(target_session_id);
      removeAccountFromCookie(req, res, target_session_id);
      return res.status(401).json(createErrorResponse(401, ErrorCodes.SESSION_EXPIRED));
    }

    const full_name = row.full_name || row.username;
    const switch_profile_image = row.image?.trim() ? row.image : null;

    await new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));

    req.session.user = {
      session_id: row.sid,
      user_id: row.user_id || undefined,
      username: row.username,
      full_name,
      role: row.role,
      allowed_apps: row.allowed_apps,
    };

    clearProfilePicCache(req, row.username);
    await new Promise((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));

    res.cookie('full_name', full_name, { ...cachedCookieOptions, httpOnly: false });
    res.cookie('profile_image_url', switch_profile_image || 'default', { ...cachedCookieOptions, httpOnly: false });
    res.cookie('profile_image_user', row.username, { ...cachedCookieOptions, httpOnly: false });
    const encrypted_sid = encryptSessionId(row.sid);
    if (encrypted_sid) res.cookie('session_id', encrypted_sid, cachedCookieOptions);

    upsertAccountListCookie(req, res, { session_id: row.sid, username: row.username, full_name, image: switch_profile_image });

    const safe_redirect = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')
      ? redirect
      : mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';

    return res.json({ success: true, username: row.username, full_name, redirect: safe_redirect, session_id: row.sid });
  } catch (err) {
    console.error(`[mbkauthe] Error during session switch:`, err);
    return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
  }
});

router.post("/api/logout-all", LoginLimit, async (req, res) => {
  try {
    const session_ids = readAccountListFromCookie(req).map((a) => a.session_id).filter(Boolean);
    if (req.session?.user?.session_id) session_ids.push(req.session.user.session_id);

    if (session_ids.length) await authRepo.deleteSessionsByIds(session_ids, "logout-all-app-sessions");
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
  const lastLogin = typeof req.cookies?.last_login_method === 'string' ? req.cookies.last_login_method : null;
  return res.render("pages/loginmbkauthe.handlebars", {
    layout: false,
    githubLoginEnabled: mbkautheVar.GITHUB_LOGIN_ENABLED,
    googleLoginEnabled: mbkautheVar.GOOGLE_LOGIN_ENABLED,
    customURL: mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard',
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
    : mbkautheVar.LOGIN_REDIRECT_URL || '/dashboard';

  return res.render("pages/accountSwitch.handlebars", {
    layout: false,
    customURL: safeRedirect,
    version: packageJson.version,
    appName: mbkautheVar.APP_NAME,
    csrfToken: req.csrfToken(),
    userLoggedIn: Boolean(req.session?.user),
    username: req.session?.user?.username,
    full_name: req.session?.user?.full_name,
    role: req.session?.user?.role,
  });
});

export default router;

/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */