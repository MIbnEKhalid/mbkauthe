import express from "express";
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { mbkautheVar, packageJson, appVersion } from "#config.js";
import { renderError, renderPage } from "#response.js";
import { authenticate, sessVal, sessRole } from "../middleware/auth.js";
import { ErrorCodes, ErrorMessages, createErrorResponse } from "../utils/errors.js";
import { dblogin, dialect } from "#pool.js";
import { clearSessionCookies, decryptSessionId, cachedCookieOptions, getCookieDomain } from "#cookies.js";
import { AuthRepository } from "../db/AuthRepository.js";
import { isSafeFetchUrl } from "../utils/urlSafety.js";
import { createLogger } from "../utils/logger.js";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const router = express.Router();
const authRepo = new AuthRepository({ db: dblogin, dialect });
const logMisc = createLogger("misc");

const PROFILE_IMAGE_CACHE_CONTROL = 'private, max-age=300, stale-while-revalidate=300';
const LATEST_VERSION_CACHE_TTL_MS = 10 * 60 * 1000;
const LATEST_VERSION_FAILURE_CACHE_TTL_MS = 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (val) => typeof val === 'string' && UUID_RE.test(val);

const latestVersionCache = { value: null, expiresAt: 0, pending: null };

function setProfileImageCacheHeaders(res, eTag = null) {
  res.setHeader('Cache-Control', PROFILE_IMAGE_CACHE_CONTROL);
  if (eTag) res.setHeader('ETag', eTag);
}

const LoginLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => Boolean(req.session?.user),
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const AdminOperationLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 3,
  message: { success: false, message: "Too many admin operations, please try again later" },
  validate: { trustProxy: false, xForwardedForHeader: false }
});

let mainJsSource = null;
const getMainJsSource = () => {
  if (mainJsSource === null) {
    mainJsSource = fs.readFileSync(path.join(__dirname, '..', '..', 'public', 'main.js'), 'utf8');
  }
  return mainJsSource;
};

router.get('/main.js', (req, res) => {
  const clientConfig = JSON.stringify({
    cookieDomain: getCookieDomain() || null,
    domain: mbkautheVar.DOMAIN,
    isDeployed: mbkautheVar.IS_DEPLOYED === 'true'
  });
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.type('application/javascript').send(`window.mbkautheConfig=${clientConfig};\n${getMainJsSource()}`);
});

router.get('/main.css', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', '..', 'public', 'main.css'));
});

router.get("/bg.webp", (req, res) => {
  res.setHeader('Content-Type', 'image/webp');
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  fs.createReadStream(path.join(__dirname, "..", "..", "public", "bg.webp"))
    .on('error', () => res.status(404).send('Image not found'))
    .pipe(res);
});

router.get('/user/profilepic', async (req, res) => {
  const serveDefaultIcon = () => {
    res.setHeader('Content-Type', 'image/png');
    if (!res.getHeader('Cache-Control')) setProfileImageCacheHeaders(res);
    fs.createReadStream(path.join(__dirname, "..", "..", "public", "M.png"))
      .on('error', () => res.status(404).send('Icon not found'))
      .pipe(res);
  };

  try {
    if (!req.session?.user?.username) return serveDefaultIcon();

    const username = req.session.user.username;
    let imageUrl = req.cookies?.profileImageUser === username && req.cookies?.profileImageUrl ? req.cookies.profileImageUrl : null;

    if (!imageUrl) {
      const profile = await authRepo.getUserImageByUsername(username, 'get-user-profile-pic');
      imageUrl = profile?.Image?.trim() ? profile.Image : 'default';
      res.cookie('profileImageUrl', imageUrl, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
    }

    const eTag = `"${Buffer.from(username + ':' + imageUrl).toString('base64')}"`;
    setProfileImageCacheHeaders(res, eTag);

    if (req.headers['if-none-match'] === eTag) return res.status(304).end();
    if (imageUrl === 'default') return serveDefaultIcon();

    if (!isSafeFetchUrl(imageUrl)) {
      console.warn(`[mbkauthe] Blocked unsafe profile image URL for user ${username}`);
      res.cookie('profileImageUrl', 'default', { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
      return serveDefaultIcon();
    }

    try {
      const imageResponse = await fetch(imageUrl, { headers: { 'User-Agent': 'mbkauthe/1.0' }, timeout: 5000 });
      if (!imageResponse.ok) {
        res.cookie('profileImageUrl', 'default', { ...cachedCookieOptions, httpOnly: false });
        res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
        return serveDefaultIcon();
      }
      res.setHeader('Content-Type', imageResponse.headers.get('content-type') || 'image/jpeg');
      imageResponse.body.pipe(res);
    } catch {
      res.cookie('profileImageUrl', 'default', { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
      return serveDefaultIcon();
    }
  } catch {
    return serveDefaultIcon();
  }
});

if (process.env.env === 'dev') {
  router.get(['/validate-superadmin'], sessRole("SuperAdmin"), LoginLimit, async (req, res) => {
    try {
      const user = req.session?.user || null;
      return res.json({
        success: true,
        message: 'SuperAdmin access granted',
        user: user ? { userId: user.userId, username: user.username, role: user.role, sessionId: user.sessionId } : null
      });
    } catch (err) {
      return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
    }
  });
}

const buildTestViewData = (req) => {
  const { username, fullname, role, userId, sessionId, allowedApps } = req.session.user;
  const sessionExpiry = req.session.cookie?.expires ? new Date(req.session.cookie.expires).toISOString() : null;
  return {
    username,
    fullname: fullname || 'N/A',
    role,
    userId: userId || 'N/A',
    sessionIdShort: sessionId.slice(0, 8),
    profilePicUrl: encodeURIComponent(username),
    displayName: fullname || username,
    initial: (fullname && fullname[0]) || username[0],
    allowedApps: Array.isArray(allowedApps) ? allowedApps.join(', ') : 'N/A',
    sessionExpiry
  };
};

router.get(['/test', '/'], sessVal, LoginLimit, async (req, res) => {
  return renderPage(req, res, 'pages/test.handlebars', false, buildTestViewData(req));
});

router.get('/test.json', sessVal, LoginLimit, async (req, res) => {
  return res.json(buildTestViewData(req));
});

router.post('/test', sessVal, LoginLimit, async (req, res) => {
  if (req.session?.user) return res.json({ success: true, message: "You are logged in" });
});

router.get('/api/checkSession', LoginLimit, async (req, res) => {
  try {
    if (!req.session?.user?.sessionId) {
      req.session?.destroy?.(() => {});
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const row = await authRepo.getSessionValidity(req.session.user.sessionId, req.sessionID, 'check-session-validity');
    if (!row || (row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
      req.session.destroy(() => {});
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const expirySource = row.expires_at || row.connect_expire || null;
    return res.status(200).json({ sessionValid: true, expiry: expirySource ? new Date(expirySource).toISOString() : null });
  } catch (err) {
    console.error(`[mbkauthe] checkSession error:`, err);
    return res.status(200).json({ sessionValid: false, expiry: null });
  }
});

function normalizeSessionIdFromBody(body = {}) {
  const { sessionId: rawSessionId, isEncrypt, isEncryt } = body;
  if (!rawSessionId) return { sessionId: null, error: 'MISSING' };
  if (!(isEncrypt === true || isEncrypt === 'true' || isEncryt === true || isEncryt === 'true')) {
    return { sessionId: rawSessionId, error: null };
  }

  let toDecrypt = String(rawSessionId);
  try { toDecrypt = decodeURIComponent(toDecrypt); } catch {}
  const decrypted = decryptSessionId(toDecrypt);
  return decrypted && isUuid(decrypted) ? { sessionId: decrypted, error: null } : { sessionId: null, error: 'INVALID' };
}

const isSessionRowValid = (row) => Boolean(row && !((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active));

router.post('/api/checkSession', LoginLimit, async (req, res) => {
  try {
    const { sessionId, error } = normalizeSessionIdFromBody(req.body || {});
    if (error === 'MISSING') return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    if (error === 'INVALID' || !sessionId || !isUuid(sessionId)) return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));

    const row = await authRepo.getSessionValidationRow(sessionId, 'check-session-validity-by-id');
    if (!isSessionRowValid(row)) return res.status(200).json({ sessionValid: false, expiry: null });

    return res.status(200).json({ sessionValid: true, expiry: row.expires_at ? new Date(row.expires_at).toISOString() : null });
  } catch (err) {
    console.error(`[mbkauthe] checkSession (body) error:`, err);
    return res.status(200).json({ sessionValid: false, expiry: null });
  }
});

router.post('/api/verifySession', LoginLimit, async (req, res) => {
  try {
    const { sessionId, error } = normalizeSessionIdFromBody(req.body || {});
    if (error === 'MISSING') return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    if (error === 'INVALID' || !sessionId || !isUuid(sessionId)) return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));

    const row = await authRepo.getSessionValidationRow(sessionId, 'verify-session');
    if (!isSessionRowValid(row)) return res.status(200).json({ valid: false, expiry: null });

    return res.status(200).json({ valid: true, expiry: row.expires_at ? new Date(row.expires_at).toISOString() : null });
  } catch (err) {
    console.error(`[mbkauthe] verifySession error:`, err);
    return res.status(200).json({ valid: false, expiry: null });
  }
});

router.get("/ErrorCode", (req, res) => {
  try {
    const getErrorName = (code) => Object.keys(ErrorCodes).find((key) => ErrorCodes[key] === code) || 'UNKNOWN_ERROR';
    const errorCategories = [
      { name: 'Authentication Errors', icon: '🔑', range: '(600-699)', category: 'authentication', codes: [601, 602, 603, 604, 605] },
      { name: 'Two-Factor Authentication Errors', icon: '📱', range: '(700-799)', category: '2fa', codes: [701, 702, 703, 704] },
      { name: 'Session Management Errors', icon: '🔄', range: '(800-899)', category: 'session', codes: [801, 802, 803] },
      { name: 'Authorization Errors', icon: '🛡️', range: '(900-999)', category: 'authorization', codes: [901, 902] },
      { name: 'Input Validation Errors', icon: '✏️', range: '(1000-1099)', category: 'validation', codes: [1001, 1002, 1003, 1004] },
      { name: 'Rate Limiting Errors', icon: '⏱️', range: '(1100-1199)', category: 'ratelimit', codes: [1101] },
      { name: 'Server Errors', icon: '⚠️', range: '(1200-1299)', category: 'server', codes: [1201, 1202, 1203] },
      { name: 'OAuth Errors', icon: '🔗', range: '(1300-1399)', category: 'oauth', codes: [1301, 1302, 1303] }
    ];

    const categoriesWithErrors = errorCategories
      .map((cat) => ({ ...cat, errors: cat.codes.filter((code) => ErrorMessages[code]).map((code) => ({ code, name: getErrorName(code), ...ErrorMessages[code] })) }))
      .filter((cat) => cat.errors.length > 0);

    return renderPage(req, res, "pages/errorCodes.handlebars", false, {
      pageTitle: 'Error Codes',
      appName: mbkautheVar.APP_NAME,
      errorCategories: categoriesWithErrors
    });
  } catch (err) {
    console.error(`[mbkauthe] Error rendering error codes page:`, err);
    return renderError(res, req, { layout: false, code: 500, error: "Internal Server Error", message: "Could not load error codes page.", pagename: "Error Codes", page: "/mbkauthe/info" });
  }
});

export async function getLatestVersion({ forceRefresh = false } = {}) {
  const now = Date.now();
  if (!forceRefresh && latestVersionCache.expiresAt > now) return latestVersionCache.value;
  if (!forceRefresh && latestVersionCache.pending) return latestVersionCache.pending;

  latestVersionCache.pending = (async () => {
    try {
      const response = await fetch('https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/main/package.json');
      if (!response.ok) {
        latestVersionCache.value = null;
        latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_FAILURE_CACHE_TTL_MS;
        return null;
      }
      const latestPackageJson = await response.json();
      const latestVersion = typeof latestPackageJson.version === 'string' ? latestPackageJson.version : null;
      latestVersionCache.value = latestVersion;
      latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_CACHE_TTL_MS;
      return latestVersion;
    } catch {
      latestVersionCache.value = null;
      latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_FAILURE_CACHE_TTL_MS;
      return null;
    } finally {
      latestVersionCache.pending = null;
    }
  })();

  return latestVersionCache.pending;
}

export async function checkVersion() {
  try {
    const latestVersion = await getLatestVersion();
    const hasValidLatest = typeof latestVersion === 'string' && /^\d+\.\d+\.\d+/.test(latestVersion);
    if (hasValidLatest && latestVersion !== packageJson.version) {
      console.warn(`[mbkauthe] Current version (${packageJson.version}) is outdated. Latest version: ${latestVersion}. Consider updating mbkauthe.`);
    } else if (hasValidLatest) {
      logMisc(`Running latest version (${packageJson.version}).`);
    }
  } catch (error) {
    console.warn(`[mbkauthe] Failed to check for updates: ${error.message}`);
  }
}

const { APP_NAME, DOMAIN, IS_DEPLOYED, loginRedirectURL } = mbkautheVar;
const safe_mbkautheVar = { APP_NAME, DOMAIN, IS_DEPLOYED, loginRedirectURL };

router.get(["/info", "/i"], LoginLimit, async (req, res) => {
  let latestVersion;
  try { latestVersion = await getLatestVersion(); } catch {}
  try {
    renderPage(req, res, "pages/info_mbkauthe.handlebars", false, {
      mbkautheVar: safe_mbkautheVar,
      CurrentVersion: packageJson.version,
      APP_VERSION: appVersion,
      latestVersion
    });
  } catch {
    res.status(500).send(`<html><head><title>Error</title></head><body><h1>Error</h1><p>Failed to fetch version information. Please try again later.</p></body></html>`);
  }
});

router.get(["/info.json", "/i.json"], LoginLimit, async (req, res) => {
  let latestVersion;
  try { latestVersion = await getLatestVersion(); } catch {}
  try {
    res.json({ mbkautheVar: safe_mbkautheVar, CurrentVersion: packageJson.version, APP_VERSION: appVersion, latestVersion });
  } catch {
    res.status(500).json({ success: false, message: "Failed to fetch version information" });
  }
});

router.post("/api/terminateAllSessions", AdminOperationLimit, authenticate(mbkautheVar.Main_SECRET_TOKEN), async (req, res) => {
  try {
    await Promise.all([
      authRepo.deleteAllAppSessions('terminate-all-app-sessions'),
      authRepo.deleteActiveSessionStoreRows('terminate-all-db-sessions')
    ]);

    req.session.destroy((err) => {
      if (err) return res.status(500).json({ success: false, message: "Failed to terminate sessions" });
      clearSessionCookies(res);
      logMisc(`All sessions terminated successfully`);
      res.status(200).json({ success: true, message: "All sessions terminated successfully" });
    });
  } catch (err) {
    console.error(`[mbkauthe] Database query error during session termination:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

export default router;