import express from "express";
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import { mbkautheVar, packageJson, appVersion } from "#config.js";
import { renderError, renderPage } from "#response.js";
import { authenticate, sessVal, sessRole } from "../middleware/auth.js";
import { ErrorCodes, ErrorMessages, createErrorResponse } from "../utils/errors.js";
import { dblogin } from "#pool.js";
import { clearSessionCookies, decryptSessionId, cachedCookieOptions } from "#cookies.js";
import { AuthRepository } from "../db/AuthRepository.js";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";
import dotenv from "dotenv";
import { createLogger } from "../utils/logger.js";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));


const router = express.Router();
const authRepo = new AuthRepository({ db: dblogin });
const logMisc = createLogger("misc");
const PROFILE_IMAGE_CACHE_SECONDS = 300;
const PROFILE_IMAGE_CACHE_CONTROL = `private, max-age=${PROFILE_IMAGE_CACHE_SECONDS}, stale-while-revalidate=${PROFILE_IMAGE_CACHE_SECONDS}`;
const LATEST_VERSION_CACHE_TTL_MS = 10 * 60 * 1000;
const LATEST_VERSION_FAILURE_CACHE_TTL_MS = 60 * 1000;
const latestVersionCache = {
  value: null,
  expiresAt: 0,
  pending: null
};

function setProfileImageCacheHeaders(res, eTag = null) {
  res.setHeader('Cache-Control', PROFILE_IMAGE_CACHE_CONTROL);
  if (eTag) {
    res.setHeader('ETag', eTag);
  }
}

// Rate limiter for info/test routes
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

// Rate limiter for admin operations
const AdminOperationLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 3,
  message: { success: false, message: "Too many admin operations, please try again later" },
  validate: {
    trustProxy: false,
    xForwardedForHeader: false
  }
});

// Static file routes
router.get('/main.js', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', '..', 'public', 'main.js'));
});

router.get('/main.css', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', '..', 'public', 'main.css'));
});

router.get("/bg.webp", (req, res) => {
  const imgPath = path.join(__dirname, "..", "..", "public", "bg.webp");
  res.setHeader('Content-Type', 'image/webp');
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  const stream = fs.createReadStream(imgPath);
  stream.on('error', (err) => {
    console.error(`[mbkauthe] Error streaming bg.webp:`, err);
    res.status(404).send('Image not found');
  });
  stream.pipe(res);
});

// Profile picture route
router.get('/user/profilepic', async (req, res) => {
  // Helper function to serve default icon
  const serveDefaultIcon = () => {
    const iconPath = path.join(__dirname, "..", "..", "public", "M.png");
    res.setHeader('Content-Type', 'image/png');
    if (!res.getHeader('Cache-Control')) {
      setProfileImageCacheHeaders(res);
    }
    const stream = fs.createReadStream(iconPath);
    stream.on('error', (err) => {
      console.error(`[mbkauthe] Error streaming icon.svg:`, err);
      res.status(404).send('Icon not found');
    });
    stream.pipe(res);
  };

  try {
    // Check if user is logged in
    if (!req.session?.user?.username) {
      return serveDefaultIcon();
    }

    const username = req.session.user.username;
    let imageUrl = null;
    const cookieUser = req.cookies?.profileImageUser;
    const cookieImageUrl = req.cookies?.profileImageUrl;
    if (cookieUser === username && typeof cookieImageUrl === 'string' && cookieImageUrl.length > 0) {
      imageUrl = cookieImageUrl;
    }

    // If not in cache, fetch from DB
    if (!imageUrl) {
      const profile = await authRepo.getUserImageByUsername(username, 'get-user-profile-pic');

      if (profile && profile.Image && profile.Image.trim() !== '') {
        imageUrl = profile.Image;
      } else {
        imageUrl = 'default';
      }
      res.cookie('profileImageUrl', imageUrl, { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
    }

    // Generate ETag based on username and image URL
    const eTag = `"${Buffer.from(username + ':' + imageUrl).toString('base64')}"`;

    setProfileImageCacheHeaders(res, eTag);

    // Check for conditional request
    if (req.headers['if-none-match'] === eTag) {
      return res.status(304).end();
    }

    if (imageUrl === 'default') {
      return serveDefaultIcon();
    }

    // Fetch and stream the image
    try {
      const imageResponse = await fetch(imageUrl, {
        headers: {
          'User-Agent': 'mbkauthe/1.0'
        },
        timeout: 5000
      });

      if (!imageResponse.ok) {
        console.warn(`[mbkauthe] Failed to fetch profile pic from ${imageUrl}, status: ${imageResponse.status}`);
        res.cookie('profileImageUrl', 'default', { ...cachedCookieOptions, httpOnly: false });
        res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
        return serveDefaultIcon();
      }

      const contentType = imageResponse.headers.get('content-type') || 'image/jpeg';
      res.setHeader('Content-Type', contentType);

      imageResponse.body.pipe(res);
    } catch (fetchErr) {
      console.error(`[mbkauthe] Error fetching external profile picture:`, fetchErr);
      res.cookie('profileImageUrl', 'default', { ...cachedCookieOptions, httpOnly: false });
      res.cookie('profileImageUser', username, { ...cachedCookieOptions, httpOnly: false });
      return serveDefaultIcon();
    }

  } catch (err) {
    console.error(`[mbkauthe] Error fetching profile picture:`, err);
    return serveDefaultIcon();
  }
});

if (process.env.env === 'dev') {
  // Dev-only diagnostic endpoint to verify SuperAdmin role enforcement
  router.get(['/validate-superadmin'], sessRole("SuperAdmin"), LoginLimit, async (req, res) => {
    try {
      const user = req.session?.user || null;
      return res.json({
        success: true,
        message: 'SuperAdmin access granted',
        user: user ? {
          id: user.id,
          username: user.username,
          role: user.role,
          sessionId: user.sessionId
        } : null
      });
    } catch (err) {
      console.error(`[mbkauthe] debug validate-superadmin error:`, err);
      return res.status(500).json(createErrorResponse(500, ErrorCodes.INTERNAL_SERVER_ERROR));
    }
  });
}

// Test route
router.get(['/test', '/'], sessVal, LoginLimit, async (req, res) => {
  const { username, fullname, role, id, sessionId, allowedApps } = req.session.user;

  const sessionExpiry = req.session.cookie?.expires
    ? new Date(req.session.cookie.expires).toISOString()
    : null;

  return renderPage(req, res, 'pages/test.handlebars', false, {
    username,
    fullname: fullname || 'N/A',
    role,
    id,
    sessionIdShort: sessionId.slice(0, 8),
    profilePicUrl: encodeURIComponent(username),
    displayName: fullname || username,
    initial: (fullname && fullname[0]) || username[0],
    allowedApps: Array.isArray(allowedApps) ? allowedApps.join(', ') : 'N/A',
    sessionExpiry
  });
});

router.post('/test', sessVal, LoginLimit, async (req, res) => {
  if (req.session?.user) {
    return res.json({ success: true, message: "You are logged in" });
  }
});

// API: check current session validity (JSON) — minimal response
router.get('/api/checkSession', LoginLimit, async (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const { id, sessionId } = req.session.user;
    if (!sessionId) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    // Single round-trip: fetch app-session expiry and (if needed) connect-pg-simple expiry.
    const row = await authRepo.getSessionValidity(sessionId, req.sessionID, 'check-session-validity');

    if (!row) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }
    if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    // Determine expiry: prefer application session expiry if present else fallback to connect-pg-simple expiry.
    const expirySource = row.expires_at || row.connect_expire || null;
    const expiry = expirySource ? new Date(expirySource).toISOString() : null;

    return res.status(200).json({ sessionValid: true, expiry });
  } catch (err) {
    console.error(`[mbkauthe] checkSession error:`, err);
    return res.status(200).json({ sessionValid: false, expiry: null });
  }
});

// UUID helper used by session endpoints
const isUuid = (val) => typeof val === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);

function normalizeSessionIdFromBody(body = {}) {
  const { sessionId: rawSessionId, isEncrypt, isEncryt } = body;
  if (!rawSessionId) return { sessionId: null, error: 'MISSING' };

  const encryptedFlag = isEncrypt === true || isEncrypt === 'true' || isEncryt === true || isEncryt === 'true';
  if (!encryptedFlag) return { sessionId: rawSessionId, error: null };

  let toDecrypt = typeof rawSessionId === 'string' ? rawSessionId : String(rawSessionId);
  try {
    // Some clients URL-encode cookie values when posting.
    toDecrypt = decodeURIComponent(toDecrypt);
  } catch (decodeErr) {
    // Ignore decode errors and continue with the original value.
  }

  const decrypted = decryptSessionId(toDecrypt);
  if (!decrypted || !isUuid(decrypted)) {
    return { sessionId: null, error: 'INVALID' };
  }

  return { sessionId: decrypted, error: null };
}

async function getSessionValidationRow(sessionId, queryName = 'check-session-validity-by-id') {
  const row = await authRepo.getSessionValidationRow(sessionId, queryName);
  return row || null;
}

function isSessionRowValid(row) {
  return !((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active);
}

// POST /api/checkSession — accept sessionId in request body { sessionId: "<uuid>" }
router.post('/api/checkSession', LoginLimit, async (req, res) => {
  try {
    const { sessionId, error } = normalizeSessionIdFromBody(req.body || {});
    if (error === 'MISSING') {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    }
    if (error === 'INVALID') {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));
    }

    if (!sessionId) {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    }

    if (!isUuid(sessionId)) {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));
    }

    const row = await getSessionValidationRow(sessionId, 'check-session-validity-by-id');
    if (!row || !isSessionRowValid(row)) {
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const expiry = row.expires_at ? new Date(row.expires_at).toISOString() : null;
    return res.status(200).json({ sessionValid: true, expiry });
  } catch (err) {
    console.error(`[mbkauthe] checkSession (body) error:`, err);
    return res.status(200).json({ sessionValid: false, expiry: null });
  }
});

// POST /api/verifySession — returns details about sessionId provided in body
router.post('/api/verifySession', LoginLimit, async (req, res) => {
  try {
    const { sessionId, error } = normalizeSessionIdFromBody(req.body || {});
    if (error === 'MISSING') {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    }
    if (error === 'INVALID') {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));
    }

    if (!sessionId) {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    }

    if (!isUuid(sessionId)) {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));
    }

    const row = await getSessionValidationRow(sessionId, 'verify-session');
    if (!row || !isSessionRowValid(row)) {
      return res.status(200).json({ valid: false, expiry: null });
    }

    const expiry = row.expires_at ? new Date(row.expires_at).toISOString() : null;
    return res.status(200).json({ valid: true, expiry, username: row.UserName, role: row.Role });
  } catch (err) {
    console.error(`[mbkauthe] verifySession error:`, err);
    return res.status(200).json({ valid: false, expiry: null });
  }
});

// Error codes page
router.get("/ErrorCode", (req, res) => {
  try {
    // Helper function to get error name from ErrorCodes
    const getErrorName = (code) => {
      return Object.keys(ErrorCodes).find(key => ErrorCodes[key] === code) || 'UNKNOWN_ERROR';
    };

    // Dynamically organize errors by category based on code ranges
    const errorCategories = [
      {
        name: 'Authentication Errors',
        icon: '🔑',
        range: '(600-699)',
        category: 'authentication',
        codes: [601, 602, 603, 604, 605]
      },
      {
        name: 'Two-Factor Authentication Errors',
        icon: '📱',
        range: '(700-799)',
        category: '2fa',
        codes: [701, 702, 703, 704]
      },
      {
        name: 'Session Management Errors',
        icon: '🔄',
        range: '(800-899)',
        category: 'session',
        codes: [801, 802, 803]
      },
      {
        name: 'Authorization Errors',
        icon: '🛡️',
        range: '(900-999)',
        category: 'authorization',
        codes: [901, 902]
      },
      {
        name: 'Input Validation Errors',
        icon: '✏️',
        range: '(1000-1099)',
        category: 'validation',
        codes: [1001, 1002, 1003, 1004]
      },
      {
        name: 'Rate Limiting Errors',
        icon: '⏱️',
        range: '(1100-1199)',
        category: 'ratelimit',
        codes: [1101]
      },
      {
        name: 'Server Errors',
        icon: '⚠️',
        range: '(1200-1299)',
        category: 'server',
        codes: [1201, 1202, 1203]
      },
      {
        name: 'OAuth Errors',
        icon: '🔗',
        range: '(1300-1399)',
        category: 'oauth',
        codes: [1301, 1302, 1303]
      }
    ];

    // Build error data from ErrorMessages
    const categoriesWithErrors = errorCategories.map(category => ({
      ...category,
      errors: category.codes
        .filter(code => ErrorMessages[code]) // Only include if message exists
        .map(code => ({
          code,
          name: getErrorName(code),
          ...ErrorMessages[code]
        }))
    })).filter(category => category.errors.length > 0); // Remove empty categories

    return renderPage(req, res, "pages/errorCodes.handlebars", false, {
      pageTitle: 'Error Codes',
      appName: mbkautheVar.APP_NAME,
      errorCategories: categoriesWithErrors
    });
  } catch (err) {
    console.error(`[mbkauthe] Error rendering error codes page:`, err);
    return renderError(res, req, {
      layout: false,
      code: 500,
      error: "Internal Server Error",
      message: "Could not load error codes page.",
      pagename: "Error Codes",
      page: "/mbkauthe/info",
    });
  }
});

// Fetch latest version from GitHub with a short in-memory cache.
export async function getLatestVersion({ forceRefresh = false } = {}) {
  const now = Date.now();

  if (!forceRefresh && latestVersionCache.expiresAt > now) {
    return latestVersionCache.value;
  }

  if (!forceRefresh && latestVersionCache.pending) {
    return latestVersionCache.pending;
  }

  latestVersionCache.pending = (async () => {
    try {
      const response = await fetch('https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/main/package.json');
      if (!response.ok) {
        console.error(`[mbkauthe] GitHub API responded with status ${response.status}`);
        latestVersionCache.value = null;
        latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_FAILURE_CACHE_TTL_MS;
        return null;
      }

      const latestPackageJson = await response.json();
      const latestVersion = typeof latestPackageJson.version === 'string' ? latestPackageJson.version : null;
      latestVersionCache.value = latestVersion;
      latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_CACHE_TTL_MS;
      return latestVersion;
    } catch (error) {
      console.error(`[mbkauthe] Error fetching latest version from GitHub`, error);
      latestVersionCache.value = null;
      latestVersionCache.expiresAt = Date.now() + LATEST_VERSION_FAILURE_CACHE_TTL_MS;
      return null;
    } finally {
      latestVersionCache.pending = null;
    }
  })();

  return latestVersionCache.pending;
}

// Version check with error handling
export async function checkVersion() {
    try {
        const latestVersion = await getLatestVersion();
        const hasValidLatest = typeof latestVersion === 'string' && /^\d+\.\d+\.\d+/.test(latestVersion);
        if (hasValidLatest && latestVersion !== packageJson.version) {
            console.warn(`[mbkauthe] Current version (${packageJson.version}) is outdated. Latest version: ${latestVersion}. Consider updating mbkauthe.`);
        } else if (hasValidLatest) {
            logMisc(`Running latest version (${packageJson.version}).`);
        } else {
            logMisc(`Skipped version check warning: latest version unavailable.`);
        }
    } catch (error) {
        console.warn(`[mbkauthe] Failed to check for updates: ${error.message}`);
    }
}

const { APP_NAME, DOMAIN, IS_DEPLOYED, loginRedirectURL } = mbkautheVar;
const safe_mbkautheVar = { APP_NAME, DOMAIN, IS_DEPLOYED, loginRedirectURL };

// Info page
router.get(["/info", "/i"], LoginLimit, async (req, res) => {
  let latestVersion;

  try {
    latestVersion = await getLatestVersion();
  } catch (err) {
    console.error(`[mbkauthe] Error fetching package-lock.json:`, err);
  }

  try {
    renderPage(req, res, "pages/info_mbkauthe.handlebars", false, {
      mbkautheVar: safe_mbkautheVar,
      CurrentVersion: packageJson.version,
      APP_VERSION: appVersion,
      latestVersion
    });
  } catch (err) {
    console.error(`[mbkauthe] Error fetching version information:`, err);
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

router.get(["/info.json", "/i.json"], LoginLimit, async (req, res) => {
  let latestVersion;
  try {
    latestVersion = await getLatestVersion();
  } catch (err) {
    console.error(`[mbkauthe] Error fetching package-lock.json:`, err);
  }

  try {
    res.json({ mbkautheVar: safe_mbkautheVar, CurrentVersion: packageJson.version, APP_VERSION: appVersion, latestVersion });
  } catch (err) {
    console.error(`[mbkauthe] Error fetching version information:`, err);
    res.status(500).json({ success: false, message: "Failed to fetch version information" });
  }
});

// Terminate all sessions (admin endpoint)
router.post("/api/terminateAllSessions", AdminOperationLimit, authenticate(mbkautheVar.Main_SECRET_TOKEN), async (req, res) => {
  try {
    // Run both operations in parallel for better performance
    await Promise.all([
      authRepo.deleteAllAppSessions('terminate-all-app-sessions'),
      authRepo.deleteActiveSessionStoreRows('terminate-all-db-sessions')
    ]);

    req.session.destroy((err) => {
      if (err) {
        console.error(`[mbkauthe] Error destroying session:`, err);
        return res.status(500).json({ success: false, message: "Failed to terminate sessions" });
      }

      clearSessionCookies(res);

      logMisc(`All sessions terminated successfully`);
      res.status(200).json({
        success: true,
        message: "All sessions terminated successfully",
      });
    });
  } catch (err) {
    console.error(`[mbkauthe] Database query error during session termination:`, err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

export default router;