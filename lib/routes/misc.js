import express from "express";
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import { mbkautheVar, packageJson, appVersion } from "#config.js";
import { renderError } from "#response.js";
import { authenticate, validateSession, validateApiSession } from "../middleware/auth.js";
import { ErrorCodes, ErrorMessages, createErrorResponse } from "../utils/errors.js";
import { dblogin } from "#pool.js";
import { clearSessionCookies, decryptSessionId } from "#cookies.js";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));


const router = express.Router();
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

router.get("/bg.webp", (req, res) => {
  const imgPath = path.join(__dirname, "..", "..", "public", "bg.webp");
  res.setHeader('Content-Type', 'image/webp');
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  const stream = fs.createReadStream(imgPath);
  stream.on('error', (err) => {
    console.error('[mbkauthe] Error streaming bg.webp:', err);
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
    // Ensure we don't override the Cache-Control we set earlier, or set a default if not set
    if (!res.getHeader('Cache-Control')) {
      res.setHeader('Cache-Control', 'private, no-cache');
    }
    const stream = fs.createReadStream(iconPath);
    stream.on('error', (err) => {
      console.error('[mbkauthe] Error streaming icon.svg:', err);
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
    const cacheKey = `profilepic_${username}`;
    let imageUrl = req.session[cacheKey];

    // If not in cache, fetch from DB
    if (!imageUrl) {
      const result = await dblogin.query({
        name: 'get-user-profile-pic',
        text: 'SELECT "Image" FROM "Users" WHERE "UserName" = $1 LIMIT 1',
        values: [username]
      });

      if (result.rows.length > 0 && result.rows[0].Image && result.rows[0].Image.trim() !== '') {
        imageUrl = result.rows[0].Image;
      } else {
        imageUrl = 'default';
      }
      req.session[cacheKey] = imageUrl;
    }

    // Generate ETag based on username and image URL
    const eTag = `"${Buffer.from(username + ':' + imageUrl).toString('base64')}"`;

    // Set caching headers
    res.setHeader('Cache-Control', 'private, no-cache');
    res.setHeader('ETag', eTag);

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
        req.session[cacheKey] = 'default';
        return serveDefaultIcon();
      }

      const contentType = imageResponse.headers.get('content-type') || 'image/jpeg';
      res.setHeader('Content-Type', contentType);

      imageResponse.body.pipe(res);
    } catch (fetchErr) {
      console.error('[mbkauthe] Error fetching external profile picture:', fetchErr);
      req.session[cacheKey] = 'default';
      return serveDefaultIcon();
    }

  } catch (err) {
    console.error('[mbkauthe] Error fetching profile picture:', err);
    return serveDefaultIcon();
  }
});

// Test route
router.get(['/test', '/'], validateSession, LoginLimit, async (req, res) => {
  const { username, fullname, role, id, sessionId, allowedApps } = req.session.user;

  const sessionExpiry = req.session.cookie?.expires
    ? new Date(req.session.cookie.expires).toISOString()
    : null;

  return res.render('test.handlebars', {
    layout: false,
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

router.post('/test', validateSession, LoginLimit, async (req, res) => {
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

    const result = await dblogin.query({ name: 'check-session-validity', text: `SELECT s.expires_at, u."Active" FROM "Sessions" s JOIN "Users" u ON s."UserName" = u."UserName" WHERE s.id = $1 LIMIT 1`, values: [sessionId] });

    if (result.rows.length === 0) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const row = result.rows[0];
    if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
      req.session.destroy(() => { });
      clearSessionCookies(res);
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    // Determine expiry: prefer application session expiry if present else fallback to connect-pg-simple expire
    let expiry = row.expires_at ? new Date(row.expires_at).toISOString() : null;
    if (!expiry) {
      const sessResult = await dblogin.query({ name: 'get-session-expiry', text: 'SELECT expire FROM "session" WHERE sid = $1', values: [req.sessionID] });
      expiry = sessResult.rows.length > 0 && sessResult.rows[0].expire ? new Date(sessResult.rows[0].expire).toISOString() : null;
    }

    return res.status(200).json({ sessionValid: true, expiry });
  } catch (err) {
    console.error('[mbkauthe] checkSession error:', err);
    return res.status(200).json({ sessionValid: false, expiry: null });
  }
});

// UUID helper used by session endpoints
const isUuid = (val) => typeof val === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);

// POST /api/checkSession — accept sessionId in request body { sessionId: "<uuid>" }
router.post('/api/checkSession', LoginLimit, async (req, res) => {
  try {
    const { sessionId: rawSessionId, isEncrypt, isEncryt } = req.body || {};
    let sessionId = rawSessionId;
    if (!sessionId) {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    }

    // If body indicates the sessionId is encrypted, decode (if URL-encoded) then decrypt it first
    const encryptedFlag = isEncrypt === true || isEncrypt === 'true' || isEncryt === true || isEncryt === 'true';
    if (encryptedFlag) {
      // Some clients URL-encode cookie values when posting; safely try to decode first
      let toDecrypt = typeof sessionId === 'string' ? sessionId : String(sessionId);
      try {
        toDecrypt = decodeURIComponent(toDecrypt);
      } catch (decodeErr) {
        // ignore decode errors and continue with original value
      }
      const decrypted = decryptSessionId(toDecrypt);
      if (!decrypted || !isUuid(decrypted)) {
        return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));
      }
      sessionId = decrypted;
    }

    const result = await dblogin.query({
      name: 'check-session-validity-by-id',
      text: `SELECT s.expires_at, u."Active" FROM "Sessions" s JOIN "Users" u ON s."UserName" = u."UserName" WHERE s.id = $1 LIMIT 1`,
      values: [sessionId]
    });

    if (result.rows.length === 0) {
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const row = result.rows[0];
    if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
      return res.status(200).json({ sessionValid: false, expiry: null });
    }

    const expiry = row.expires_at ? new Date(row.expires_at).toISOString() : null;
    return res.status(200).json({ sessionValid: true, expiry });
  } catch (err) {
    console.error('[mbkauthe] checkSession (body) error:', err);
    return res.status(200).json({ sessionValid: false, expiry: null });
  }
});

// POST /api/verifySession — returns details about sessionId provided in body
router.post('/api/verifySession', LoginLimit, async (req, res) => {
  try {
    const { sessionId: rawSessionId, isEncrypt, isEncryt } = req.body || {};
    let sessionId = rawSessionId;
    if (!sessionId) {
      return res.status(400).json(createErrorResponse(400, ErrorCodes.MISSING_REQUIRED_FIELD));
    }

    // If body indicates the sessionId is encrypted, decode (if URL-encoded) then decrypt it first
    const encryptedFlag = isEncrypt === true || isEncrypt === 'true' || isEncryt === true || isEncryt === 'true';
    if (encryptedFlag) {
      // Some clients URL-encode cookie values when posting; safely try to decode first
      let toDecrypt = typeof sessionId === 'string' ? sessionId : String(sessionId);
      try {
        toDecrypt = decodeURIComponent(toDecrypt);
      } catch (decodeErr) {
        // ignore decode errors and continue with original value
      }
      const decrypted = decryptSessionId(toDecrypt);
      if (!decrypted || !isUuid(decrypted)) {
        return res.status(400).json(createErrorResponse(400, ErrorCodes.SESSION_INVALID));
      }
      sessionId = decrypted;
    }

    const query = `SELECT s.id as sid, s.expires_at, u.id as uid, u."UserName", u."Active", u."Role", u."AllowedApps"
                   FROM "Sessions" s
                   JOIN "Users" u ON s."UserName" = u."UserName"
                   WHERE s.id = $1 LIMIT 1`;
    const result = await dblogin.query({ name: 'verify-session', text: query, values: [sessionId] });

    if (result.rows.length === 0) {
      return res.status(200).json({ valid: false, expiry: null });
    }

    const row = result.rows[0];
    if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
      return res.status(200).json({ valid: false, expiry: null });
    }

    const expiry = row.expires_at ? new Date(row.expires_at).toISOString() : null;
    return res.status(200).json({ valid: true, expiry, username: row.UserName, role: row.Role });
  } catch (err) {
    console.error('[mbkauthe] verifySession error:', err);
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

    res.render("errorCodes.handlebars", {
      layout: false,
      pageTitle: 'Error Codes',
      appName: mbkautheVar.APP_NAME,
      errorCategories: categoriesWithErrors
    });
  } catch (err) {
    console.error("[mbkauthe] Error rendering error codes page:", err);
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

// Fetch latest version from GitHub
export async function getLatestVersion() {
  try {
    const response = await fetch('https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/main/package.json');
    if (!response.ok) {
      console.error(`[mbkauthe] GitHub API responded with status ${response.status}`);
      return "0.0.0";
    }
    const latestPackageJson = await response.json();
    return latestPackageJson.version;
  } catch (error) {
    console.error('[mbkauthe] Error fetching latest version from GitHub:', error);
    return null;
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
    console.error("[mbkauthe] Error fetching package-lock.json:", err);
  }

  try {
    res.render("info_mbkauthe.handlebars", {
      layout: false,
      mbkautheVar: safe_mbkautheVar,
      CurrentVersion: packageJson.version,
      APP_VERSION: appVersion,
      latestVersion
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

router.get(["/info.json", "/i.json"], LoginLimit, async (req, res) => {
  let latestVersion;
  try {
    latestVersion = await getLatestVersion();
  } catch (err) {
    console.error("[mbkauthe] Error fetching package-lock.json:", err);
  }

  try {
    res.json({ mbkautheVar: safe_mbkautheVar, CurrentVersion: packageJson.version, APP_VERSION: appVersion, latestVersion });
  } catch (err) {
    console.error("[mbkauthe] Error fetching version information:", err);
    res.status(500).json({ success: false, message: "Failed to fetch version information" });
  }
});

// Terminate all sessions (admin endpoint)
router.post("/api/terminateAllSessions", AdminOperationLimit, authenticate(mbkautheVar.Main_SECRET_TOKEN), async (req, res) => {
  try {
    // Run both operations in parallel for better performance
    await Promise.all([
      dblogin.query({
        name: 'terminate-all-app-sessions',
        text: 'DELETE FROM "Sessions"'
      }),
      dblogin.query({
        name: 'terminate-all-db-sessions',
        text: 'DELETE FROM "session" WHERE expire > NOW()'
      })
    ]);

    req.session.destroy((err) => {
      if (err) {
        console.log("[mbkauthe] Error destroying session:", err);
        return res.status(500).json({ success: false, message: "Failed to terminate sessions" });
      }

      clearSessionCookies(res);

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

export default router;