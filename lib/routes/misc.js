import express from "express";
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import { mbkautheVar, packageJson, appVersion } from "../config/index.js";
import { renderError } from "../utils/response.js";
import { authenticate, validateSession, validateApiSession } from "../middleware/auth.js";
import { ErrorCodes, ErrorMessages } from "../utils/errors.js";
import { dblogin } from "../database/pool.js";
import { clearSessionCookies } from "../config/cookies.js";
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
    const iconPath = path.join(__dirname, "..", "..", "public", "icon.svg");
    res.setHeader('Content-Type', 'image/svg+xml');
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
router.get('/test', validateSession, LoginLimit, async (req, res) => {
  if (req.session?.user) {
    return res.send(`
      <head> 
        <script src="/mbkauthe/main.js"></script> 
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
          .card { background: white; border-radius: 8px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
          .success { color: #16a085; border-left: 4px solid #16a085; padding-left: 15px; }
          .user-info { background: #ecf0f1; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 14px; }
          button { background: #e74c3c; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 10px 5px; }
          button:hover { background: #c0392b; }
          a { color: #3498db; text-decoration: none; margin: 0 10px; padding: 8px 12px; border: 1px solid #3498db; border-radius: 4px; display: inline-block; }
          a:hover { background: #3498db; color: white; }
        </style>
      </head>
      <div class="card">
        <p class="success">✅ Authentication successful! User is logged in.</p>
        <p>Welcome, <strong>${req.session.user.username}</strong>! Your role: <strong>${req.session.user.role}</strong></p>
        <div class="user-info">
          Username: ${req.session.user.username}<br>
          Role: ${req.session.user.role}<br>
          Full Name: ${req.session.user.fullname || 'N/A'}<br>
          User ID: ${req.session.user.id}<br>
          Session ID: ${req.session.user.sessionId.slice(0, 5)}...
        </div>
        <button onclick="logout()">Logout</button>
        <a href="https://portal.mbktech.org/">Web Portal</a>
        <a href="https://portal.mbktech.org/user/settings">User Settings</a>
        <a href="/mbkauthe/info">Info Page</a>
        <a href="/mbkauthe/login">Login Page</a>
      </div>
      `);
  }
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

// Info page
router.get(["/info", "/i"], LoginLimit, async (req, res) => {
  let latestVersion;
  const parameters = req.query;
  let authorized = false;

  if (parameters.password && mbkautheVar.Main_SECRET_TOKEN) {
    authorized = String(parameters.password) === String(mbkautheVar.Main_SECRET_TOKEN);
  }

  try {
    latestVersion = await getLatestVersion();
  } catch (err) {
    console.error("[mbkauthe] Error fetching package-lock.json:", err);
  }

  try {
    res.render("info.handlebars", {
      layout: false,
      mbkautheVar: mbkautheVar,
      version: packageJson.version,
      APP_VERSION: appVersion,
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
