import express from "express";
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import { mbkautheVar, packageJson, appVersion } from "../config/index.js";
import { renderError } from "../utils/response.js";
import { authenticate, validateSession } from "../middleware/auth.js";
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
          User ID: ${req.session.user.id}<br>
          Session ID: ${req.session.user.sessionId.slice(0, 5)}...
        </div>
        <button onclick="logout()">Logout</button>
        <a href="/mbkauthe/info">Info Page</a>
        <a href="/mbkauthe/login">Login Page</a>
      </div>
      `);
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
    return renderError(res, {
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
        name: 'terminate-all-user-sessions', 
        text: 'UPDATE "Users" SET "SessionId" = NULL WHERE "SessionId" IS NOT NULL'
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
