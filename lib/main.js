import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import passport from 'passport';
import {
  sessionConfig,
  corsMiddleware,
  sessionRestorationMiddleware,
  sessionCookieSyncMiddleware,
  requestContextMiddleware
} from "./middleware/index.js";
import authRoutes from "./routes/auth.js";
import oauthRoutes from "./routes/oauth.js";
import miscRoutes from "./routes/misc.js";
import dbLogsRoutes from "./routes/dbLogs.js";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));


const router = express.Router();

// Configure Express to trust proxy headers for rate limiting in dev mode only
// This prevents conflicts with parent project proxy settings in production
if (process.env.test === "dev") {
  router.use((req, res, next) => {
    // Set trust proxy to true for the app instance if not already set
    if (!req.app.get('trust proxy')) {
      req.app.set('trust proxy', true);
    }
    next();
  });
}

// Basic middleware
router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());

// CORS and security headers
router.use(corsMiddleware);

// Attach request context as early as possible so session-store queries are tied to the request.
if (process.env.env === 'dev') {
  router.use(requestContextMiddleware);
}

// Session configuration
router.use(session(sessionConfig));

// Session restoration
router.use(sessionRestorationMiddleware);

// Initialize passport
router.use(passport.initialize());
router.use(passport.session());

// Session cookie sync
router.use(sessionCookieSyncMiddleware);

// Mount routes (rate limiting is applied within each route module)
router.use('/mbkauthe', authRoutes);
router.use('/mbkauthe', oauthRoutes);
router.use('/mbkauthe', miscRoutes);

if (process.env.env === 'dev') {
  router.use('/mbkauthe', dbLogsRoutes);
}

// Redirect shortcuts for login
router.get(["/login", "/signin"], async (req, res) => {
  const queryParams = new URLSearchParams(req.query).toString();
  const redirectUrl = `/mbkauthe/login${queryParams ? `?${queryParams}` : ''}`;
  return res.redirect(redirectUrl);
});

router.get(['/icon.svg', "/favicon.ico", "/icon.png"], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', 'public', 'M.png'));
});

export { checkVersion } from "./routes/misc.js";
export default router;