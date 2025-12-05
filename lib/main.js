import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import passport from 'passport';
import {
  sessionConfig,
  corsMiddleware,
  sessionRestorationMiddleware,
  sessionCookieSyncMiddleware
} from "./middleware/index.js";
import authRoutes from "./routes/auth.js";
import oauthRoutes from "./routes/oauth.js";
import miscRoutes from "./routes/misc.js";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));


const router = express.Router();

// Basic middleware
router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());

// CORS and security headers
router.use(corsMiddleware);

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

// Redirect shortcuts for login
router.get(["/login", "/signin"], async (req, res) => {
  const queryParams = new URLSearchParams(req.query).toString();
  const redirectUrl = `/mbkauthe/login${queryParams ? `?${queryParams}` : ''}`;
  return res.redirect(redirectUrl);
});

router.get('/icon.svg', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', 'public', 'icon.svg'));
});

router.get(['/favicon.ico', '/icon.ico'], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', 'public', 'icon.ico'));
});

export { getLatestVersion } from "./routes/misc.js";
export default router;