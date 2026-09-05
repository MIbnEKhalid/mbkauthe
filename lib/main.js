import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import passport from 'passport';
import path from "path";
import { fileURLToPath } from "url";
import {
  sessionConfig,
  corsMiddleware,
  securityHeadersMiddleware,
  sessionRestorationMiddleware,
  sessionCookieSyncMiddleware,
  requestContextMiddleware
} from "./middleware/index.js";
import authRoutes from "./routes/auth.js";
import oauthRoutes from "./routes/oauth.js";
import miscRoutes from "./routes/misc.js";
import dbLogsRoutes from "./routes/dbLogs.js";
import cliAuthRouter from "./routes/cliAuth.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const router = express.Router();

if (process.env.test === "dev") {
  router.use((req, res, next) => {
    if (!req.app.get('trust proxy')) req.app.set('trust proxy', true);
    next();
  });
}

router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(cookieParser());
router.use(securityHeadersMiddleware);
router.use(corsMiddleware);

if (process.env.env === 'dev') {
  router.use(requestContextMiddleware);
}

router.use(session(sessionConfig));
router.use(sessionRestorationMiddleware);
router.use(passport.initialize());
router.use(passport.session());
router.use(sessionCookieSyncMiddleware);

router.use('/mbkauthe', authRoutes);
router.use('/mbkauthe', oauthRoutes);
router.use('/mbkauthe', miscRoutes);

if (process.env.env === 'dev') {
  router.use('/mbkauthe', dbLogsRoutes);
}

router.use(cliAuthRouter);

router.get(["/login", "/signin"], (req, res) => {
  const queryParams = new URLSearchParams(req.query).toString();
  return res.redirect(`/mbkauthe/login${queryParams ? `?${queryParams}` : ''}`);
});

router.get(['/icon.svg', "/favicon.ico", "/icon.png"], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  res.sendFile(path.join(__dirname, '..', 'public', 'M.png'));
});

export { checkVersion } from "./routes/misc.js";
export default router;

/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */