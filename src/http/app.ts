/**
 * MBKAuthe HTTP Application & Router
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import express, { Router } from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { corsMiddleware, securityHeadersMiddleware, requestContextMiddleware } from "./middleware/index.js";
import authRoutes from "./routes/auth.routes.js";
import oauthRoutes from "./routes/oauth.routes.js";
import miscRoutes, { checkVersion } from "./routes/misc.routes.js";
import dbLogsRoutes from "./routes/dbLogs.routes.js";
import cliAuthRouter from "./routes/cliAuth.routes.js";
import devRoutes from "./routes/dev.routes.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface MbkautheAppOptions {
  enableStaticAssets?: boolean;
  enableCliAuth?: boolean;
  enableOAuth?: boolean;
  enableDbLogs?: boolean;
  enableDevRoutes?: boolean;
}

export function createMbkautheApp(options: MbkautheAppOptions = {}): Router {
  const router = express.Router();
  const {
    enableStaticAssets = true,
    enableCliAuth = true,
    enableOAuth = true,
    enableDbLogs = process.env.dbLogs === "true" || process.env.DB_LOGS === "true",
    enableDevRoutes = process.env.env === "dev" || process.env.test === "dev" || process.env.NODE_ENV !== "production",
  } = options;

  if (process.env.test === "dev") {
    router.use((req, res, next) => {
      if (!req.app.get("trust proxy")) req.app.set("trust proxy", true);
      next();
    });
  }

  router.use(express.json());
  router.use(express.urlencoded({ extended: true }));
  router.use(cookieParser());
  router.use(securityHeadersMiddleware);
  router.use(corsMiddleware);

  if (enableDbLogs) {
    router.use(requestContextMiddleware);
  }

  router.use("/mbkauthe", authRoutes);
  if (enableOAuth) router.use("/mbkauthe", oauthRoutes);
  router.use("/mbkauthe", miscRoutes);

  if (enableDbLogs) {
    router.use("/mbkauthe", dbLogsRoutes);
    router.get(["/db", "/dblogs", "/db-logs"], (req, res) => {
      const queryParams = new URLSearchParams(req.query as any).toString();
      return res.redirect(`/mbkauthe/db${queryParams ? `?${queryParams}` : ""}`);
    });
  }

  if (enableDevRoutes) {
    router.use("/dev", devRoutes);
    router.use("/mbkauthe/dev", devRoutes);
  }

  if (enableCliAuth) {
    router.use(cliAuthRouter);
  }

  router.get(["/login", "/signin"], (req, res) => {
    const queryParams = new URLSearchParams(req.query as any).toString();
    return res.redirect(`/mbkauthe/login${queryParams ? `?${queryParams}` : ""}`);
  });

  if (enableStaticAssets) {
    router.get(["/icon.svg", "/favicon.ico", "/icon.png"], (req, res) => {
      res.setHeader("Cache-Control", "public, max-age=31536000");
      res.sendFile(path.join(__dirname, "..", "..", "public", "M.png"));
    });
  }

  return router;
}

export const mbkautheApp = createMbkautheApp();
export { checkVersion };
export default mbkautheApp;
