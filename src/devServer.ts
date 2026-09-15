/**
 * MBKAuthe Standalone Development Server
 * Runs on http://localhost:5555
 */

import express from "express";
import { engine } from "express-handlebars";
import path from "path";
import { fileURLToPath } from "url";
import mbkautheRouter from "./http/app.js";
import { commonHandlebarsHelpers } from "./ui/helpers/handlebarsHelpers.js";
import { mbkautheVar } from "./config/env.js";
import { createNotFoundHandler, createErrorHandler } from "./http/response/handlers.js";
import { apiTokensRouter } from "./http/routes/apiToken.routes.js";
import { adminApiTokensRouter } from "./http/routes/adminApiToken.routes.js";
import { devRouter } from "./http/routes/dev.routes.js";

process.env.env = process.env.env || "dev";
process.env.dbLogs = process.env.dbLogs || "true";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const port = parseInt(process.env.PORT || "5555", 10);

const app = express();

app.engine(
  "handlebars",
  engine({
    helpers: commonHandlebarsHelpers,
    defaultLayout: "main",
    layoutsDir: path.join(rootDir, "views", "layouts"),
    partialsDir: [
      path.join(rootDir, "views", "partials"),
      path.join(rootDir, "views"),
      path.join(rootDir, "views", "Error"),
    ],
  })
);

app.set("view engine", "handlebars");
app.set("views", path.join(rootDir, "views"));

app.use("/public", express.static(path.join(rootDir, "public")));
app.use("/assets", express.static(path.join(rootDir, "public")));
app.use("/Assets", express.static(path.join(rootDir, "public")));

// API Tokens & Admin API Tokens Routers
app.use(apiTokensRouter);
app.use(adminApiTokensRouter);

// Dev Preview Routes
app.use("/dev", devRouter);
app.use("/mbkauthe/dev", devRouter);

// Dashboard & Home Redirects
app.get(["/dashboard", "/home"], (req, res) => res.redirect("/mbkauthe/"));

app.use(mbkautheRouter);

// 404 Page Controller for Development Server
app.use(
  createNotFoundHandler({
    defaultPage: "/mbkauthe/login",
    defaultPageName: "Login Portal",
  })
);

// 500 Error Controller
app.use(
  createErrorHandler({
    appName: mbkautheVar.APP_NAME,
    defaultPage: "/mbkauthe/login",
    defaultPageName: "Login Portal",
  })
);

app.listen(port, () => {
  console.log(`\n==================================================`);
  console.log(`🚀 [MBKAuthe DevServer] Running at: http://localhost:${port}`);
  console.log(`🔑 Login page:      http://localhost:${port}/mbkauthe/login`);
  console.log(`ℹ️  Info page:       http://localhost:${port}/mbkauthe/info`);
  console.log(`🩺 Health check:    http://localhost:${port}/mbkauthe/api/health`);
  console.log(`📊 DB logs:        http://localhost:${port}/mbkauthe/db`);
  console.log(`🧪 Test page:       http://localhost:${port}/mbkauthe/test`);
  console.log(`🛠️  Dev 2FA preview: http://localhost:${port}/dev/2fa`);
  console.log(`🛠️  Dev CLI preview: http://localhost:${port}/dev/device-approval`);
  console.log(`🛠️  Dev 500 error:   http://localhost:${port}/dev/500`);
  console.log(`🛠️  Dev 404 error:   http://localhost:${port}/dev/404`);
  console.log(`💾 App Name:        ${mbkautheVar.APP_NAME}`);
  console.log(`==================================================\n`);
});
