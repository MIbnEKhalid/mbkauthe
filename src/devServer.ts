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
    ],
  })
);

app.set("view engine", "handlebars");
app.set("views", path.join(rootDir, "views"));

app.use("/public", express.static(path.join(rootDir, "public")));
app.use("/assets", express.static(path.join(rootDir, "public")));
app.use("/Assets", express.static(path.join(rootDir, "public")));

app.use(mbkautheRouter);

app.listen(port, () => {
  console.log(`\n==================================================`);
  console.log(`🚀 [MBKAuthe DevServer] Running at: http://localhost:${port}`);
  console.log(`🔑 Login page: http://localhost:${port}/mbkauthe/login`);
  console.log(`ℹ️  Info page:  http://localhost:${port}/mbkauthe/info`);
  console.log(`📊 DB logs:   http://localhost:${port}/mbkauthe/db`);
  console.log(`💾 App Name:  ${mbkautheVar.APP_NAME}`);
  console.log(`==================================================\n`);
});
