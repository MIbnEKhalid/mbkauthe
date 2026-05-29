import express from "express";
import router, { checkVersion } from "./lib/main.js";
import { engine } from "express-handlebars";
import path from "path";
import { fileURLToPath } from "url";
import { renderError, renderPage } from "#response.js";
import { packageJson } from "#config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isDevMode = process.env.test === "dev";
const DEV_PORT = 5555;
const viewsPath = path.join(__dirname, "views");
const packageVersion = packageJson.version;

const app = express();

app.set("views", [
    viewsPath,
    path.join(__dirname, "node_modules/mbkauthe/views")
]);

const handlebarsHelpers = {
    eq: (a, b) => a === b,
    encodeURIComponent: (str) => encodeURIComponent(str),
    formatTimestamp: (timestamp) => new Date(timestamp).toLocaleString(),
    jsonStringify: (context) => JSON.stringify(context),
    json: (obj) => JSON.stringify(obj, null, 2),
    objectEntries: (obj) => {
        if (!obj || typeof obj !== 'object') return [];
        return Object.entries(obj).map(([key, value]) => ({ key, value }));
    },
    cacheBuster: () => `?v=${packageVersion}`
};

app.engine("handlebars", engine({
    defaultLayout: false,
    cache: true,
    partialsDir: [
        viewsPath,
        path.join(__dirname, "node_modules/mbkauthe/views"),
        path.join(__dirname, "node_modules/mbkauthe/views/Error"),
    ],
    helpers: handlebarsHelpers
}));

app.set("view engine", "handlebars");
app.use(router);

const renderDevError = (res, req, code, error, message, page, details) => renderError(res, req, {
    layout: false,
    code,
    error,
    message,
    details,
    pagename: "Home",
    page,
});

if (isDevMode) {
    console.log(`[mbkauthe] Dev mode is enabled. Starting server in dev mode.`);

    app.get(["/dashboard", "/home", "/"], (req, res) => res.redirect("/mbkauthe/"));

    app.get("/dev/2fa", (req, res) => renderPage(req, res, "pages/2fa.handlebars", false, {
        pagename: "Two-Factor Authentication",
        page: "/home"
    }));

    app.get("/showmessage", (req, res) => renderPage(req, res, "showmessage", false));

    app.get("/500", (req, res) => renderDevError(res, req, 500,
        "Internal Server Error", "Simulated 500 Error",
        "/mbkauthe/login", "This is a simulated 500 error page for testing purposes."
    ));

    app.use((req, res) => {
        console.log(`[mbkauthe] Path not found: ${req.method} ${req.url}`);
        renderDevError(res, req, 404, "Not Found", "The requested page was not found.", "/mbkauthe/login");
    });

    app.listen(DEV_PORT, () => {
        console.log(`[mbkauthe] Server running on http://localhost:${DEV_PORT}`);
    });
}

if (!isDevMode) {
    await checkVersion();
}

export * from "./lib/middleware/auth.js";
export * from "./lib/middleware/index.js";
export { validateTokenScope } from "./lib/middleware/scopeValidator.js";
export * from "#response.js";
export { dblogin } from "#pool.js";
export { getLatestVersion } from "./lib/routes/misc.js";
export * from "./lib/routes/auth.js";
export * from "./lib/utils/errors.js";
export * from "./lib/config/cookies.js";
export * from "./lib/config/security.js";
export * from "./lib/db/AuthRepository.js";
export { mbkautheVar } from "#config.js";
export default app;