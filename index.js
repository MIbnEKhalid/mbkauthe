import express from "express";
import router from "./lib/main.js";
import { getLatestVersion } from "./lib/main.js";
import { engine } from "express-handlebars";
import path from "path";
import { fileURLToPath } from "url";
import { packageJson } from "./lib/config/index.js";
import { renderError } from "./lib/utils/response.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.set("views", [
    path.join(__dirname, "views"),
    path.join(__dirname, "node_modules/mbkauthe/views")
]);

app.engine("handlebars", engine({
    defaultLayout: false,
    cache: true,
    partialsDir: [
        path.join(__dirname, "views"),
        path.join(__dirname, "node_modules/mbkauthe/views"),
        path.join(__dirname, "node_modules/mbkauthe/views/Error"),
    ],
    helpers: {
        eq: function (a, b) {
            return a === b;
        },
        encodeURIComponent: function (str) {
            return encodeURIComponent(str);
        },
        formatTimestamp: function (timestamp) {
            return new Date(timestamp).toLocaleString();
        },
        jsonStringify: function (context) {
            return JSON.stringify(context);
        },
        json: (obj) => JSON.stringify(obj, null, 2),
        objectEntries: function (obj) {
            if (!obj || typeof obj !== 'object') {
                return []; // Return an empty array if obj is undefined, null, or not an object
            }
            return Object.entries(obj).map(([key, value]) => ({ key, value }));
        }
    }

}));

app.set("view engine", "handlebars");

// Version check with error handling
async function checkVersion() {
    try {
        const latestVersion = await getLatestVersion();
        if (latestVersion && latestVersion !== packageJson.version) {
            console.warn(`[mbkauthe] Current version (${packageJson.version}) is outdated. Latest version: ${latestVersion}. Consider updating mbkauthe.`);
        } else if (latestVersion) {
            console.info(`[mbkauthe] Running latest version (${packageJson.version}).`);
        }
    } catch (error) {
        console.warn(`[mbkauthe] Failed to check for updates: ${error.message}`);
    }
}

if (process.env.test === "dev") {
    console.log("[mbkauthe] Dev mode is enabled. Starting server in dev mode.");
    const port = 5555;
    app.use(router);
    app.use((req, res) => {
        console.log(`[mbkauthe] Path not found: ${req.method} ${req.url}`);
        return renderError(res, {
            layout: false,
            code: 404,
            error: "Not Found",
            message: "The requested page was not found.",
            pagename: "Home",
            page: "/mbkauthe/login",
        });
    });
    app.listen(port, () => {
        console.log(`[mbkauthe] Server running on http://localhost:${port}`);
    });
}

if (process.env.test !== "dev") {
    await checkVersion();
}

export { validateSession, checkRolePermission, validateSessionAndRole, authenticate } from "./lib/middleware/auth.js";
export { renderError } from "./lib/utils/response.js";
export { dblogin } from "./lib/database/pool.js";
export { ErrorCodes, ErrorMessages, getErrorByCode, createErrorResponse, logError } from "./lib/utils/errors.js";
export default router;