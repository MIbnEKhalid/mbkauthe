import express from "express"; // Add this line
import router from "./lib/main.js";
import { getLatestVersion } from "./lib/main.js";
import { engine } from "express-handlebars";
import path from "path";
import { fileURLToPath } from "url";
import { renderError, packageJson } from "./lib/config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
if (process.env.test === "dev") {
    console.log("[mbkauthe] Dev mode is enabled. Starting server in dev mode.");
    const port = 5555;
    app.use(router);
    app.use((req, res) => {
        console.log(`Path not found: ${req.method} ${req.url}`);
        return res.status(404).render("Error/dError.handlebars", {
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
        concat: function (...args) {
            // Remove the handlebars options object from args
            args.pop();
            return args.join('');
        },
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

const latestVersion = await getLatestVersion();
if (latestVersion !== packageJson.version) {
    console.warn(`[mbkauthe] Warning: The current version (${packageJson.version}) is not the latest version (${latestVersion}). Please update mbkauthe.`);
}

export { validateSession, checkRolePermission, validateSessionAndRole, authenticate } from "./lib/validateSessionAndRole.js";
export { renderError } from "./lib/config.js";
export { dblogin } from "./lib/pool.js";
export default router;