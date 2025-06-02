import express from "express"; // Add this line
import router from "./lib/main.js";
import { engine } from "express-handlebars";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
let mbkautheVar;

try {
    mbkautheVar = JSON.parse(process.env.mbkautheVar);
} catch (error) {
    throw new Error("Invalid JSON in process.env.mbkautheVar");
}
if (!mbkautheVar) {
    throw new Error("mbkautheVar is not defined");
}
const requiredKeys = ["APP_NAME", "RECAPTCHA_Enabled", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];
requiredKeys.forEach(key => {
    if (!mbkautheVar[key]) {
        throw new Error(`mbkautheVar.${key} is required`);
    }
});
if (mbkautheVar.RECAPTCHA_Enabled === "true") {
    if (mbkautheVar.RECAPTCHA_SECRET_KEY === undefined) {
        throw new Error("mbkautheVar.RECAPTCHA_SECRET_KEY is required");
    }
}
if (mbkautheVar.COOKIE_EXPIRE_TIME !== undefined) {
    const expireTime = parseFloat(mbkautheVar.COOKIE_EXPIRE_TIME);
    if (isNaN(expireTime) || expireTime <= 0) {
        throw new Error("mbkautheVar.COOKIE_EXPIRE_TIME must be a valid positive number");
    }
}
if (mbkautheVar.BypassUsers !== undefined) {
    if (!Array.isArray(mbkautheVar.BypassUsers)) {
        throw new Error("mbkautheVar.BypassUsers must be a valid array");
    }
}

const app = express();
if (process.env.test === "true") {
    console.log("Test mode is enabled. Starting server in test mode.");
    const port = 3000;
    app.use(router);
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
}

app.set("views", path.join(__dirname, "node_modules/mbkauthe/views"));

app.engine("handlebars", engine({
    defaultLayout: false,
    partialsDir: [
        path.join(__dirname, "node_modules/mbkauthe/views"),
    ],
}));

app.set("view engine", "handlebars");

export { validateSession, checkRolePermission, validateSessionAndRole, getUserData, authenticate, authapi } from "./lib/validateSessionAndRole.js";
export { dblogin } from "./lib/pool.js";
export default router;