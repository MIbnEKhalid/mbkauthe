import router from "./lib/main.js";

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);
if (!mbkautheVar) {
    throw new Error("mbkautheVar is not defined");
}
const requiredKeys = ["RECAPTCHA_SECRET_KEY", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];
requiredKeys.forEach(key => {
    if (!mbkautheVar[key]) {
        throw new Error(`mbkautheVar.${key} is required`);
    }
});
if (mbkautheVar.COOKIE_EXPIRE_TIME !== undefined) {
    const expireTime = parseFloat(mbkautheVar.COOKIE_EXPIRE_TIME);
    if (isNaN(expireTime) || expireTime <= 0) {
        throw new Error("mbkautheVar.COOKIE_EXPIRE_TIME must be a valid positive number");
    }
}


export { validateSession, checkRolePermission, validateSessionAndRole, getUserData, authenticate } from "./lib/validateSessionAndRole.js";
export { dblogin } from "./lib/pool.js";
export default router;