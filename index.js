import dotenv from "dotenv";
import Joi from "joi";
import router from "./lib/main.js";
dotenv.config();

const envSchema = Joi.object({
    RECAPTCHA_SECRET_KEY: Joi.string().required(),
    SESSION_SECRET_KEY: Joi.string().required(),
    IS_DEPLOYED: Joi.string().valid("true", "false").required(),
    LOGIN_DB: Joi.string().uri().required(),
    MBKAUTH_TWO_FA_ENABLE: Joi.string().valid("true", "false").required(),
    COOKIE_EXPIRE_TIME: Joi.number().integer().positive(),
    DOMAIN: Joi.string().required(),
}).unknown(true);

const { error } = envSchema.validate(process.env);
if (error) {
    throw new Error(`Environment variable validation error: ${error.message}`);
}
export { validateSession, checkRolePermission, validateSessionAndRole, getUserData } from "./lib/validateSessionAndRole.js";
export { authenticate } from "./lib/auth.js";
export { dblogin } from "./lib/pool.js";
export default router;