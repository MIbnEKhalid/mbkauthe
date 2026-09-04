import dotenv from "dotenv";
import { createRequire } from "module";
import { createLogger } from "../utils/logger.js";
import { setPasswordPepper } from "./security.js";

dotenv.config();
const logConfig = createLogger("config");

const CONFIG_KEYS = [
    "APP_NAME", "DEVICE_TRUST_DURATION_DAYS", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY",
    "IS_DEPLOYED", "DB_TYPE", "LOGIN_DB", "SQLITE_PATH", "MBKAUTH_TWO_FA_ENABLE", "COOKIE_EXPIRE_TIME", "DOMAIN", "loginRedirectURL",
    "GITHUB_LOGIN_ENABLED", "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GOOGLE_LOGIN_ENABLED", "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET", "MAX_SESSIONS_PER_USER", "CLI_AUTH_BASE_URL", "CLI_AUTH_ENABLED"
];

const DEFAULT_CONFIG = {
    DEVICE_TRUST_DURATION_DAYS: 7,
    IS_DEPLOYED: 'false',
    DB_TYPE: 'postgres',
    SQLITE_PATH: './mbkauthe.sqlite',
    MBKAUTH_TWO_FA_ENABLE: 'false',
    COOKIE_EXPIRE_TIME: 2,
    loginRedirectURL: '/dashboard',
    GITHUB_LOGIN_ENABLED: 'false',
    GOOGLE_LOGIN_ENABLED: 'false',
    MAX_SESSIONS_PER_USER: 5,
    CLI_AUTH_ENABLED: 'false'
};

const BOOLEAN_KEYS = ['GITHUB_LOGIN_ENABLED', 'GOOGLE_LOGIN_ENABLED', 'MBKAUTH_TWO_FA_ENABLE', 'IS_DEPLOYED', 'CLI_AUTH_ENABLED'];
const STRING_KEYS = [
    "APP_NAME", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY", "DB_TYPE", "LOGIN_DB", "SQLITE_PATH", "DOMAIN", "loginRedirectURL",
    "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
    "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "CLI_AUTH_BASE_URL"
];
const REQUIRED_KEYS = ["APP_NAME", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY", "IS_DEPLOYED", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];

const isPlainObject = (val) => Boolean(val && typeof val === 'object' && !Array.isArray(val));
const isBlank = (val) => val === undefined || val === null || (typeof val === 'string' && val.trim() === '');
const hasValue = (val) => !isBlank(val);

function parseJsonEnv(name, { required = false } = {}) {
    const raw = process.env[name];
    if (isBlank(raw)) {
        if (required) throw new Error(`[mbkauthe] Configuration Error:\n  - process.env.${name} is not defined`);
        return null;
    }

    try {
        const parsed = JSON.parse(raw);
        if (!isPlainObject(parsed)) throw new Error(`${name} must be a valid object`);
        return parsed;
    } catch (error) {
        const message = error.message === `${name} must be a valid object` ? error.message : `Invalid JSON in process.env.${name}`;
        if (required) throw new Error(`[mbkauthe] Configuration Error:\n  - ${message}`);
        console.warn(`[mbkauthe] ${message}, ignoring it`);
        return null;
    }
}

function applySharedFallbacks(config, sharedConfig, usedFromShared) {
    if (!sharedConfig) return;
    Object.entries(sharedConfig).forEach(([key, value]) => {
        if (isBlank(config[key]) && hasValue(value)) {
            config[key] = value;
            usedFromShared.add(key);
        }
    });
}

function applyDefaults(config, usedDefaults) {
    CONFIG_KEYS.forEach((key) => {
        if (isBlank(config[key]) && DEFAULT_CONFIG[key] !== undefined) {
            config[key] = DEFAULT_CONFIG[key];
            usedDefaults.add(key);
        }
    });
}

function normalizeBooleanFlag(config, key, errors) {
    const value = config[key];
    if (typeof value === 'boolean') {
        config[key] = value ? 'true' : 'false';
        return;
    }
    const norm = String(value ?? '').trim().toLowerCase();
    if (norm === 'f' || norm === 'false') {
        config[key] = 'false';
    } else if (norm === 'true') {
        config[key] = 'true';
    } else if (!isBlank(value)) {
        errors.push(`mbkautheVar.${key} must be either 'true' or 'false' or 'f'`);
    }
}

function normalizePositiveNumber(config, key, errors, integerOnly = false) {
    const num = Number(config[key]);
    const valid = Number.isFinite(num) && num > 0 && (!integerOnly || Number.isInteger(num));
    if (!valid) {
        errors.push(`mbkautheVar.${key} must be a valid positive ${integerOnly ? 'integer' : 'number'}`);
    } else {
        config[key] = num;
    }
}

function normalizeAndValidateConfig(config, errors) {
    STRING_KEYS.forEach((key) => {
        if (hasValue(config[key])) config[key] = String(config[key]).trim();
    });

    if (hasValue(config.APP_NAME)) config.APP_NAME = config.APP_NAME.toLowerCase();

    if (hasValue(config.DB_TYPE)) {
        config.DB_TYPE = config.DB_TYPE.toLowerCase();
        if (!["postgres", "sqlite"].includes(config.DB_TYPE)) {
            errors.push("mbkautheVar.DB_TYPE must be either 'postgres' or 'sqlite'");
        }
    }

    if (hasValue(config.DOMAIN)) {
        const domain = config.DOMAIN.toLowerCase().replace(/^\.+/, '');
        config.DOMAIN = domain;
        if (domain.includes('://') || domain.includes('/') || domain.includes(':')) {
            errors.push("mbkautheVar.DOMAIN must be a hostname only, without protocol, path, or port");
        }
    }

    if (hasValue(config.loginRedirectURL)) {
        const redirectUrl = String(config.loginRedirectURL).trim();
        config.loginRedirectURL = redirectUrl;
        if (!redirectUrl.startsWith('/') || redirectUrl.startsWith('//')) {
            errors.push("mbkautheVar.loginRedirectURL must be a relative path starting with '/'");
        }
    }

    BOOLEAN_KEYS.forEach((key) => normalizeBooleanFlag(config, key, errors));
    normalizePositiveNumber(config, "COOKIE_EXPIRE_TIME", errors);
    normalizePositiveNumber(config, "DEVICE_TRUST_DURATION_DAYS", errors);
    normalizePositiveNumber(config, "MAX_SESSIONS_PER_USER", errors, true);
}

function validateConfiguration() {
    const errors = [];
    const usedFromShared = new Set();
    const usedDefaults = new Set();
    const mbkautheVar = parseJsonEnv("mbkautheVar", { required: true });
    const mbkauthShared = parseJsonEnv("mbkauthShared");

    applySharedFallbacks(mbkautheVar, mbkauthShared, usedFromShared);
    applyDefaults(mbkautheVar, usedDefaults);
    normalizeAndValidateConfig(mbkautheVar, errors);

    REQUIRED_KEYS.forEach((key) => {
        if (isBlank(mbkautheVar[key])) errors.push(`mbkautheVar.${key} is required and cannot be empty`);
    });

    if (mbkautheVar.GITHUB_LOGIN_ENABLED === "true") {
        if (!(mbkautheVar.GITHUB_APP_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID)) {
            errors.push("mbkautheVar.GITHUB_APP_CLIENT_ID (or GITHUB_CLIENT_ID) is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
        if (!(mbkautheVar.GITHUB_APP_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET)) {
            errors.push("mbkautheVar.GITHUB_APP_CLIENT_SECRET (or GITHUB_CLIENT_SECRET) is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
    }

    if (mbkautheVar.GOOGLE_LOGIN_ENABLED === "true") {
        if (isBlank(mbkautheVar.GOOGLE_CLIENT_ID)) errors.push("mbkautheVar.GOOGLE_CLIENT_ID is required when GOOGLE_LOGIN_ENABLED is 'true'");
        if (isBlank(mbkautheVar.GOOGLE_CLIENT_SECRET)) errors.push("mbkautheVar.GOOGLE_CLIENT_SECRET is required when GOOGLE_LOGIN_ENABLED is 'true'");
    }

    if (mbkautheVar.DB_TYPE === "sqlite") {
        if (isBlank(mbkautheVar.SQLITE_PATH)) errors.push("mbkautheVar.SQLITE_PATH is required and cannot be empty when DB_TYPE is 'sqlite'");
    } else {
        if (isBlank(mbkautheVar.LOGIN_DB)) {
            errors.push("mbkautheVar.LOGIN_DB is required and cannot be empty when DB_TYPE is 'postgres'");
        } else if (!mbkautheVar.LOGIN_DB.startsWith('postgresql://') && !mbkautheVar.LOGIN_DB.startsWith('postgres://')) {
            errors.push("mbkautheVar.LOGIN_DB must be a valid PostgreSQL connection string");
        }
    }

    if (errors.length > 0) {
        throw new Error(`[mbkauthe] Configuration Validation Failed:\n  - ${errors.join('\n  - ')}`);
    }

    const configParts = [];
    if (mbkauthShared) configParts.push(`mbkauthShared: ${usedFromShared.size} keys`);
    if (usedDefaults.size > 0) configParts.push(`defaults: ${usedDefaults.size} keys`);
    const configSummary = configParts.length > 0 ? ` (${configParts.join(', ')})` : '';
    logConfig(`Configuration loaded${configSummary}`);

    return Object.freeze(mbkautheVar);
}

const mbkautheVar = validateConfiguration();

const require = createRequire(import.meta.url);
let packageJson;
try {
    packageJson = require("mbkauthe/package.json");
} catch {
    packageJson = require("../../package.json");
}

let appVersion;
try {
    appVersion = require("../../../../package.json")?.version || require(process.cwd() + "/package.json")?.version || "unknown";
} catch {
    appVersion = "unknown";
}

setPasswordPepper(mbkautheVar.SESSION_SECRET_KEY);

export { packageJson, appVersion, mbkautheVar };
export { hashPassword, hashApiToken, verifyPassword } from "./security.js";
export { TOKEN_SCOPES, DEFAULT_SCOPE, canAccessMethod, isValidScope, getAvailableScopes } from "./tokenScopes.js";