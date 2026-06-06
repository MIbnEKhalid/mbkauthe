import dotenv from "dotenv";
import { createRequire } from "module";
import { createLogger } from "../utils/logger.js";

dotenv.config();
const logConfig = createLogger("config");

const CONFIG_KEYS = [
    "APP_NAME", "DEVICE_TRUST_DURATION_DAYS", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY",
    "IS_DEPLOYED", "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "COOKIE_EXPIRE_TIME", "DOMAIN", "loginRedirectURL",
    "GITHUB_LOGIN_ENABLED", "GITHUB_APP_SLUG", "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GOOGLE_LOGIN_ENABLED", "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET", "MAX_SESSIONS_PER_USER"
];

const DEFAULT_CONFIG = {
    DEVICE_TRUST_DURATION_DAYS: 7,
    IS_DEPLOYED: 'false',
    MBKAUTH_TWO_FA_ENABLE: 'false',
    COOKIE_EXPIRE_TIME: 2,
    loginRedirectURL: '/dashboard',
    GITHUB_LOGIN_ENABLED: 'false',
    GOOGLE_LOGIN_ENABLED: 'false',
    MAX_SESSIONS_PER_USER: 5
};

const BOOLEAN_KEYS = ['GITHUB_LOGIN_ENABLED', 'GOOGLE_LOGIN_ENABLED', 'MBKAUTH_TWO_FA_ENABLE', 'IS_DEPLOYED'];
const STRING_KEYS = [
    "APP_NAME", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY", "LOGIN_DB", "DOMAIN", "loginRedirectURL",
    "GITHUB_APP_SLUG", "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
    "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"
];
const REQUIRED_KEYS = ["APP_NAME", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB",
    "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];

const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);
const isBlank = (value) => value === undefined || value === null || (typeof value === 'string' && value.trim() === '');
const hasValue = (value) => !isBlank(value);

function parseJsonEnv(name, { required = false } = {}) {
    const raw = process.env[name];
    if (isBlank(raw)) {
        if (required) {
            throw new Error(`[mbkauthe] Configuration Error:\n  - process.env.${name} is not defined`);
        }
        return null;
    }

    try {
        const parsed = JSON.parse(raw);
        if (!isPlainObject(parsed)) {
            throw new Error(`${name} must be a valid object`);
        }
        return parsed;
    } catch (error) {
        const message = error.message === `${name} must be a valid object`
            ? error.message
            : `Invalid JSON in process.env.${name}`;
        if (required) {
            throw new Error(`[mbkauthe] Configuration Error:\n  - ${message}`);
        }
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

    const normalized = String(value ?? '').trim().toLowerCase();
    if (normalized === 'f') {
        config[key] = 'false';
        return;
    }

    if (normalized === 'true' || normalized === 'false') {
        config[key] = normalized;
        return;
    }

    if (!isBlank(value)) {
        errors.push(`mbkautheVar.${key} must be either 'true' or 'false' or 'f'`);
    }
}

function normalizePositiveNumber(config, key, errors) {
    const numericValue = Number(config[key]);
    if (!Number.isFinite(numericValue) || numericValue <= 0) {
        errors.push(`mbkautheVar.${key} must be a valid positive number`);
        return;
    }
    config[key] = numericValue;
}

function normalizePositiveInteger(config, key, errors) {
    const numericValue = Number(config[key]);
    if (!Number.isInteger(numericValue) || numericValue <= 0) {
        errors.push(`mbkautheVar.${key} must be a valid positive integer`);
        return;
    }
    config[key] = numericValue;
}

function normalizeString(config, key) {
    if (hasValue(config[key])) {
        config[key] = String(config[key]).trim();
    }
}

function normalizeAndValidateConfig(config, errors) {
    STRING_KEYS.forEach((key) => normalizeString(config, key));

    if (hasValue(config.APP_NAME)) {
        config.APP_NAME = config.APP_NAME.toLowerCase();
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
    normalizePositiveInteger(config, "MAX_SESSIONS_PER_USER", errors);
}

// Comprehensive validation function
function validateConfiguration() {
    const errors = [];
    const usedFromShared = new Set();
    const usedDefaults = new Set();
    const mbkautheVar = parseJsonEnv("mbkautheVar", { required: true });
    const mbkauthShared = parseJsonEnv("mbkauthShared");

    applySharedFallbacks(mbkautheVar, mbkauthShared, usedFromShared);
    applyDefaults(mbkautheVar, usedDefaults);
    normalizeAndValidateConfig(mbkautheVar, errors);

    // Validate required keys
    // COOKIE_EXPIRE_TIME is not required but if provided must be valid, COOKIE_EXPIRE_TIME by default is 2 days
    // loginRedirectURL is not required but if provided must be valid, loginRedirectURL by default is /dashboard
    REQUIRED_KEYS.forEach(key => {
        if (isBlank(mbkautheVar[key])) {
            errors.push(`mbkautheVar.${key} is required and cannot be empty`);
        }
    });

    // Validate GitHub login configuration
    if (mbkautheVar.GITHUB_LOGIN_ENABLED === "true") {
        const hasGithubClientId = !!(mbkautheVar.GITHUB_APP_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID);
        const hasGithubClientSecret = !!(mbkautheVar.GITHUB_APP_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET);

        if (!hasGithubClientId) {
            errors.push("mbkautheVar.GITHUB_APP_CLIENT_ID (or GITHUB_CLIENT_ID) is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
        if (!hasGithubClientSecret) {
            errors.push("mbkautheVar.GITHUB_APP_CLIENT_SECRET (or GITHUB_CLIENT_SECRET) is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
    }

    // Validate Google login configuration
    if (mbkautheVar.GOOGLE_LOGIN_ENABLED === "true") {
        if (isBlank(mbkautheVar.GOOGLE_CLIENT_ID)) {
            errors.push("mbkautheVar.GOOGLE_CLIENT_ID is required when GOOGLE_LOGIN_ENABLED is 'true'");
        }
        if (isBlank(mbkautheVar.GOOGLE_CLIENT_SECRET)) {
            errors.push("mbkautheVar.GOOGLE_CLIENT_SECRET is required when GOOGLE_LOGIN_ENABLED is 'true'");
        }
    }

    // Validate LOGIN_DB connection string format
    if (mbkautheVar.LOGIN_DB && !mbkautheVar.LOGIN_DB.startsWith('postgresql://') && !mbkautheVar.LOGIN_DB.startsWith('postgres://')) {
        errors.push("mbkautheVar.LOGIN_DB must be a valid PostgreSQL connection string");
    }

    // If there are validation errors, throw them all at once
    if (errors.length > 0) {
        throw new Error(`[mbkauthe] Configuration Validation Failed:\n  - ${errors.join('\n  - ')}`);
    }

    // Print consolidated configuration summary
    const configParts = [];
    if (mbkauthShared) {
        configParts.push(`mbkauthShared: ${usedFromShared.size} keys`);
    }
    if (usedDefaults.size > 0) {
        configParts.push(`defaults: ${usedDefaults.size} keys`);
    }
    const configSummary = configParts.length > 0 ? ` (${configParts.join(', ')})` : '';
    logConfig(`Configuration loaded${configSummary}`);
    return Object.freeze(mbkautheVar);
}

// Parse and validate mbkautheVar once
const mbkautheVar = validateConfiguration();

// Load package.json from mbkauthe package (not parent project)
const require = createRequire(import.meta.url);
let packageJson;
try {
    // Try to load from mbkauthe package directory
    packageJson = require("mbkauthe/package.json");
} catch {
    // Fallback to relative path (for development/testing)
    packageJson = require("../../package.json");
}

// Parent project version
let appVersion;
try {
    appVersion = require("../../../../package.json")?.version || "unknown";
} catch {
    // Fallback if path doesn't work
    try {
        appVersion = require(process.cwd() + "/package.json")?.version || "unknown";
    } catch {
        appVersion = "unknown";
    }
}

export { packageJson, appVersion, mbkautheVar };
export { hashPassword, hashApiToken } from "./security.js";
export { TOKEN_SCOPES, DEFAULT_SCOPE, canAccessMethod, isValidScope, getAvailableScopes } from "./tokenScopes.js";