import dotenv from "dotenv";
import { createRequire } from "module";
import { createLogger } from "../utils/logger.js";
import { setPasswordPepper } from "./security.js";

dotenv.config();
const logConfig = createLogger("config");

export function normalizeKey(key) {
    if (!key || typeof key !== "string") return "";
    return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

const CANONICAL_KEYS = [
    { lower: "app_name", upper: "APP_NAME" },
    { lower: "device_trust_duration_days", upper: "DEVICE_TRUST_DURATION_DAYS" },
    { lower: "main_secret_token", upper: "MAIN_SECRET_TOKEN" },
    { lower: "session_secret_key", upper: "SESSION_SECRET_KEY" },
    { lower: "is_deployed", upper: "IS_DEPLOYED" },
    { lower: "db_type", upper: "DB_TYPE" },
    { lower: "login_db", upper: "LOGIN_DB" },
    { lower: "sqlite_path", upper: "SQLITE_PATH" },
    { lower: "mbkauth_two_fa_enable", upper: "MBKAUTH_TWO_FA_ENABLE" },
    { lower: "cookie_expire_time", upper: "COOKIE_EXPIRE_TIME" },
    { lower: "domain", upper: "DOMAIN" },
    { lower: "login_redirect_url", upper: "LOGIN_REDIRECT_URL" },
    { lower: "github_login_enabled", upper: "GITHUB_LOGIN_ENABLED" },
    { lower: "github_app_client_id", upper: "GITHUB_APP_CLIENT_ID" },
    { lower: "github_app_client_secret", upper: "GITHUB_APP_CLIENT_SECRET" },
    { lower: "github_client_id", upper: "GITHUB_CLIENT_ID" },
    { lower: "github_client_secret", upper: "GITHUB_CLIENT_SECRET" },
    { lower: "google_login_enabled", upper: "GOOGLE_LOGIN_ENABLED" },
    { lower: "google_client_id", upper: "GOOGLE_CLIENT_ID" },
    { lower: "google_client_secret", upper: "GOOGLE_CLIENT_SECRET" },
    { lower: "max_sessions_per_user", upper: "MAX_SESSIONS_PER_USER" },
    { lower: "cli_auth_base_url", upper: "CLI_AUTH_BASE_URL" },
    { lower: "cli_auth_enabled", upper: "CLI_AUTH_ENABLED" }
];

const DEFAULT_CONFIG = {
    device_trust_duration_days: 7,
    is_deployed: 'false',
    db_type: 'postgres',
    sqlite_path: './mbkauthe.sqlite',
    mbkauth_two_fa_enable: 'false',
    cookie_expire_time: 2,
    login_redirect_url: '/dashboard',
    github_login_enabled: 'false',
    google_login_enabled: 'false',
    max_sessions_per_user: 5,
    cli_auth_enabled: 'false'
};

const BOOLEAN_KEYS = ['github_login_enabled', 'google_login_enabled', 'mbkauth_two_fa_enable', 'is_deployed', 'cli_auth_enabled'];
const STRING_KEYS = [
    "app_name", "main_secret_token", "session_secret_key", "db_type", "login_db", "sqlite_path", "domain", "login_redirect_url",
    "github_app_client_id", "github_app_client_secret", "github_client_id", "github_client_secret",
    "google_client_id", "google_client_secret", "cli_auth_base_url"
];
const REQUIRED_KEYS = ["app_name", "main_secret_token", "session_secret_key", "is_deployed", "mbkauth_two_fa_enable", "domain"];

const isPlainObject = (val) => Boolean(val && typeof val === 'object' && !Array.isArray(val));
const isBlank = (val) => val === undefined || val === null || (typeof val === 'string' && val.trim() === '');
const hasValue = (val) => !isBlank(val);

function parseJsonEnv(name, { required = false } = {}) {
    const directKey = Object.keys(process.env).find((k) => k.toLowerCase() === name.toLowerCase());
    const raw = directKey ? process.env[directKey] : undefined;
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

function getPrefixedEnvVars(prefix) {
    const result = {};
    const lowerPrefix = prefix.toLowerCase();
    for (const [key, value] of Object.entries(process.env)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith(`${lowerPrefix}.`)) {
            const subKey = key.slice(prefix.length + 1);
            if (hasValue(value)) result[subKey] = value;
        } else if (lowerKey.startsWith(`${lowerPrefix}_`)) {
            const subKey = key.slice(prefix.length + 1);
            if (hasValue(value)) result[subKey] = value;
        }
    }
    return result;
}

function getSimpleEnvValue(key) {
    const target = normalizeKey(key);
    for (const [envKey, envVal] of Object.entries(process.env)) {
        const lowerEnvKey = envKey.toLowerCase();
        if (lowerEnvKey === 'mbkauthevar' || lowerEnvKey === 'mbkauthshared') continue;
        if (lowerEnvKey.startsWith('mbkauthevar.') || lowerEnvKey.startsWith('mbkauthevar_')) continue;
        if (lowerEnvKey.startsWith('mbkauthshared.') || lowerEnvKey.startsWith('mbkauthshared_')) continue;

        if (normalizeKey(envKey) === target && hasValue(envVal)) {
            return envVal;
        }
    }
    return undefined;
}

function findValue(source, key) {
    if (!source || typeof source !== 'object') return undefined;
    if (source[key] !== undefined) return source[key];
    const target = normalizeKey(key);
    const matchKey = Object.keys(source).find((k) => normalizeKey(k) === target);
    return matchKey !== undefined ? source[matchKey] : undefined;
}

function setBoth(config, lowerKey, upperKey, val) {
    config[lowerKey] = val;
    config[upperKey] = val;
}

function normalizeBooleanFlag(config, lowerKey, upperKey, errors) {
    const value = config[lowerKey];
    if (typeof value === 'boolean') {
        const strVal = value ? 'true' : 'false';
        setBoth(config, lowerKey, upperKey, strVal);
        return;
    }
    const norm = String(value ?? '').trim().toLowerCase();
    if (norm === 'f' || norm === 'false') {
        setBoth(config, lowerKey, upperKey, 'false');
    } else if (norm === 'true') {
        setBoth(config, lowerKey, upperKey, 'true');
    } else if (!isBlank(value)) {
        errors.push(`${upperKey} must be either 'true' or 'false' or 'f'`);
    }
}

function normalizePositiveNumber(config, lowerKey, upperKey, errors, integerOnly = false) {
    const num = Number(config[lowerKey]);
    const valid = Number.isFinite(num) && num > 0 && (!integerOnly || Number.isInteger(num));
    if (!valid) {
        errors.push(`${upperKey} must be a valid positive ${integerOnly ? 'integer' : 'number'}`);
    } else {
        setBoth(config, lowerKey, upperKey, num);
    }
}

function normalizeAndValidateConfig(config, errors) {
    CANONICAL_KEYS.forEach(({ lower, upper }) => {
        if (STRING_KEYS.includes(lower) && hasValue(config[lower])) {
            setBoth(config, lower, upper, String(config[lower]).trim());
        }
    });

    if (hasValue(config.app_name)) {
        setBoth(config, "app_name", "APP_NAME", config.app_name.toLowerCase());
    }

    if (hasValue(config.db_type)) {
        const db_type = config.db_type.toLowerCase();
        setBoth(config, "db_type", "DB_TYPE", db_type);
        if (!["postgres", "sqlite"].includes(db_type)) {
            errors.push("DB_TYPE must be either 'postgres' or 'sqlite'");
        }
    }

    if (hasValue(config.domain)) {
        const domain = config.domain.toLowerCase().replace(/^\.+/, '');
        setBoth(config, "domain", "DOMAIN", domain);
        if (domain.includes('://') || domain.includes('/') || domain.includes(':')) {
            errors.push("DOMAIN must be a hostname only, without protocol, path, or port");
        }
    }

    if (hasValue(config.login_redirect_url)) {
        const redirectUrl = String(config.login_redirect_url).trim();
        setBoth(config, "login_redirect_url", "LOGIN_REDIRECT_URL", redirectUrl);
        if (!redirectUrl.startsWith('/') || redirectUrl.startsWith('//')) {
            errors.push("LOGIN_REDIRECT_URL must be a relative path starting with '/'");
        }
    }

    CANONICAL_KEYS.forEach(({ lower, upper }) => {
        if (BOOLEAN_KEYS.includes(lower)) {
            normalizeBooleanFlag(config, lower, upper, errors);
        }
    });

    normalizePositiveNumber(config, "cookie_expire_time", "COOKIE_EXPIRE_TIME", errors);
    normalizePositiveNumber(config, "device_trust_duration_days", "DEVICE_TRUST_DURATION_DAYS", errors);
    normalizePositiveNumber(config, "max_sessions_per_user", "MAX_SESSIONS_PER_USER", errors, true);
}

function createConfigProxy(target) {
    return new Proxy(target, {
        get(t, prop, receiver) {
            if (typeof prop !== 'string') return Reflect.get(t, prop, receiver);
            if (prop in t) return t[prop];
            const lower = prop.toLowerCase();
            if (lower in t) return t[lower];
            const upper = prop.toUpperCase();
            if (upper in t) return t[upper];
            const norm = normalizeKey(prop);
            const match = Object.keys(t).find((k) => normalizeKey(k) === norm);
            if (match) return t[match];
            return undefined;
        },
        has(t, prop) {
            if (typeof prop !== 'string') return Reflect.has(t, prop);
            if (prop in t) return true;
            const lower = prop.toLowerCase();
            if (lower in t) return true;
            const norm = normalizeKey(prop);
            return Object.keys(t).some((k) => normalizeKey(k) === norm);
        }
    });
}

function resolveRawConfig() {
    const errors = [];
    const usedFromEnv = new Set();
    const usedFromVar = new Set();
    const usedFromShared = new Set();
    const usedDefaults = new Set();

    const mbkautheVarParsed = parseJsonEnv("mbkautheVar") || {};
    const mbkautheVarPrefixed = getPrefixedEnvVars("mbkautheVar");
    const mbkautheVarSource = { ...mbkautheVarParsed, ...mbkautheVarPrefixed };

    const mbkauthSharedParsed = parseJsonEnv("mbkauthShared") || {};
    const mbkauthSharedPrefixed = getPrefixedEnvVars("mbkauthShared");
    const mbkauthSharedSource = { ...mbkauthSharedParsed, ...mbkauthSharedPrefixed };

    const resolved = {};

    // 1. Resolve canonical keys following: VarName > mbkautheVar.VarName > mbkauthShared.VarName > DEFAULT_CONFIG
    CANONICAL_KEYS.forEach(({ lower, upper }) => {
        // Priority 1: Simple flat process.env (VarName)
        const simpleVal = getSimpleEnvValue(lower);
        if (hasValue(simpleVal)) {
            setBoth(resolved, lower, upper, simpleVal);
            usedFromEnv.add(upper);
            return;
        }

        // Priority 2: mbkautheVar.VarName (JSON object or prefixed flat env)
        const varVal = findValue(mbkautheVarSource, lower);
        if (hasValue(varVal)) {
            setBoth(resolved, lower, upper, varVal);
            usedFromVar.add(upper);
            return;
        }

        // Priority 3: mbkauthShared.VarName (JSON object or prefixed flat env)
        const sharedVal = findValue(mbkauthSharedSource, lower);
        if (hasValue(sharedVal)) {
            setBoth(resolved, lower, upper, sharedVal);
            usedFromShared.add(upper);
            return;
        }

        // Priority 4: Default configuration
        const defVal = findValue(DEFAULT_CONFIG, lower);
        if (defVal !== undefined) {
            setBoth(resolved, lower, upper, defVal);
            usedDefaults.add(upper);
        }
    });

    // 2. Pass through any custom/arbitrary keys from mbkauthShared, mbkautheVar, or simple env
    const knownNorms = new Set(CANONICAL_KEYS.map((k) => normalizeKey(k.lower)));

    const resolveCustomKey = (k, sourceVal, sourceTag) => {
        const norm = normalizeKey(k);
        if (knownNorms.has(norm)) return;

        // Check if simple process.env overrides it
        const simpleVal = getSimpleEnvValue(k);
        if (hasValue(simpleVal)) {
            setBoth(resolved, k.toLowerCase(), k.toUpperCase(), simpleVal);
            usedFromEnv.add(k.toUpperCase());
            return;
        }

        // Check if mbkautheVar overrides it
        const varVal = findValue(mbkautheVarSource, k);
        if (hasValue(varVal)) {
            setBoth(resolved, k.toLowerCase(), k.toUpperCase(), varVal);
            usedFromVar.add(k.toUpperCase());
            return;
        }

        // Check if mbkauthShared has it
        const sharedVal = findValue(mbkauthSharedSource, k);
        if (hasValue(sharedVal)) {
            setBoth(resolved, k.toLowerCase(), k.toUpperCase(), sharedVal);
            usedFromShared.add(k.toUpperCase());
        }
    };

    Object.keys(mbkauthSharedSource).forEach((k) => resolveCustomKey(k, mbkauthSharedSource[k], "shared"));
    Object.keys(mbkautheVarSource).forEach((k) => resolveCustomKey(k, mbkautheVarSource[k], "var"));

    normalizeAndValidateConfig(resolved, errors);

    return { resolved, errors, usedFromEnv, usedFromVar, usedFromShared, usedDefaults };
}

function validateConfiguration(options = {}) {
    const throwOnError = typeof options === 'boolean' ? options : (options?.throwOnError ?? true);
    const logSummary = typeof options === 'object' && options?.logSummary !== undefined ? options.logSummary : true;
    const { resolved, errors, usedFromEnv, usedFromVar, usedFromShared, usedDefaults } = resolveRawConfig();

    REQUIRED_KEYS.forEach((key) => {
        if (isBlank(resolved[key])) {
            const upper = key.toUpperCase();
            errors.push(`${upper} is required and cannot be empty`);
        }
    });

    if (resolved.github_login_enabled === "true") {
        if (!(resolved.github_app_client_id || resolved.github_client_id)) {
            errors.push("GITHUB_APP_CLIENT_ID (or GITHUB_CLIENT_ID) is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
        if (!(resolved.github_app_client_secret || resolved.github_client_secret)) {
            errors.push("GITHUB_APP_CLIENT_SECRET (or GITHUB_CLIENT_SECRET) is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
    }

    if (resolved.google_login_enabled === "true") {
        if (isBlank(resolved.google_client_id)) errors.push("GOOGLE_CLIENT_ID is required when GOOGLE_LOGIN_ENABLED is 'true'");
        if (isBlank(resolved.google_client_secret)) errors.push("GOOGLE_CLIENT_SECRET is required when GOOGLE_LOGIN_ENABLED is 'true'");
    }

    if (resolved.db_type === "sqlite") {
        if (isBlank(resolved.sqlite_path)) errors.push("SQLITE_PATH is required and cannot be empty when DB_TYPE is 'sqlite'");
    } else {
        if (isBlank(resolved.login_db)) {
            errors.push("LOGIN_DB is required and cannot be empty when DB_TYPE is 'postgres'");
        } else if (!resolved.login_db.startsWith('postgresql://') && !resolved.login_db.startsWith('postgres://')) {
            errors.push("LOGIN_DB must be a valid PostgreSQL connection string");
        }
    }

    if (errors.length > 0) {
        if (throwOnError) {
            throw new Error(`[mbkauthe] Configuration Validation Failed:\n  - ${errors.join('\n  - ')}`);
        }
    } else if (logSummary) {
        const configParts = [];
        if (usedFromEnv.size > 0) configParts.push(`process.env: ${usedFromEnv.size} keys`);
        if (usedFromVar.size > 0) configParts.push(`mbkautheVar: ${usedFromVar.size} keys`);
        if (usedFromShared.size > 0) configParts.push(`mbkauthShared: ${usedFromShared.size} keys`);
        if (usedDefaults.size > 0) configParts.push(`defaults: ${usedDefaults.size} keys`);
        const configSummary = configParts.length > 0 ? ` (${configParts.join(', ')})` : '';
        logConfig(`Configuration loaded${configSummary}`);
    }

    return Object.freeze(createConfigProxy(resolved));
}

const mbkautheVar = new Proxy({}, {
    get(t, prop, receiver) {
        if (typeof prop !== 'string') return Reflect.get(t, prop, receiver);
        const { resolved } = resolveRawConfig();
        const proxy = createConfigProxy(resolved);
        return proxy[prop];
    },
    has(t, prop) {
        if (typeof prop !== 'string') return Reflect.has(t, prop);
        const { resolved } = resolveRawConfig();
        const proxy = createConfigProxy(resolved);
        return prop in proxy;
    },
    ownKeys(t) {
        const { resolved } = resolveRawConfig();
        return Reflect.ownKeys(resolved);
    },
    getOwnPropertyDescriptor(t, prop) {
        const { resolved } = resolveRawConfig();
        if (prop in resolved) {
            return {
                value: resolved[prop],
                writable: false,
                enumerable: true,
                configurable: true
            };
        }
        return undefined;
    }
});

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

if (mbkautheVar.SESSION_SECRET_KEY) {
    setPasswordPepper(mbkautheVar.SESSION_SECRET_KEY);
}

export { packageJson, appVersion, mbkautheVar, validateConfiguration, findValue, resolveRawConfig };
export { hashPassword, hashApiToken, verifyPassword } from "./security.js";

/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */