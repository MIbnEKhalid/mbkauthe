import dotenv from "dotenv";
import { createRequire } from "module";

dotenv.config();

// Comprehensive validation function
function validateConfiguration() {
    const errors = [];

    // Parse and validate mbkautheVar
    let mbkautheVar;
    try {
        if (!process.env.mbkautheVar) {
            errors.push("process.env.mbkautheVar is not defined");
            throw new Error("Configuration validation failed");
        }
        mbkautheVar = JSON.parse(process.env.mbkautheVar);
    } catch (error) {
        if (error.message === "Configuration validation failed") {
            throw new Error(`[mbkauthe] Configuration Error:\n  - ${errors.join('\n  - ')}`);
        }
        errors.push("Invalid JSON in process.env.mbkautheVar");
        throw new Error(`[mbkauthe] Configuration Error:\n  - ${errors.join('\n  - ')}`);
    }

    if (!mbkautheVar || typeof mbkautheVar !== 'object') {
        errors.push("mbkautheVar must be a valid object");
        throw new Error(`[mbkauthe] Configuration Error:\n  - ${errors.join('\n  - ')}`);
    }

    // Parse and validate mbkauthShared (optional fallback for shared settings)
    let mbkauthShared = null;
    try {
        if (process.env.mbkauthShared) {
            mbkauthShared = JSON.parse(process.env.mbkauthShared);
            if (mbkauthShared && typeof mbkauthShared !== 'object') {
                console.warn('[mbkauthe] mbkauthShared is not a valid object, ignoring it');
                mbkauthShared = null;
            } else {
                console.log('[mbkauthe] mbkauthShared detected and parsed successfully');
            }
        }
    } catch (error) {
        console.warn('[mbkauthe] Invalid JSON in process.env.mbkauthShared, ignoring it');
        mbkauthShared = null;
    }

    // Merge fallback settings: for any key missing or empty in mbkautheVar, check mbkauthShared
    const applyFallback = (source, sourceName) => {
        if (!source) return;
        Object.keys(source).forEach(key => {
            const val = source[key];
            if ((mbkautheVar[key] === undefined || (typeof mbkautheVar[key] === 'string' && mbkautheVar[key].trim() === '')) &&
                val !== undefined && !(typeof val === 'string' && val.trim() === '')) {
                mbkautheVar[key] = val;
                console.log(`[mbkauthe] Using ${key} from ${sourceName}`);
            }
        });
    };

    applyFallback(mbkauthShared, 'mbkauthShared');

    // Ensure specific keys are checked in mbkautheVar first, then mbkauthShared, then apply config defaults
    const keysToCheck = [
        "APP_NAME","DEVICE_TRUST_DURATION_DAYS","EncPass","Main_SECRET_TOKEN","SESSION_SECRET_KEY",
        "IS_DEPLOYED","LOGIN_DB","MBKAUTH_TWO_FA_ENABLE","COOKIE_EXPIRE_TIME","DOMAIN","loginRedirectURL",
        "GITHUB_LOGIN_ENABLED","GITHUB_CLIENT_ID","GITHUB_CLIENT_SECRET","GOOGLE_LOGIN_ENABLED","GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET","MAX_SESSIONS_PER_USER"
    ];

    const defaults = {
        DEVICE_TRUST_DURATION_DAYS: 7,
        EncPass: 'false',
        IS_DEPLOYED: 'false',
        MBKAUTH_TWO_FA_ENABLE: 'false',
        COOKIE_EXPIRE_TIME: 2,
        loginRedirectURL: '/dashboard',
        GITHUB_LOGIN_ENABLED: 'false',
        GOOGLE_LOGIN_ENABLED: 'false',
        MAX_SESSIONS_PER_USER: 5
    };

    keysToCheck.forEach(key => {
        const current = mbkautheVar[key];
        const isEmpty = current === undefined || (typeof current === 'string' && current.trim() === '');
        if (isEmpty) {
            if (mbkauthShared && mbkauthShared[key] !== undefined && !(typeof mbkauthShared[key] === 'string' && mbkauthShared[key].trim() === '')) {
                mbkautheVar[key] = mbkauthShared[key];
                console.log(`[mbkauthe] Using ${key} from mbkauthShared`);
            } else if (defaults[key] !== undefined) {
                mbkautheVar[key] = defaults[key];
                console.log(`[mbkauthe] Using default value for ${key}`);
            }
        }
    });

    // Normalize boolean-like values to consistent lowercase 'true'/'false' strings
    ['GITHUB_LOGIN_ENABLED','GOOGLE_LOGIN_ENABLED','MBKAUTH_TWO_FA_ENABLE','IS_DEPLOYED','EncPass'].forEach(k => {
        const val = mbkautheVar[k];
        if (typeof val === 'boolean') {
            mbkautheVar[k] = val ? 'true' : 'false';
        } else if (typeof val === 'string') {
            const norm = val.trim().toLowerCase();
            // Accept 'f' as shorthand for false but normalize it to 'false'
            mbkautheVar[k] = (norm === 'f') ? 'false' : norm;
        }
    });

    // Validate required keys
    // COOKIE_EXPIRE_TIME is not required but if provided must be valid, COOKIE_EXPIRE_TIME by default is 2 days
    // loginRedirectURL is not required but if provided must be valid, loginRedirectURL by default is /dashboard
    const requiredKeys = ["APP_NAME", "Main_SECRET_TOKEN", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB",
        "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];
    
    requiredKeys.forEach(key => {
        if (!mbkautheVar[key] || (typeof mbkautheVar[key] === 'string' && mbkautheVar[key].trim() === '')) {
            errors.push(`mbkautheVar.${key} is required and cannot be empty`);
        }
    });

    // Validate IS_DEPLOYED value
    if (mbkautheVar.IS_DEPLOYED && !['true', 'false', 'f'].includes((mbkautheVar.IS_DEPLOYED + '').toLowerCase())) {
        errors.push("mbkautheVar.IS_DEPLOYED must be either 'true' or 'false' or 'f'");
    }

    // Validate MBKAUTH_TWO_FA_ENABLE value
    if (mbkautheVar.MBKAUTH_TWO_FA_ENABLE && !['true', 'false', 'f'].includes(mbkautheVar.MBKAUTH_TWO_FA_ENABLE.toLowerCase())) {
        errors.push("mbkautheVar.MBKAUTH_TWO_FA_ENABLE must be either 'true' or 'false' or 'f'");
    }

    // Validate GITHUB_LOGIN_ENABLED value
    if (mbkautheVar.GITHUB_LOGIN_ENABLED && !['true', 'false', 'f'].includes(mbkautheVar.GITHUB_LOGIN_ENABLED.toLowerCase())) {
        errors.push("mbkautheVar.GITHUB_LOGIN_ENABLED must be either 'true' or 'false' or 'f'");
    }

    // Validate GOOGLE_LOGIN_ENABLED value
    if (mbkautheVar.GOOGLE_LOGIN_ENABLED && !['true', 'false', 'f'].includes(mbkautheVar.GOOGLE_LOGIN_ENABLED.toLowerCase())) {
        errors.push("mbkautheVar.GOOGLE_LOGIN_ENABLED must be either 'true' or 'false' or 'f'");
    }

    // Validate EncPass value if provided
    if (mbkautheVar.EncPass && !['true', 'false', 'f'].includes(mbkautheVar.EncPass.toLowerCase())) {
        errors.push("mbkautheVar.EncPass must be either 'true' or 'false' or 'f'");
    }

    // Validate GitHub login configuration
    if (mbkautheVar.GITHUB_LOGIN_ENABLED === "true") {
        if (!mbkautheVar.GITHUB_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID.trim() === '') {
            errors.push("mbkautheVar.GITHUB_CLIENT_ID is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
        if (!mbkautheVar.GITHUB_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET.trim() === '') {
            errors.push("mbkautheVar.GITHUB_CLIENT_SECRET is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
    }

    // Validate Google login configuration
    if (mbkautheVar.GOOGLE_LOGIN_ENABLED === "true") {
        if (!mbkautheVar.GOOGLE_CLIENT_ID || mbkautheVar.GOOGLE_CLIENT_ID.trim() === '') {
            errors.push("mbkautheVar.GOOGLE_CLIENT_ID is required when GOOGLE_LOGIN_ENABLED is 'true'");
        }
        if (!mbkautheVar.GOOGLE_CLIENT_SECRET || mbkautheVar.GOOGLE_CLIENT_SECRET.trim() === '') {
            errors.push("mbkautheVar.GOOGLE_CLIENT_SECRET is required when GOOGLE_LOGIN_ENABLED is 'true'");
        }
    }

    // Validate COOKIE_EXPIRE_TIME if provided
    if (mbkautheVar.COOKIE_EXPIRE_TIME !== undefined) {
        const expireTime = parseFloat(mbkautheVar.COOKIE_EXPIRE_TIME);
        if (isNaN(expireTime) || expireTime <= 0) {
            errors.push("mbkautheVar.COOKIE_EXPIRE_TIME must be a valid positive number");
        }
    } else {
        // Set default value
        mbkautheVar.COOKIE_EXPIRE_TIME = 2;
    }

    // Validate DEVICE_TRUST_DURATION_DAYS if provided
    if (mbkautheVar.DEVICE_TRUST_DURATION_DAYS !== undefined) {
        const trustDuration = parseFloat(mbkautheVar.DEVICE_TRUST_DURATION_DAYS);
        if (isNaN(trustDuration) || trustDuration <= 0) {
            errors.push("mbkautheVar.DEVICE_TRUST_DURATION_DAYS must be a valid positive number");
        }
    } else {
        // Set default value
        mbkautheVar.DEVICE_TRUST_DURATION_DAYS = 7;
    }

    // Validate MAX_SESSIONS_PER_USER if provided (must be positive integer)
    if (mbkautheVar.MAX_SESSIONS_PER_USER !== undefined) {
        const maxSessions = parseInt(mbkautheVar.MAX_SESSIONS_PER_USER, 10);
        if (isNaN(maxSessions) || maxSessions <= 0) {
            errors.push("mbkautheVar.MAX_SESSIONS_PER_USER must be a valid positive integer");
        } else {
            // Normalize to integer
            mbkautheVar.MAX_SESSIONS_PER_USER = maxSessions;
        }
    } else {
        // Ensure default value is set
        mbkautheVar.MAX_SESSIONS_PER_USER = 5;
    }

    // Validate LOGIN_DB connection string format
    if (mbkautheVar.LOGIN_DB && !mbkautheVar.LOGIN_DB.startsWith('postgresql://') && !mbkautheVar.LOGIN_DB.startsWith('postgres://')) {
        errors.push("mbkautheVar.LOGIN_DB must be a valid PostgreSQL connection string");
    }

    // If there are validation errors, throw them all at once
    if (errors.length > 0) {
        throw new Error(`[mbkauthe] Configuration Validation Failed:\n  - ${errors.join('\n  - ')}`);
    }

    console.log('[mbkauthe] Configuration validation passed successfully');
    return mbkautheVar;
}

// Parse and validate mbkautheVar once
export const mbkautheVar = validateConfiguration();

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

export { packageJson, appVersion };