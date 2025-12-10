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

    // Parse and validate oAuthVar (optional fallback for OAuth settings)
    let oAuthVar = null;
    try {
        if (process.env.oAuthVar) {
            oAuthVar = JSON.parse(process.env.oAuthVar);
            if (oAuthVar && typeof oAuthVar !== 'object') {
                console.warn('[mbkauthe] oAuthVar is not a valid object, ignoring it');
                oAuthVar = null;
            } else {
                console.log('[mbkauthe] oAuthVar detected and parsed successfully');
            }
        }
    } catch (error) {
        console.warn('[mbkauthe] Invalid JSON in process.env.oAuthVar, ignoring it');
        oAuthVar = null;
    }

    // Merge OAuth settings: use oAuthVar as fallback if values not in mbkautheVar
    const oAuthKeys = [
        'GITHUB_LOGIN_ENABLED', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
        'GOOGLE_LOGIN_ENABLED', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'
    ];
    
    if (oAuthVar) {
        oAuthKeys.forEach(key => {
            if ((!mbkautheVar[key] || (typeof mbkautheVar[key] === 'string' && mbkautheVar[key].trim() === '')) && oAuthVar[key]) {
                mbkautheVar[key] = oAuthVar[key];
                console.log(`[mbkauthe] Using ${key} from oAuthVar`);
            }
        });
    }

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
    if (mbkautheVar.IS_DEPLOYED && !['true', 'false', 'f'].includes(mbkautheVar.IS_DEPLOYED)) {
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