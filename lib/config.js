import dotenv from "dotenv";
import crypto from "crypto";
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

    // Validate GitHub login configuration
    if (mbkautheVar.GITHUB_LOGIN_ENABLED === "true") {
        if (!mbkautheVar.GITHUB_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID.trim() === '') {
            errors.push("mbkautheVar.GITHUB_CLIENT_ID is required when GITHUB_LOGIN_ENABLED is 'true'");
        }
        if (!mbkautheVar.GITHUB_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET.trim() === '') {
            errors.push("mbkautheVar.GITHUB_CLIENT_SECRET is required when GITHUB_LOGIN_ENABLED is 'true'");
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
const mbkautheVar = validateConfiguration();

// Shared cookie options functions
const getCookieOptions = () => ({
    maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    secure: mbkautheVar.IS_DEPLOYED === 'true',
    sameSite: 'lax',
    path: '/',
    httpOnly: true
});

const getClearCookieOptions = () => ({
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    secure: mbkautheVar.IS_DEPLOYED === 'true',
    sameSite: 'lax',
    path: '/',
    httpOnly: true
});

// Cache cookie options for performance
const cachedCookieOptions = getCookieOptions();
const cachedClearCookieOptions = getClearCookieOptions();

// Constants for device trust feature
const DEVICE_TRUST_DURATION_DAYS = mbkautheVar.DEVICE_TRUST_DURATION_DAYS;
const DEVICE_TRUST_DURATION_MS = DEVICE_TRUST_DURATION_DAYS * 24 * 60 * 60 * 1000;

// Device token utilities
const generateDeviceToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const getDeviceTokenCookieOptions = () => ({
    maxAge: DEVICE_TRUST_DURATION_MS,
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    secure: mbkautheVar.IS_DEPLOYED === 'true',
    sameSite: 'lax',
    path: '/',
    httpOnly: true
});

// Load package.json from mbkauthe package (not parent project)
const require = createRequire(import.meta.url);
let packageJson;
try {
    // Try to load from mbkauthe package directory
    packageJson = require("mbkauthe/package.json");
} catch {
    // Fallback to relative path (for development/testing)
    packageJson = require("../package.json");
}

// Helper function to render error pages consistently
const renderError = (res, { code, error, message, page, pagename, details }) => {
    const renderData = {
        layout: false,
        code,
        error,
        message,
        page,
        pagename,
        app: mbkautheVar.APP_NAME,
        version: packageJson.version
    };

    // Add optional parameters if provided
    if (details !== undefined) renderData.details = details;

    return res.render("Error/dError.handlebars", renderData);
};

// Helper to clear all session cookies
const clearSessionCookies = (res) => {
    res.clearCookie("mbkauthe.sid", cachedClearCookieOptions);
    res.clearCookie("sessionId", cachedClearCookieOptions);
    res.clearCookie("username", cachedClearCookieOptions);
    res.clearCookie("device_token", cachedClearCookieOptions);
};

export {
    mbkautheVar,
    getCookieOptions,
    getClearCookieOptions,
    cachedCookieOptions,
    cachedClearCookieOptions,
    renderError,
    clearSessionCookies,
    packageJson,
    DEVICE_TRUST_DURATION_DAYS,
    DEVICE_TRUST_DURATION_MS,
    generateDeviceToken,
    getDeviceTokenCookieOptions
};
