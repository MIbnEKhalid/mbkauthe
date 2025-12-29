import crypto from "crypto";
import { mbkautheVar } from "./index.js";

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
export const cachedCookieOptions = getCookieOptions();
export const cachedClearCookieOptions = getClearCookieOptions();

// Constants for device trust feature
export const DEVICE_TRUST_DURATION_DAYS = mbkautheVar.DEVICE_TRUST_DURATION_DAYS;
export const DEVICE_TRUST_DURATION_MS = DEVICE_TRUST_DURATION_DAYS * 24 * 60 * 60 * 1000;

// Device token utilities
export const generateDeviceToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Hash a device token for safe storage in the database
export const hashDeviceToken = (token) => {
    if (!token || typeof token !== 'string') return null;
    return crypto.createHmac('sha256').update(token).digest('hex');
};

export const getDeviceTokenCookieOptions = () => ({
    maxAge: DEVICE_TRUST_DURATION_MS,
    domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
    secure: mbkautheVar.IS_DEPLOYED === 'true',
    sameSite: 'lax',
    path: '/',
    httpOnly: true
});

// Helper to clear all session cookies
export const clearSessionCookies = (res) => {
    res.clearCookie("mbkauthe.sid", cachedClearCookieOptions);
    res.clearCookie("sessionId", cachedClearCookieOptions);
    res.clearCookie("username", cachedClearCookieOptions);
    res.clearCookie("fullName", cachedClearCookieOptions);
    res.clearCookie("device_token", cachedClearCookieOptions);
};

export { getCookieOptions, getClearCookieOptions };
