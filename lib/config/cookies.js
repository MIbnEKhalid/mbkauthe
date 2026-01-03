import crypto from "crypto";
import { mbkautheVar } from "./index.js";

// Maximum number of remembered accounts per device
const MAX_REMEMBERED_ACCOUNTS = 5;
const ACCOUNT_LIST_COOKIE = 'mbkauthe_accounts';

// Cookie security: encryption and signing
const COOKIE_ENCRYPTION_KEY = mbkautheVar.SESSION_SECRET || 'fallback-secret-key-change-this';
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

// Derive encryption key from session secret
const getEncryptionKey = () => {
    return crypto.createHash('sha256').update(COOKIE_ENCRYPTION_KEY).digest();
};

// Encrypt and sign cookie payload
const encryptCookiePayload = (data) => {
    try {
        const iv = crypto.randomBytes(16);
        const key = getEncryptionKey();
        const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        // Combine iv + authTag + encrypted data
        return {
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            data: encrypted
        };
    } catch (error) {
        console.error('[mbkauthe] Cookie encryption error:', error);
        return null;
    }
};

// Decrypt and verify cookie payload
const decryptCookiePayload = (payload) => {
    try {
        if (!payload || !payload.iv || !payload.authTag || !payload.data) {
            return null;
        }

        const key = getEncryptionKey();
        const decipher = crypto.createDecipheriv(
            ENCRYPTION_ALGORITHM,
            key,
            Buffer.from(payload.iv, 'hex')
        );

        decipher.setAuthTag(Buffer.from(payload.authTag, 'hex'));

        let decrypted = decipher.update(payload.data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return JSON.parse(decrypted);
    } catch (error) {
        console.error('[mbkauthe] Cookie decryption error:', error);
        return null;
    }
};

// Generate fingerprint from user-agent only (salted)
const generateFingerprint = (req) => {
    const userAgent = req.headers['user-agent'] || '';
    // Use SESSION_SECRET_KEY as salt if available, otherwise fallback to encryption key
    const salt = mbkautheVar.SESSION_SECRET_KEY || COOKIE_ENCRYPTION_KEY;

    // Hash user-agent with salt to prevent rainbow table attacks on UAs
    return crypto
        .createHash('sha256')
        .update(`${userAgent}:${salt}`)
        .digest('hex')
        .substring(0, 32);
};

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

// ---- Multi-account helpers ----
const parseAccountList = (raw, req) => {
    if (!raw) return [];
    try {
        // First, decrypt the cookie payload
        const parsed = JSON.parse(raw);
        const decrypted = decryptCookiePayload(parsed);

        if (!decrypted || !decrypted.accounts || !decrypted.fingerprint) {
            return [];
        }

        // Verify fingerprint matches current request
        const currentFingerprint = generateFingerprint(req);
        if (decrypted.fingerprint !== currentFingerprint) {
            console.warn('[mbkauthe] Cookie fingerprint mismatch - possible cookie theft attempt');
            return [];
        }

        const accounts = decrypted.accounts;
        if (!Array.isArray(accounts)) return [];

        // Accept only minimal safe fields
        return accounts
            .filter(item => item && typeof item === 'object')
            .map(item => ({
                sessionId: typeof item.sessionId === 'string' ? item.sessionId : null,
                username: typeof item.username === 'string' ? item.username : null,
                fullName: typeof item.fullName === 'string' ? item.fullName : null
            }))
            .filter(item => item.sessionId && item.username)
            .slice(0, MAX_REMEMBERED_ACCOUNTS);
    } catch (error) {
        console.error('[mbkauthe] Error parsing account list:', error);
        return [];
    }
};

const writeAccountList = (res, list, req) => {
    const sanitized = Array.isArray(list) ? list.slice(0, MAX_REMEMBERED_ACCOUNTS) : [];

    // Create payload with fingerprint
    const payload = {
        accounts: sanitized,
        fingerprint: generateFingerprint(req)
    };

    // Encrypt the payload
    const encrypted = encryptCookiePayload(payload);
    if (!encrypted) {
        console.error('[mbkauthe] Failed to encrypt account list cookie');
        return;
    }

    res.cookie(ACCOUNT_LIST_COOKIE, JSON.stringify(encrypted), cachedCookieOptions);
};

export const readAccountListFromCookie = (req) => {
    const raw = req?.cookies ? req.cookies[ACCOUNT_LIST_COOKIE] : null;
    return parseAccountList(raw, req);
};

export const upsertAccountListCookie = (req, res, entry) => {
    if (!entry || !entry.sessionId || !entry.username) return;
    const current = readAccountListFromCookie(req);
    const filtered = current.filter(item => item.sessionId !== entry.sessionId && item.username !== entry.username);
    const next = [{ sessionId: entry.sessionId, username: entry.username, fullName: entry.fullName || entry.username }, ...filtered];
    writeAccountList(res, next, req);
};

export const removeAccountFromCookie = (req, res, sessionId) => {
    const current = readAccountListFromCookie(req);
    const next = current.filter(item => item.sessionId !== sessionId);
    writeAccountList(res, next, req);
};

export const clearAccountListCookie = (res) => {
    res.clearCookie(ACCOUNT_LIST_COOKIE, cachedClearCookieOptions);
};
