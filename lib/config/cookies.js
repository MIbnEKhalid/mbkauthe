import crypto from "crypto";
import { mbkautheVar } from "#config.js";

// Maximum number of remembered accounts per device
const MAX_REMEMBERED_ACCOUNTS = 5;
const ACCOUNT_LIST_COOKIE = 'mbkauthe_accounts';

// Cookie security: encryption and signing
const COOKIE_ENCRYPTION_KEY = mbkautheVar.SESSION_SECRET_KEY;
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

// Derive encryption key from session secret
const getEncryptionKey = () => {
    return crypto.createHash('sha256').update(COOKIE_ENCRYPTION_KEY).digest();
};

const getSigningKey = () => {
    return crypto.createHash('sha256').update(`${COOKIE_ENCRYPTION_KEY}:cookie-signing`).digest();
};

const encodePayload = (data) => {
    return Buffer.from(JSON.stringify(data), 'utf8').toString('base64url');
};

const decodePayload = (encoded) => {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
};

const signCookiePayload = (encodedPayload) => {
    return crypto.createHmac('sha256', getSigningKey()).update(encodedPayload).digest('hex');
};

const verifyCookieSignature = (encodedPayload, signature) => {
    if (!encodedPayload || !signature || typeof encodedPayload !== 'string' || typeof signature !== 'string') {
        return false;
    }

    const expected = signCookiePayload(encodedPayload);
    const expectedBuffer = Buffer.from(expected, 'hex');
    const actualBuffer = Buffer.from(signature, 'hex');

    return expectedBuffer.length === actualBuffer.length && crypto.timingSafeEqual(expectedBuffer, actualBuffer);
};

const createSignedCookiePayload = (data) => {
    try {
        const payload = encodePayload(data);
        return {
            payload,
            signature: signCookiePayload(payload)
        };
    } catch (error) {
        console.error(`[mbkauthe] Cookie signing error:`, error);
        return null;
    }
};

const parseSignedCookiePayload = (signedPayload) => {
    try {
        if (!signedPayload || !verifyCookieSignature(signedPayload.payload, signedPayload.signature)) {
            return null;
        }

        return decodePayload(signedPayload.payload);
    } catch (error) {
        console.error(`[mbkauthe] Cookie signature verification error:`, error);
        return null;
    }
};

// Encrypt and sign cookie payload
const encryptCookiePayload = (data) => {
    try {
        const iv = crypto.randomBytes(12);
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
        console.error(`[mbkauthe] Cookie encryption error:`, error);
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
        console.error(`[mbkauthe] Cookie decryption error:`, error);
        return null;
    }
};

// Generate fingerprint from user-agent only (salted)
const generateFingerprint = (req) => {
    const userAgent = req.headers['user-agent'] || '';
    const salt = mbkautheVar.SESSION_SECRET_KEY;

    // Hash user-agent with salt to prevent rainbow table attacks on UAs
    return crypto
        .createHash('sha256')
        .update(`${userAgent}:${salt}`)
        .digest('hex')
        .substring(0, 32);
};

// Encrypt sessionId for cookie storage
export const encryptSessionId = (sessionId) => {
    if (!sessionId) return null;
    const encrypted = encryptCookiePayload({ sessionId });
    return encrypted ? JSON.stringify(encrypted) : null;
};

// Decrypt sessionId from cookie
export const decryptSessionId = (encryptedSessionId) => {
    if (!encryptedSessionId) return null;
    try {
        const parsed = JSON.parse(encryptedSessionId);
        const decrypted = decryptCookiePayload(parsed);
        return decrypted?.sessionId || null;
    } catch (error) {
        console.error(`[mbkauthe] SessionId decryption error:`, error);
        return null;
    }
};

const isTestDevEnvironment = () => process.env.test === 'dev';

export const resolveCookieDomain = (isDeployed, domain, isTestDev = isTestDevEnvironment()) => {
    if (isDeployed !== 'true' || isTestDev || !domain) {
        return undefined;
    }

    return `.${String(domain).replace(/^\.+/, '')}`;
};

export const getCookieDomain = () => resolveCookieDomain(mbkautheVar.IS_DEPLOYED, mbkautheVar.DOMAIN);

export const getCookieSecure = () => mbkautheVar.IS_DEPLOYED === 'true' && !isTestDevEnvironment();

export const isAllowedOriginHostname = (hostname, domain = mbkautheVar.DOMAIN) => {
    if (!hostname || !domain) {
        return false;
    }

    return hostname === domain || hostname.endsWith(`.${domain}`);
};

// Shared cookie options functions
const getCookieOptions = () => ({
    maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
    domain: getCookieDomain(),
    secure: getCookieSecure(),
    sameSite: 'lax',
    path: '/',
    httpOnly: true
});

const getClearCookieOptions = () => ({
    domain: getCookieDomain(),
    secure: getCookieSecure(),
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

const getDeviceTokenKey = () => {
    return crypto.createHash('sha256').update(`${mbkautheVar.SESSION_SECRET_KEY}:device-token`).digest();
};

// Hash a device token for safe storage in the database
export const hashDeviceToken = (token) => {
    if (!token || typeof token !== 'string') return null;
    return crypto.createHmac('sha256', getDeviceTokenKey()).update(token).digest('hex');
};

export const getDeviceTokenCookieOptions = () => ({
    maxAge: DEVICE_TRUST_DURATION_MS,
    domain: getCookieDomain(),
    secure: getCookieSecure(),
    sameSite: 'lax',
    path: '/',
    httpOnly: true
});

// Helper to clear all session cookies
export const clearSessionCookies = (res) => {
    res.clearCookie("mbkauthe.sid", cachedClearCookieOptions);
    res.clearCookie("sessionId", cachedClearCookieOptions);
    res.clearCookie("fullName", cachedClearCookieOptions);
    res.clearCookie("profileImageUrl", cachedClearCookieOptions);
    res.clearCookie("profileImageUser", cachedClearCookieOptions);
    res.clearCookie("device_token", cachedClearCookieOptions);
};

export { getCookieOptions, getClearCookieOptions };

// ---- Multi-account helpers ----
const parseAccountList = (raw, req) => {
    if (!raw) return [];
    try {
        const parsed = JSON.parse(raw);
        let data = parseSignedCookiePayload(parsed);
        let isLegacyEncryptedCookie = false;

        // Backward compatibility for previously encrypted account-list cookies.
        if (!data && parsed.iv && parsed.authTag && parsed.data) {
            data = decryptCookiePayload(parsed);
            isLegacyEncryptedCookie = true;
        }

        if (!data || !data.accounts || !data.fingerprint) {
            return [];
        }

        // Verify fingerprint matches current request
        const currentFingerprint = generateFingerprint(req);
        if (data.fingerprint !== currentFingerprint) {
            console.warn(`[mbkauthe] Cookie fingerprint mismatch - possible cookie theft attempt`);
            return [];
        }

        const accounts = data.accounts;
        if (!Array.isArray(accounts)) return [];

        // Accept only minimal safe fields
        return accounts
            .filter(item => item && typeof item === 'object')
            .map(item => {
                const rawSessionId = typeof item.sessionId === 'string' ? item.sessionId : null;
                const sessionId = isLegacyEncryptedCookie
                    ? rawSessionId
                    : decryptSessionId(rawSessionId);

                return {
                    sessionId,
                    username: typeof item.username === 'string' ? item.username : null,
                    fullName: typeof item.fullName === 'string' ? item.fullName : null,
                    image: typeof item.image === 'string' ? item.image : null
                };
            })
            .filter(item => item.sessionId && item.username)
            .slice(0, MAX_REMEMBERED_ACCOUNTS);
    } catch (error) {
        console.error(`[mbkauthe] Error parsing account list:`, error);
        return [];
    }
};

const writeAccountList = (res, list, req) => {
    const sanitized = Array.isArray(list) ? list.slice(0, MAX_REMEMBERED_ACCOUNTS) : [];

    // Clean and limit fields to safe values (limit image URL length)
    const cleaned = sanitized.map(item => ({
        sessionId: item && item.sessionId ? encryptSessionId(item.sessionId) : null,
        username: item && item.username ? item.username : null,
        fullName: item && item.fullName ? item.fullName : null,
        image: (item && typeof item.image === 'string' && item.image.length <= 2048) ? item.image : null
    })).filter(i => i && i.sessionId && i.username);

    // Create payload with fingerprint
    const payload = {
        accounts: cleaned,
        fingerprint: generateFingerprint(req)
    };

    const signed = createSignedCookiePayload(payload);
    if (!signed) {
        console.error(`[mbkauthe] Failed to sign account list cookie`);
        return;
    }

    res.cookie(ACCOUNT_LIST_COOKIE, JSON.stringify(signed), cachedCookieOptions);
};

export const readAccountListFromCookie = (req) => {
    const raw = req?.cookies ? req.cookies[ACCOUNT_LIST_COOKIE] : null;
    return parseAccountList(raw, req);
};

export const upsertAccountListCookie = (req, res, entry) => {
    if (!entry || !entry.sessionId || !entry.username) return;
    const current = readAccountListFromCookie(req);
    const filtered = current.filter(item => item.sessionId !== entry.sessionId && item.username !== entry.username);
    const next = [{ sessionId: entry.sessionId, username: entry.username, fullName: entry.fullName || entry.username, image: entry.image || null }, ...filtered];
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