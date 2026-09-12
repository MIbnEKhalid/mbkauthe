import crypto from "node:crypto";
import { mbkautheVar } from "#config.js";

const MAX_REMEMBERED_ACCOUNTS = 5;
const ACCOUNT_LIST_COOKIE = "mbkauthe_accounts";
const COOKIE_ENCRYPTION_KEY = mbkautheVar.SESSION_SECRET_KEY;
const ENCRYPTION_ALGORITHM = "aes-256-gcm";

const sha256 = (val) => crypto.createHash("sha256").update(val).digest();
const getEncryptionKey = () => sha256(COOKIE_ENCRYPTION_KEY);
const getSigningKey = () => sha256(`${COOKIE_ENCRYPTION_KEY}:cookie-signing`);

const encodePayload = (data) => Buffer.from(JSON.stringify(data), "utf8").toString("base64url");
const decodePayload = (encoded) => JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));

const signCookiePayload = (encodedPayload) =>
  crypto.createHmac("sha256", getSigningKey()).update(encodedPayload).digest("hex");

const verifyCookieSignature = (encodedPayload, signature) => {
  if (!encodedPayload || !signature || typeof encodedPayload !== "string" || typeof signature !== "string") return false;
  const expected = Buffer.from(signCookiePayload(encodedPayload), "hex");
  const actual = Buffer.from(signature, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
};

const createSignedCookiePayload = (data) => {
  try {
    const payload = encodePayload(data);
    return { payload, signature: signCookiePayload(payload) };
  } catch (error) {
    console.error("[mbkauthe] Cookie signing error:", error);
    return null;
  }
};

const parseSignedCookiePayload = (signedPayload) => {
  try {
    if (!signedPayload || !verifyCookieSignature(signedPayload.payload, signedPayload.signature)) return null;
    return decodePayload(signedPayload.payload);
  } catch (error) {
    console.error("[mbkauthe] Cookie signature verification error:", error);
    return null;
  }
};

const encryptCookiePayload = (data) => {
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
    let encrypted = cipher.update(JSON.stringify(data), "utf8", "hex") + cipher.final("hex");
    return { iv: iv.toString("hex"), authTag: cipher.getAuthTag().toString("hex"), data: encrypted };
  } catch (error) {
    console.error("[mbkauthe] Cookie encryption error:", error);
    return null;
  }
};

const decryptCookiePayload = (payload) => {
  try {
    if (!payload?.iv || !payload?.authTag || !payload?.data) return null;
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), Buffer.from(payload.iv, "hex"));
    decipher.setAuthTag(Buffer.from(payload.authTag, "hex"));
    return JSON.parse(decipher.update(payload.data, "hex", "utf8") + decipher.final("utf8"));
  } catch (error) {
    console.error("[mbkauthe] Cookie decryption error:", error);
    return null;
  }
};

const generateFingerprint = (req) =>
  crypto.createHash("sha256").update(`${req.headers["user-agent"] || ""}:${mbkautheVar.SESSION_SECRET_KEY}`).digest("hex").slice(0, 32);

export const encryptSessionId = (session_id) => {
  if (!session_id) return null;
  const encrypted = encryptCookiePayload({ session_id });
  return encrypted ? JSON.stringify(encrypted) : null;
};

export const decryptSessionId = (encrypted_session_id) => {
  if (!encrypted_session_id) return null;
  try {
    const payload = typeof encrypted_session_id === "string" ? JSON.parse(encrypted_session_id) : encrypted_session_id;
    return decryptCookiePayload(payload)?.session_id || null;
  } catch (error) {
    console.error("[mbkauthe] Session ID decryption error:", error);
    return null;
  }
};

const isTestDevEnvironment = () => process.env.test === "dev";

export const resolveCookieDomain = (isDeployed, domain, isTestDev = isTestDevEnvironment()) =>
  isDeployed !== "true" || isTestDev || !domain ? undefined : `.${String(domain).replace(/^\.+/, "")}`;

export const getCookieDomain = () => resolveCookieDomain(mbkautheVar.IS_DEPLOYED, mbkautheVar.DOMAIN);
export const getCookieSecure = () => mbkautheVar.IS_DEPLOYED === "true" && !isTestDevEnvironment();

export const isAllowedOriginHostname = (hostname, domain = mbkautheVar.DOMAIN) =>
  Boolean(hostname && domain && (hostname === domain || hostname.endsWith(`.${domain}`)));

const createCookieOptions = (maxAge) => ({
  ...(maxAge !== undefined && { maxAge }),
  domain: getCookieDomain(),
  secure: getCookieSecure(),
  sameSite: "lax",
  path: "/",
  httpOnly: true,
});

export const getCookieOptions = () => createCookieOptions(mbkautheVar.COOKIE_EXPIRE_TIME * 86400000);
export const getClearCookieOptions = () => createCookieOptions();

export const cachedCookieOptions = getCookieOptions();
export const cachedClearCookieOptions = getClearCookieOptions();

export const DEVICE_TRUST_DURATION_DAYS = mbkautheVar.DEVICE_TRUST_DURATION_DAYS;
export const DEVICE_TRUST_DURATION_MS = DEVICE_TRUST_DURATION_DAYS * 86400000;

export const generateDeviceToken = () => crypto.randomBytes(32).toString("hex");
const getDeviceTokenKey = () => sha256(`${mbkautheVar.SESSION_SECRET_KEY}:device-token`);

export const hashDeviceToken = (device_token) =>
  typeof device_token === "string" && device_token
    ? crypto.createHmac("sha256", getDeviceTokenKey()).update(device_token).digest("hex")
    : null;

export const getDeviceTokenCookieOptions = () => createCookieOptions(DEVICE_TRUST_DURATION_MS);

export const clearSessionCookies = (res) => {
  ["mbkauthe.sid", "session_id", "full_name", "profile_image_url", "profile_image_user", "device_token", "last_login_method"]
    .forEach((cookie) => res.clearCookie(cookie, cachedClearCookieOptions));
};


const parseAccountList = (raw, req) => {
  if (!raw) return [];
  try {
    const data = parseSignedCookiePayload(JSON.parse(raw));
    if (!data?.accounts || !data?.fingerprint || data.fingerprint !== generateFingerprint(req)) {
      if (data?.fingerprint) console.warn("[mbkauthe] Cookie fingerprint mismatch - possible cookie theft attempt");
      return [];
    }
    if (!Array.isArray(data.accounts)) return [];
    return data.accounts
      .filter((item) => item && typeof item === "object")
      .map(({ session_id, username, full_name, image }) => ({
        session_id: typeof session_id === "string" ? decryptSessionId(session_id) : null,
        username: typeof username === "string" ? username : null,
        full_name: typeof full_name === "string" ? full_name : null,
        image: typeof image === "string" ? image : null,
      }))
      .filter((item) => item.session_id && item.username)
      .slice(0, MAX_REMEMBERED_ACCOUNTS);
  } catch (error) {
    console.error("[mbkauthe] Error parsing account list:", error);
    return [];
  }
};

const writeAccountList = (res, list, req) => {
  const cleaned = (Array.isArray(list) ? list.slice(0, MAX_REMEMBERED_ACCOUNTS) : [])
    .map((item) => ({
      session_id: item?.session_id ? encryptSessionId(item.session_id) : null,
      username: item?.username || null,
      full_name: item?.full_name || null,
      image: typeof item?.image === "string" && item.image.length <= 2048 ? item.image : null,
    }))
    .filter((i) => i.session_id && i.username);

  const signed = createSignedCookiePayload({ accounts: cleaned, fingerprint: generateFingerprint(req) });
  if (signed) {
    res.cookie(ACCOUNT_LIST_COOKIE, JSON.stringify(signed), cachedCookieOptions);
  } else {
    console.error("[mbkauthe] Failed to sign account list cookie");
  }
};

export const readAccountListFromCookie = (req) => parseAccountList(req?.cookies?.[ACCOUNT_LIST_COOKIE], req);

export const upsertAccountListCookie = (req, res, entry) => {
  if (!entry?.session_id || !entry?.username) return;
  const current = readAccountListFromCookie(req).filter(
    (item) => item.session_id !== entry.session_id && item.username !== entry.username
  );
  writeAccountList(res, [{ session_id: entry.session_id, username: entry.username, full_name: entry.full_name || entry.username, image: entry.image || null }, ...current], req);
};

export const removeAccountFromCookie = (req, res, session_id) => {
  writeAccountList(res, readAccountListFromCookie(req).filter((item) => item.session_id !== session_id), req);
};

export const clearAccountListCookie = (res) => {
  res.clearCookie(ACCOUNT_LIST_COOKIE, cachedClearCookieOptions);
};