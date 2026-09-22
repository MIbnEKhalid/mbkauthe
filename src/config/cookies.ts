import crypto from "node:crypto";
import cookieSignature from "cookie-signature";
import { mbkautheVar } from "./env.js";

const MAX_REMEMBERED_ACCOUNTS = 5;
const ACCOUNT_LIST_COOKIE = "mbkauthe_accounts";
const ENCRYPTION_ALGORITHM = "aes-256-gcm";

const sha256 = (val: string) => crypto.createHash("sha256").update(val).digest();
const getEncryptionKey = () => sha256(mbkautheVar.SESSION_SECRET_KEY || "default-secret-key");
const getSigningKey = () => sha256(`${mbkautheVar.SESSION_SECRET_KEY || "default-secret-key"}:cookie-signing`);

export const encodePayload = (data: unknown) => Buffer.from(JSON.stringify(data), "utf8").toString("base64url");
export const decodePayload = (encoded: string) => JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));

export const signCookiePayload = (encodedPayload: string) =>
  crypto.createHmac("sha256", getSigningKey()).update(encodedPayload).digest("hex");

export const verifyCookieSignature = (encodedPayload?: string | null, signature?: string | null) => {
  if (!encodedPayload || !signature || typeof encodedPayload !== "string" || typeof signature !== "string") return false;
  const expected = Buffer.from(signCookiePayload(encodedPayload), "hex");
  const actual = Buffer.from(signature, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
};

export const createSignedCookiePayload = (data: unknown) => {
  try {
    const payload = encodePayload(data);
    return { payload, signature: signCookiePayload(payload) };
  } catch (error) {
    console.error("[mbkauthe] Cookie signing error:", error);
    return null;
  }
};

export const parseSignedCookiePayload = (signedPayload: any) => {
  try {
    if (!signedPayload || !verifyCookieSignature(signedPayload.payload, signedPayload.signature)) return null;
    return decodePayload(signedPayload.payload);
  } catch (error) {
    console.error("[mbkauthe] Cookie signature verification error:", error);
    return null;
  }
};

export const generateFingerprintFromUserAgent = (userAgent: string = "") =>
  crypto.createHash("sha256").update(`${userAgent}:${mbkautheVar.SESSION_SECRET_KEY || ""}`).digest("hex").slice(0, 32);

export const encryptSessionId = (session_id?: string | null): string | null => {
  if (!session_id || typeof session_id !== "string") return null;
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
    const encrypted = Buffer.concat([cipher.update(session_id, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${iv.toString("base64url")}.${authTag.toString("base64url")}.${encrypted.toString("base64url")}`;
  } catch (error) {
    console.error("[mbkauthe] Session ID encryption error:", error);
    return null;
  }
};

export const decryptSessionId = (encrypted_session_id?: string | null): string | null => {
  if (!encrypted_session_id || typeof encrypted_session_id !== "string") return null;
  const parts = encrypted_session_id.split(".");
  if (parts.length !== 3) return null;
  try {
    const iv = Buffer.from(parts[0], "base64url");
    const authTag = Buffer.from(parts[1], "base64url");
    const data = Buffer.from(parts[2], "base64url");
    if (iv.length !== 12 || authTag.length !== 16 || data.length === 0) return null;
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
    decipher.setAuthTag(authTag);
    return decipher.update(data, undefined, "utf8") + decipher.final("utf8");
  } catch (error) {
    console.error("[mbkauthe] Session ID decryption error:", error);
    return null;
  }
};

const isTestDevEnvironment = () => process.env.test === "dev";

export const resolveCookieDomain = (isDeployed: string | boolean, domain?: string | null, isTestDev = isTestDevEnvironment()): string | undefined => {
  if (isDeployed !== "true" || isTestDev || !domain) return undefined;
  const cleaned = String(domain).trim().replace(/^\.+/, "");
  if (!cleaned || cleaned === "localhost" || cleaned === "127.0.0.1" || cleaned === "::1" || /^\d+\.\d+\.\d+\.\d+$/.test(cleaned)) {
    return undefined;
  }
  return `.${cleaned}`;
};

export const getCookieDomain = (): string | undefined => resolveCookieDomain(mbkautheVar.IS_DEPLOYED, mbkautheVar.DOMAIN);
export const getCookieSecure = (): boolean => mbkautheVar.IS_DEPLOYED === "true" && !isTestDevEnvironment();

export const isAllowedOriginHostname = (hostname?: string | null, domain: string = mbkautheVar.DOMAIN): boolean =>
  Boolean(hostname && domain && (hostname === domain || hostname.endsWith(`.${domain}`)));

export interface CookieConfigOptions {
  maxAge?: number;
  domain?: string;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none" | boolean;
  path?: string;
  httpOnly?: boolean;
}

export const createCookieOptions = (maxAge?: number): CookieConfigOptions => {
  const sameSite = (mbkautheVar.SESSION_COOKIE_SAMESITE as any) || "lax";
  return {
    ...(maxAge !== undefined && { maxAge }),
    domain: getCookieDomain(),
    secure: getCookieSecure(),
    sameSite: sameSite === "strict" || sameSite === "none" ? sameSite : "lax",
    path: "/",
    httpOnly: true,
  };
};

export const DEVICE_ID_COOKIE = "mbk_device_id";
export const DEVICE_ID_MAX_AGE = 10 * 365 * 24 * 60 * 60 * 1000; // 10 years

export const getDeviceCookieOptions = (): CookieConfigOptions => {
  return {
    ...createCookieOptions(DEVICE_ID_MAX_AGE),
    httpOnly: true,
  };
};

export const getOrCreateDeviceId = (req: any, res?: any): string => {
  const existing = req?.cookies?.[DEVICE_ID_COOKIE];
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (typeof existing === "string" && UUID_RE.test(existing.trim())) {
    return existing.trim();
  }
  const newDeviceId = crypto.randomUUID();
  if (res && typeof res.cookie === "function") {
    res.cookie(DEVICE_ID_COOKIE, newDeviceId, getDeviceCookieOptions());
  }
  if (req) {
    if (!req.cookies) req.cookies = {};
    req.cookies[DEVICE_ID_COOKIE] = newDeviceId;
  }
  return newDeviceId;
};

export const formatSessionCookieValue = (sid: string): string => {
  const secret = mbkautheVar.SESSION_SECRET_KEY || "default-session-secret";
  return "s:" + cookieSignature.sign(sid, secret);
};

export const setActiveSessionCookie = (res: any, sid: string): void => {
  const cookieName = mbkautheVar.SESSION_COOKIE_NAME || "mbkauthe.sid";
  const signedVal = formatSessionCookieValue(sid);
  res.cookie(cookieName, signedVal, getCookieOptions() as any);
};

export const clearSessionCookies = (res: any): void => {
  const cookieName = mbkautheVar.SESSION_COOKIE_NAME || "mbkauthe.sid";
  [cookieName, "mbkauthe.sid", "session_id", "username", "full_name", "last_login_method"]
    .forEach((cookie) => res.clearCookie(cookie, getClearCookieOptions() as any));
};

export const getCookieOptions = (): CookieConfigOptions => createCookieOptions((mbkautheVar.COOKIE_EXPIRE_TIME || 2) * 86400000);
export const getClearCookieOptions = (): CookieConfigOptions => createCookieOptions();

export { MAX_REMEMBERED_ACCOUNTS, ACCOUNT_LIST_COOKIE };
