import crypto from "node:crypto";
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

export const encryptCookiePayload = (data: unknown) => {
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
    const encrypted = cipher.update(JSON.stringify(data), "utf8", "hex") + cipher.final("hex");
    return { iv: iv.toString("hex"), authTag: cipher.getAuthTag().toString("hex"), data: encrypted };
  } catch (error) {
    console.error("[mbkauthe] Cookie encryption error:", error);
    return null;
  }
};

export const decryptCookiePayload = (payload: any) => {
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

export const generateFingerprintFromUserAgent = (userAgent: string = "") =>
  crypto.createHash("sha256").update(`${userAgent}:${mbkautheVar.SESSION_SECRET_KEY || ""}`).digest("hex").slice(0, 32);

export const encryptSessionId = (session_id?: string | null): string | null => {
  if (!session_id) return null;
  const encrypted = encryptCookiePayload({ session_id });
  return encrypted ? JSON.stringify(encrypted) : null;
};

export const decryptSessionId = (encrypted_session_id?: string | null): string | null => {
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

export const resolveCookieDomain = (isDeployed: string | boolean, domain?: string | null, isTestDev = isTestDevEnvironment()): string | undefined =>
  isDeployed !== "true" || isTestDev || !domain ? undefined : `.${String(domain).replace(/^\.+/, "")}`;

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

export const createCookieOptions = (maxAge?: number): CookieConfigOptions => ({
  ...(maxAge !== undefined && { maxAge }),
  domain: getCookieDomain(),
  secure: getCookieSecure(),
  sameSite: "lax",
  path: "/",
  httpOnly: true,
});

export const getCookieOptions = (): CookieConfigOptions => createCookieOptions((mbkautheVar.COOKIE_EXPIRE_TIME || 2) * 86400000);
export const getClearCookieOptions = (): CookieConfigOptions => createCookieOptions();

export const cachedCookieOptions = getCookieOptions();
export const cachedClearCookieOptions = getClearCookieOptions();

export { MAX_REMEMBERED_ACCOUNTS, ACCOUNT_LIST_COOKIE };
