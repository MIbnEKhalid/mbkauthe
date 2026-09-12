import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2Async = promisify(crypto.pbkdf2);
const PBKDF2_OPTS = [100000, 64, "sha512"];
let passwordPepper = null;

export const setPasswordPepper = (pepper) => { passwordPepper = pepper; };

const getPasswordPepper = () => {
  if (!passwordPepper) throw new Error("[mbkauthe] Password pepper not initialized");
  return passwordPepper;
};

const getPasswordSalt = (username) => `${username}:${getPasswordPepper()}`;

const derivePasswordHash = async (password, username) =>
  (await pbkdf2Async(password, getPasswordSalt(username), ...PBKDF2_OPTS)).toString("hex");

const derivePasswordHashSync = (password, username) =>
  crypto.pbkdf2Sync(password, getPasswordSalt(username), ...PBKDF2_OPTS).toString("hex");

function timingSafeHashEqual(stored, computed) {
  const storedBuf = Buffer.from(String(stored), "utf8");
  const compBuf = Buffer.from(String(computed), "utf8");
  return storedBuf.length === compBuf.length && crypto.timingSafeEqual(storedBuf, compBuf);
}

export const hashPassword = (password, username) => derivePasswordHashSync(password, username);

export const verifyPassword = async (password, username, password_hash) =>
  Boolean(password && username && password_hash) && timingSafeHashEqual(password_hash, await derivePasswordHash(password, username));

export const hashApiToken = (token) =>
  token ? crypto.createHash("sha256").update(token).digest("hex") : null;

export const generateRandomHex = (bytes = 32) => crypto.randomBytes(bytes).toString("hex");

export const generatePrefixedToken = (prefix = "mbk_") => `${prefix}${generateRandomHex(32)}`;
