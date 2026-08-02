import crypto from "crypto";
import { promisify } from "util";

const pbkdf2Async = promisify(crypto.pbkdf2);
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = "sha512";

let passwordPepper = null;

export function setPasswordPepper(pepper) {
  passwordPepper = pepper;
}

const getPasswordPepper = () => {
  if (!passwordPepper) {
    throw new Error("[mbkauthe] Password pepper not initialized");
  }
  return passwordPepper;
};

const getPasswordSalt = (username) => `${username}:${getPasswordPepper()}`;

async function derivePasswordHash(password, username) {
  const derived = await pbkdf2Async(password, getPasswordSalt(username), PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
  return derived.toString("hex");
}

function derivePasswordHashSync(password, username) {
  return crypto.pbkdf2Sync(password, getPasswordSalt(username), PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString("hex");
}

function timingSafeHashEqual(stored, computed) {
  const storedBuffer = Buffer.from(String(stored), "utf8");
  const computedBuffer = Buffer.from(String(computed), "utf8");
  return storedBuffer.length === computedBuffer.length && crypto.timingSafeEqual(storedBuffer, computedBuffer);
}

// Password hashing using PBKDF2 with username + application pepper as salt
export const hashPassword = (password, username) => {
  return derivePasswordHashSync(password, username);
};

export const verifyPassword = async (password, username, storedHash) => {
  if (!password || !username || !storedHash) return false;

  const computed = await derivePasswordHash(password, username);
  return timingSafeHashEqual(storedHash, computed);
};

// Hash an API token for storage
export const hashApiToken = (token) => {
  if (!token) return null;
  return crypto.createHash("sha256").update(token).digest("hex");
};

// Generate a cryptographically random hex string (default 32 bytes → 64 chars)
export const generateRandomHex = (bytes = 32) => {
  return crypto.randomBytes(bytes).toString("hex");
};

// Generate a prefixed API token (e.g. "mbk_<64 hex chars>")
export const generatePrefixedToken = (prefix = "mbk_") => {
  return `${prefix}${generateRandomHex(32)}`;
};
