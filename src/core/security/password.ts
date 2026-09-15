import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2Async = promisify(crypto.pbkdf2);
const PBKDF2_OPTS: [number, number, string] = [100000, 64, "sha512"];
let passwordPepper: string | null = process.env.PASSWORD_PEPPER || null;

export const setPasswordPepper = (pepper: string): void => {
  passwordPepper = pepper || null;
};

export const getPasswordPepper = (): string => {
  if (!passwordPepper) {
    passwordPepper = process.env.PASSWORD_PEPPER || "mbkauthe_default_pepper_key";
  }
  return passwordPepper;
};

export const getPasswordSalt = (username: string): string => `${username}:${getPasswordPepper()}`;

export const derivePasswordHash = async (password: string, username: string): Promise<string> =>
  (await pbkdf2Async(password, getPasswordSalt(username), ...PBKDF2_OPTS)).toString("hex");

export const derivePasswordHashSync = (password: string, username: string): string =>
  crypto.pbkdf2Sync(password, getPasswordSalt(username), ...PBKDF2_OPTS).toString("hex");

export function timingSafeHashEqual(stored: string, computed: string): boolean {
  const storedBuf = Buffer.from(String(stored), "utf8");
  const compBuf = Buffer.from(String(computed), "utf8");
  return storedBuf.length === compBuf.length && crypto.timingSafeEqual(storedBuf, compBuf);
}

export const hashPassword = (password: string, username: string): string => derivePasswordHashSync(password, username);

export const verifyPassword = async (password: string, username: string, password_hash: string): Promise<boolean> =>
  Boolean(password && username && password_hash) && timingSafeHashEqual(password_hash, await derivePasswordHash(password, username));
