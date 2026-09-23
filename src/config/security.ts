export { setPasswordPepper, getPasswordPepper, getPasswordSalt, derivePasswordHash, derivePasswordHashSync, timingSafeHashEqual, hashPassword, verifyPassword } from "../core/security/password.js";

import { TokenEngine } from "../core/tokens/TokenEngine.js";

export const hashApiToken = (token: string | null | undefined): string | null =>
  TokenEngine.hashToken(token);

export const generateRandomHex = (bytes = 32): string =>
  TokenEngine.generateEntropy(bytes);

export const generatePrefixedToken = (prefix = "mbk_"): string =>
  TokenEngine.createToken("custom", prefix, 32);
