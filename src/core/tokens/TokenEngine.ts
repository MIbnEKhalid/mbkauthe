import crypto from "node:crypto";

export type TokenType = "pat" | "cli" | "session" | "custom";

export const TOKEN_PREFIXES: Record<TokenType, string> = {
  pat: "mbk_pat_",
  cli: "mbk_cli_",
  session: "mbk_sess_",
  custom: "mbk_",
};

export interface ParsedToken {
  type: TokenType;
  prefix: string;
  entropy: string;
  raw: string;
}

export class TokenEngine {
  /**
   * Generates cryptographically secure random hex bytes
   */
  static generateEntropy(bytes = 32): string {
    return crypto.randomBytes(bytes).toString("hex");
  }

  /**
   * Generates a prefixed token for standard token types
   */
  static createToken(type: TokenType = "custom", customPrefix?: string, entropyBytes = 32): string {
    const prefix = customPrefix || TOKEN_PREFIXES[type] || "mbk_";
    return `${prefix}${this.generateEntropy(entropyBytes)}`;
  }

  /**
   * Creates an API Personal Access Token (PAT)
   */
  static createApiToken(bytes = 32): string {
    return this.createToken("pat", undefined, bytes);
  }

  /**
   * Creates a CLI auth session / token
   */
  static createCliToken(bytes = 32): string {
    return this.createToken("cli", undefined, bytes);
  }

  /**
   * Hashes a token using SHA-256 by default
   */
  static hashToken(token: string | null | undefined, algorithm: "sha256" | "sha512" = "sha256"): string | null {
    if (!token || typeof token !== "string") return null;
    return crypto.createHash(algorithm).update(token, "utf8").digest("hex");
  }

  /**
   * Verifies a raw token against a stored hash in constant time
   */
  static verifyToken(rawToken: string | null | undefined, storedHash: string | null | undefined, algorithm: "sha256" | "sha512" = "sha256"): boolean {
    if (!rawToken || !storedHash) return false;
    const computedHash = this.hashToken(rawToken, algorithm);
    if (!computedHash) return false;

    const storedBuf = Buffer.from(storedHash, "utf8");
    const computedBuf = Buffer.from(computedHash, "utf8");
    return storedBuf.length === computedBuf.length && crypto.timingSafeEqual(storedBuf, computedBuf);
  }

  /**
   * Constant-time comparison between two raw strings
   */
  static timingSafeMatch(provided?: string | null, expected?: string | null): boolean {
    const p = typeof provided === "string" ? provided : "";
    const e = typeof expected === "string" ? expected : "";
    if (!e.length) return false;

    const pBuf = crypto.createHash("sha256").update(p, "utf8").digest();
    const eBuf = crypto.createHash("sha256").update(e, "utf8").digest();
    return crypto.timingSafeEqual(pBuf, eBuf);
  }

  /**
   * Extracts a bearer token from an Authorization header string
   */
  static extractBearerToken(authHeader?: string | null): string {
    if (typeof authHeader !== "string") return "";
    const raw = authHeader.trim();
    const match = /^bearer\s+(.+)$/i.exec(raw);
    return match ? match[1].trim() : raw;
  }

  /**
   * Parses token prefix and identifies token type
   */
  static parseToken(rawToken: string): ParsedToken {
    const raw = typeof rawToken === "string" ? rawToken.trim() : "";
    for (const [typeKey, prefix] of Object.entries(TOKEN_PREFIXES)) {
      if (raw.startsWith(prefix)) {
        return {
          type: typeKey as TokenType,
          prefix,
          entropy: raw.slice(prefix.length),
          raw,
        };
      }
    }

    return {
      type: "custom",
      prefix: "",
      entropy: raw,
      raw,
    };
  }
}

export const extractAuthorizationToken = (authHeader?: string | null): string =>
  TokenEngine.extractBearerToken(authHeader);

export const timingSafeTokenMatch = (provided?: string | null, expected?: string | null): boolean =>
  TokenEngine.timingSafeMatch(provided, expected);
