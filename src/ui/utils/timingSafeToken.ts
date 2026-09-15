import { createHash, timingSafeEqual } from "node:crypto";

export function extractAuthorizationToken(authorizationHeader?: string | null): string {
  if (typeof authorizationHeader !== "string") return "";
  const raw = authorizationHeader.trim();
  const match = /^bearer\s+(.+)$/i.exec(raw);
  return match ? match[1].trim() : raw;
}

const sha256Buffer = (value: string) => createHash("sha256").update(value, "utf8").digest();

/**
 * Constant-time comparison of two strings by hashing them first.
 */
export function timingSafeTokenMatch(providedToken?: string | null, expectedToken?: string | null): boolean {
  const provided = typeof providedToken === "string" ? providedToken : "";
  const expected = typeof expectedToken === "string" ? expectedToken : "";
  return Boolean(expected.length) && timingSafeEqual(sha256Buffer(provided), sha256Buffer(expected));
}
