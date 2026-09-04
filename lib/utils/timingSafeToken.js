import { createHash, timingSafeEqual } from "node:crypto";

export function extractAuthorizationToken(authorizationHeader) {
  if (typeof authorizationHeader !== "string") return "";
  const raw = authorizationHeader.trim();
  const bearerMatch = /^bearer\s+(.+)$/i.exec(raw);
  return bearerMatch ? bearerMatch[1].trim() : raw;
}

const sha256Buffer = (value) => createHash("sha256").update(value, "utf8").digest();

/**
 * Constant-time comparison of two strings by hashing them first.
 */
export function timingSafeTokenMatch(providedToken, expectedToken) {
  const provided = typeof providedToken === "string" ? providedToken : "";
  const expected = typeof expectedToken === "string" ? expectedToken : "";
  return Boolean(expected.length) && timingSafeEqual(sha256Buffer(provided), sha256Buffer(expected));
}