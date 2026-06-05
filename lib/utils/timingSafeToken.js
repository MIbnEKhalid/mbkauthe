import { createHash, timingSafeEqual } from "node:crypto";

export function extractAuthorizationToken(authorizationHeader) {
  if (typeof authorizationHeader !== "string") return "";

  const raw = authorizationHeader.trim();
  if (!raw) return "";

  const bearerMatch = /^bearer\s+(.+)$/i.exec(raw);
  if (bearerMatch) return bearerMatch[1].trim();

  return raw;
}

function sha256Buffer(value) {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * Constant-time comparison of two strings by hashing them first.
 *
 * Notes:
 * - Always computes both hashes (32 bytes each) and uses timingSafeEqual.
 * - Returns false when expectedToken is empty/unset.
 */
export function timingSafeTokenMatch(providedToken, expectedToken) {
  const provided = typeof providedToken === "string" ? providedToken : "";
  const expected = typeof expectedToken === "string" ? expectedToken : "";

  const providedHash = sha256Buffer(provided);
  const expectedHash = sha256Buffer(expected);

  const matches = timingSafeEqual(providedHash, expectedHash);
  return matches && expected.length > 0;
}