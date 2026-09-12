/**
 * Validates that a redirect target is a safe same-origin relative path.
 */
export function isSafeRelativeRedirect(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  return trimmed.startsWith("/") && !trimmed.startsWith("//") && !trimmed.includes("://") && !trimmed.includes("\\");
}

export function sanitizeRelativeRedirect(value) {
  return isSafeRelativeRedirect(value) ? value.trim() : null;
}
