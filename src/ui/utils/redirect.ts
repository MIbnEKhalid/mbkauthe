/**
 * Validates that a redirect target is a safe same-origin relative path.
 */
export function isSafeRelativeRedirect(value?: string | null): boolean {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  return trimmed.startsWith("/") && !trimmed.startsWith("//") && !trimmed.includes("://") && !trimmed.includes("\\");
}

export function sanitizeRelativeRedirect(value?: string | null): string | null {
  return isSafeRelativeRedirect(value) ? (value as string).trim() : null;
}
