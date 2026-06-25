/**
 * Validates that a redirect target is a safe same-origin relative path.
 */
export function isSafeRelativeRedirect(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) return false;
  if (trimmed.includes('://') || trimmed.includes('\\')) return false;
  return true;
}

export function sanitizeRelativeRedirect(value) {
  return isSafeRelativeRedirect(value) ? value.trim() : null;
}
