export function isSafeRelativeRedirect(value?: string | null): boolean {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) return false;
  return !trimmed.includes("://") && !trimmed.includes("\\");
}

export function sanitizeRelativeRedirect(value?: string | null, fallback: string | null = null): string | null {
  return isSafeRelativeRedirect(value) ? (value as string).trim() : fallback;
}

