export function normalizePermission(value: any): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function resolvePermission(value: any): string {
  const normalized = normalizePermission(value);
  if (normalized.split(".").length === 2 && !normalized.includes(":")) {
    const [service, action] = normalized.split(".");
    if (service && action) return `global:${service}:${action}`;
  }
  return normalized;
}

export function splitPermission(value: any): string[] {
  const normalized = normalizePermission(value);
  return normalized ? normalized.split(":").map((s) => s.trim()) : [];
}

const segmentMatches = (a: string, b: string) => a === "*" || b === "*" || a === b;

export function permissionMatches(stored: string, required: string): boolean {
  const s = normalizePermission(stored);
  const r = normalizePermission(required);
  if (!s || !r) return false;
  if (s === "*" || s === "*:*:*" || r === "*" || r === "*:*:*" || s === r) return true;

  const a = splitPermission(s);
  const b = splitPermission(r);
  return a.length === 3 && b.length === 3 && segmentMatches(a[0], b[0]) && segmentMatches(a[1], b[1]) && segmentMatches(a[2], b[2]);
}

export const matchPermission = permissionMatches;

export function compilePermissionPattern(pattern: string): (target: string) => boolean {
  return (target: string) => permissionMatches(pattern, target);
}

export function normalizePermissions(permissions: any): { allows: string[]; denies: string[] } {
  if (Array.isArray(permissions)) {
    return { allows: permissions.map(normalizePermission).filter(Boolean), denies: [] };
  }
  if (permissions && typeof permissions === "object") {
    const allows = Array.isArray(permissions.allows) ? permissions.allows : [];
    const denies = Array.isArray(permissions.denies) ? permissions.denies : [];
    return {
      allows: allows.map(normalizePermission).filter(Boolean),
      denies: denies.map(normalizePermission).filter(Boolean),
    };
  }
  if (typeof permissions === "string" && permissions.trim()) {
    return { allows: [normalizePermission(permissions)], denies: [] };
  }
  return { allows: [], denies: [] };
}
