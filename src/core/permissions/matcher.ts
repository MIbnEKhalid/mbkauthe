import type { PermissionTarget } from "../types/permission.types.js";

let _defaultRegistryRef: any = null;

export function setDefaultRoleRegistryRef(reg: any): void {
  _defaultRegistryRef = reg;
}

export function resolvePermissionId(target: PermissionTarget | any, registry?: any): number {
  if (typeof target === "number" && Number.isInteger(target)) return target;
  const reg = (registry && typeof registry.getIdByKey === "function") ? registry : _defaultRegistryRef;

  if (target && typeof target === "object") {
    if (typeof target.id === "number" && target.id > 0) return target.id;
    if (typeof target.valueOf === "function") {
      const val = target.valueOf();
      if (typeof val === "number" && val > 0) return val;
    }
    if (reg && typeof reg.getIdByKey === "function") {
      const key = target.key || (target.appKey && target.serviceKey && target.actionKey ? `${target.appKey}:${target.serviceKey}:${target.actionKey}` : null);
      if (key) {
        const found = reg.getIdByKey(key);
        if (found > 0) return found;
      }
    }
  }
  if (typeof target === "string") {
    const trimmed = target.trim();
    if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);
    if (reg && typeof reg.getIdByKey === "function") {
      const found = reg.getIdByKey(trimmed.toLowerCase());
      if (found > 0) return found;
    }
    const clean = trimmed.toLowerCase();
    const parts = clean.split(":");
    if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
      let hash = 5381;
      for (let i = 0; i < clean.length; i++) {
        hash = (((hash << 5) + hash) + clean.charCodeAt(i)) & 0x7fffffff;
      }
      const id = hash === 0 ? 1 : hash;
      if (reg && typeof reg.registerCatalogItem === "function") {
        reg.registerCatalogItem(id, parts[0], parts[1], parts[2]);
      }
      return id;
    }
  }
  return 0;
}

export function permissionIdMatches(heldId: number, requiredId: number): boolean {
  return heldId > 0 && requiredId > 0 && heldId === requiredId;
}

export function permissionMatches(held: any, required: any, registry?: any): boolean {
  const heldId = resolvePermissionId(held, registry);
  const requiredId = resolvePermissionId(required, registry);
  return permissionIdMatches(heldId, requiredId);
}

export const matchPermission = permissionMatches;

export function normalizePermissions(permissions: any, registry?: any): { allows: number[]; denies: number[] } {
  if (Array.isArray(permissions)) {
    return { allows: permissions.map((p) => resolvePermissionId(p, registry)).filter((id) => id > 0), denies: [] };
  }
  if (permissions && typeof permissions === "object") {
    const allows = Array.isArray(permissions.allows) ? permissions.allows.map((p: any) => resolvePermissionId(p, registry)).filter((id: number) => id > 0) : [];
    const denies = Array.isArray(permissions.denies) ? permissions.denies.map((p: any) => resolvePermissionId(p, registry)).filter((id: number) => id > 0) : [];
    return { allows, denies };
  }
  const single = resolvePermissionId(permissions, registry);
  return { allows: single > 0 ? [single] : [], denies: [] };
}

export function resolvePermission(value: any, registry?: any): number {
  return resolvePermissionId(value, registry);
}

export function normalizePermission(value: any): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}
