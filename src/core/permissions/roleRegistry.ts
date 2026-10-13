/**
 * MBKAuthe — Dynamic permission & role core (pure numeric ID engine).
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { resolvePermissionId, normalizePermission, setDefaultRoleRegistryRef } from "./matcher.js";
import type { PermissionDescriptor, PermissionTarget } from "../types/permission.types.js";

export const SUPERADMIN_ROLE = "superadmin";
export const GLOBAL_APP_KEY = "global";

export class RoleRegistry {
  public roles: Map<string, Set<number>>;
  public isLoaded: boolean = false;
  private keyToId: Map<string, number> = new Map();
  private idToDescriptor: Map<number, PermissionDescriptor> = new Map();

  constructor() {
    this.roles = new Map();
    this.isLoaded = false;
  }

  registerCatalogItem(id: number, appKey: string, serviceKey: string, actionKey: string, label?: string): PermissionDescriptor {
    const cleanApp = normalizePermission(appKey);
    const cleanService = normalizePermission(serviceKey);
    const cleanAction = normalizePermission(actionKey);
    const key = `${cleanApp}:${cleanService}:${cleanAction}`;

    const descriptor: PermissionDescriptor = {
      id,
      appKey: cleanApp,
      serviceKey: cleanService,
      actionKey: cleanAction,
      label,
      key,
      valueOf() {
        return this.id;
      },
      toString() {
        return String(this.id);
      },
    };

    this.keyToId.set(key, id);
    if (cleanApp === GLOBAL_APP_KEY) {
      this.keyToId.set(`${cleanService}.${cleanAction}`, id);
      this.keyToId.set(`${cleanService}:${cleanAction}`, id);
    }
    this.idToDescriptor.set(id, descriptor);
    return descriptor;
  }

  getIdByKey(key: string): number {
    const cleanKey = normalizePermission(key);
    const id = this.keyToId.get(cleanKey);
    if (id && id > 0) return id;
    if (this !== defaultRoleRegistry && typeof defaultRoleRegistry !== "undefined") {
      return defaultRoleRegistry.getIdByKey(cleanKey);
    }
    return 0;
  }

  getDescriptorById(id: number): PermissionDescriptor | undefined {
    return this.idToDescriptor.get(id);
  }

  getAllDescriptors(): PermissionDescriptor[] {
    return Array.from(this.idToDescriptor.values());
  }

  setRole(roleName: string, permissions: (number | PermissionTarget)[] = []): void {
    const role = normalizePermission(roleName);
    if (!role) return;
    const permSet = new Set<number>();
    for (const p of permissions) {
      const id = resolvePermissionId(p, this);
      if (id > 0) permSet.add(id);
    }
    this.roles.set(role, permSet);
  }

  addRolePermissions(roleName: string, permissions: (number | PermissionTarget)[] = []): void {
    const role = normalizePermission(roleName);
    if (!role) return;
    const current = this.roles.get(role) || new Set<number>();
    for (const p of permissions) {
      const id = resolvePermissionId(p, this);
      if (id > 0) current.add(id);
    }
    this.roles.set(role, current);
  }

  deleteRole(roleName: string): void {
    const role = normalizePermission(roleName);
    this.roles.delete(role);
  }

  getRolePermissions(roleName: string): Set<number> {
    return this.roles.get(normalizePermission(roleName)) || new Set<number>();
  }

  getPermissionsForRole(roleName: string): number[] {
    return Array.from(this.getRolePermissions(roleName));
  }

  hasRole(roleName: string): boolean {
    return this.roles.has(normalizePermission(roleName));
  }

  getAllRoles(): string[] {
    return Array.from(this.roles.keys());
  }

  clear(): void {
    this.roles.clear();
    this.keyToId.clear();
    this.idToDescriptor.clear();
    this.isLoaded = false;
  }

  loadRoles(rolesMap: Record<string, number[]> | Array<{ name: string; permissions?: number[] }> = {}): void {
    if (Array.isArray(rolesMap)) {
      for (const item of rolesMap) {
        if (item?.name) this.setRole(item.name, item.permissions || []);
      }
    } else if (rolesMap && typeof rolesMap === "object") {
      for (const [name, perms] of Object.entries(rolesMap)) this.setRole(name, perms as any);
    }
  }

  checkRoleHasPermission(roleName: string, requiredPermission: number | PermissionTarget): boolean {
    const role = normalizePermission(roleName);
    const permSet = this.roles.get(role);
    if (!permSet || permSet.size === 0) return false;
    const reqId = resolvePermissionId(requiredPermission, this);
    if (reqId <= 0) return false;
    return permSet.has(reqId);
  }
}

export const defaultRoleRegistry = new RoleRegistry();
setDefaultRoleRegistryRef(defaultRoleRegistry);

export const GlobalRoles: Record<string, string> = {
  superadmin: "superadmin",
  admin: "admin",
  normaluser: "normaluser",
  guest: "guest",
};

export function buildEffectivePermissions({
  roles = [],
  allows = [],
  denies = [],
  roleRegistry = defaultRoleRegistry,
}: {
  roles?: string[] | string;
  allows?: (number | PermissionTarget)[];
  denies?: (number | PermissionTarget)[];
  roleRegistry?: RoleRegistry;
} = {}): { allows: number[]; denies: number[] } {
  const normalizedAllows = (allows || []).map((p) => resolvePermissionId(p, roleRegistry)).filter((id) => id > 0);
  const normalizedDenies = (denies || []).map((p) => resolvePermissionId(p, roleRegistry)).filter((id) => id > 0);
  const base = new Set<number>();
  const roleList = Array.isArray(roles) ? roles : [roles];

  for (const r of roleList) {
    if (typeof r === "string" && r.trim()) {
      for (const id of roleRegistry.getRolePermissions(r)) {
        base.add(id);
      }
    }
  }

  // Deny always wins
  for (const denyId of normalizedDenies) {
    base.delete(denyId);
  }

  // Allow overrides grant permissions
  for (const allowId of normalizedAllows) {
    if (!normalizedDenies.includes(allowId)) {
      base.add(allowId);
    }
  }

  return {
    allows: Array.from(base).sort((a, b) => a - b),
    denies: Array.from(new Set(normalizedDenies)).sort((a, b) => a - b),
  };
}

export function intersectPermissions(held: any, requested: any, roleRegistry: RoleRegistry = defaultRoleRegistry): { allows: number[]; denies: number[] } {
  let heldAllows: number[] = [];
  let heldDenies: number[] = [];
  const targetHeld = held?.principal || held;

  if (targetHeld && typeof targetHeld === "object" && (targetHeld.role || targetHeld.roles || targetHeld.overrides)) {
    const effective = buildEffectivePermissions({
      roles: [targetHeld.role, ...(targetHeld.roles || [])].filter(Boolean),
      allows: targetHeld.overrides?.allows || [],
      denies: targetHeld.overrides?.denies || [],
      roleRegistry,
    });
    heldAllows = effective.allows;
    heldDenies = effective.denies;
  } else if (Array.isArray(targetHeld)) {
    heldAllows = targetHeld.map((p) => resolvePermissionId(p, roleRegistry)).filter((id) => id > 0);
  }

  const list = Array.isArray(requested) ? requested : [requested];
  const requestedIds = list.map((p) => resolvePermissionId(p, roleRegistry)).filter((id) => id > 0);

  const allows: number[] = [];
  for (const reqId of requestedIds) {
    if (heldDenies.includes(reqId)) continue;
    if (heldAllows.includes(reqId)) allows.push(reqId);
  }

  return { allows: Array.from(new Set(allows)).sort((a, b) => a - b), denies: [] };
}

export function hasPermission(user: any, required: number | PermissionTarget, roleRegistry: RoleRegistry = defaultRoleRegistry): boolean {
  if (!user) return false;
  const targetUser = user.principal || user;

  const primaryRole = (typeof targetUser.role === "string" ? targetUser.role : "").toLowerCase();
  if (primaryRole === SUPERADMIN_ROLE || (Array.isArray(targetUser.roles) && targetUser.roles.some((r: any) => String(r).toLowerCase() === SUPERADMIN_ROLE))) {
    return true;
  }

  const reqId = resolvePermissionId(required, roleRegistry);
  if (reqId <= 0) return false;

  const userDenies = (targetUser.overrides?.denies || targetUser.permissions?.denies || [])
    .map((p: any) => resolvePermissionId(p, roleRegistry))
    .filter((id: number) => id > 0);
  if (userDenies.includes(reqId)) return false;

  const userRoles = new Set(primaryRole ? [primaryRole] : []);
  if (Array.isArray(targetUser.roles)) {
    for (const r of targetUser.roles) {
      const cleanR = normalizePermission(r);
      if (cleanR) userRoles.add(cleanR);
    }
  }

  for (const roleName of userRoles) {
    if (roleRegistry.checkRoleHasPermission(roleName, reqId)) return true;
  }

  const userAllows = (targetUser.overrides?.allows || targetUser.permissions?.allows || (Array.isArray(targetUser.permissions) ? targetUser.permissions : []))
    .map((p: any) => resolvePermissionId(p, roleRegistry))
    .filter((id: number) => id > 0);
  return userAllows.includes(reqId);
}
