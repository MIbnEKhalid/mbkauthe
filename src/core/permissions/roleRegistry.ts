/**
 * MBKAuthe — Dynamic permission & role core (pure, in-memory).
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { normalizePermission, resolvePermission, permissionMatches, normalizePermissions } from "./matcher.js";
import type { RoleDefinition } from "../types/permission.types.js";

export const SUPERADMIN_ROLE = "superadmin";
export const GLOBAL_APP_KEY = "global";

export class RoleRegistry {
  public roles: Map<string, Set<string>>;
  public wildcards: Map<string, string[]>;

  constructor() {
    this.roles = new Map();
    this.wildcards = new Map();
  }

  setRole(roleName: string, permissions: string[] = []): void {
    const role = normalizePermission(roleName);
    if (!role) return;
    const permSet = new Set<string>();
    const wildcardList: string[] = [];
    for (const p of permissions) {
      const norm = normalizePermission(p);
      if (!norm) continue;
      permSet.add(norm);
      if (norm.includes("*")) wildcardList.push(norm);
    }
    this.roles.set(role, permSet);
    this.wildcards.set(role, wildcardList);
  }

  addRolePermissions(roleName: string, permissions: string[] = []): void {
    const role = normalizePermission(roleName);
    if (!role) return;
    const current = this.roles.get(role) || new Set<string>();
    const currentWildcards = this.wildcards.get(role) || [];
    for (const p of permissions) {
      const norm = normalizePermission(p);
      if (!norm) continue;
      current.add(norm);
      if (norm.includes("*") && !currentWildcards.includes(norm)) currentWildcards.push(norm);
    }
    this.roles.set(role, current);
    this.wildcards.set(role, currentWildcards);
  }

  deleteRole(roleName: string): void {
    const role = normalizePermission(roleName);
    this.roles.delete(role);
    this.wildcards.delete(role);
  }

  getRolePermissions(roleName: string): Set<string> {
    return this.roles.get(normalizePermission(roleName)) || new Set<string>();
  }

  getPermissionsForRole(roleName: string): string[] {
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
    this.wildcards.clear();
  }

  loadRoles(rolesMap: Record<string, string[]> | Array<{ name: string; permissions?: string[] }> = {}): void {
    if (Array.isArray(rolesMap)) {
      for (const item of rolesMap) {
        if (item?.name) this.setRole(item.name, item.permissions || []);
      }
    } else if (rolesMap && typeof rolesMap === "object") {
      for (const [name, perms] of Object.entries(rolesMap)) this.setRole(name, perms);
    }
  }

  checkRoleHasPermission(roleName: string, requiredPermission: string): boolean {
    const role = normalizePermission(roleName);
    const permSet = this.roles.get(role);
    if (!permSet) return false;
    if (permSet.has(requiredPermission) || permSet.has("*") || permSet.has("*:*:*")) return true;
    const wildcards = this.wildcards.get(role);
    return Boolean(wildcards?.length && wildcards.some((w) => permissionMatches(w, requiredPermission)));
  }
}

export const defaultRoleRegistry = new RoleRegistry();

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
  allows?: string[];
  denies?: string[];
  roleRegistry?: RoleRegistry;
} = {}): { allows: string[]; denies: string[] } {
  const normalizedAllows = allows.map(normalizePermission).filter(Boolean);
  const normalizedDenies = denies.map(normalizePermission).filter(Boolean);
  const base = new Set<string>();
  const roleList = Array.isArray(roles) ? roles : [roles];

  for (const r of roleList) {
    if (Array.isArray(r)) {
      for (const p of r) {
        const norm = normalizePermission(p);
        if (norm) base.add(norm);
      }
    } else if (typeof r === "string" && r.trim()) {
      for (const p of roleRegistry.getRolePermissions(r)) base.add(p);
    }
  }

  // Deny always wins
  for (const deny of normalizedDenies) {
    for (const permission of [...base]) {
      if (permissionMatches(deny, permission)) base.delete(permission);
    }
  }

  // Allow overrides grant permissions
  for (const allow of normalizedAllows) {
    if (!normalizedDenies.some((deny) => permissionMatches(deny, allow))) base.add(allow);
  }

  return { allows: [...base].sort(), denies: [...new Set(normalizedDenies)].sort() };
}

export function intersectPermissions(held: any, requested: any, roleRegistry: RoleRegistry = defaultRoleRegistry): { allows: string[]; denies: string[] } {
  let heldAllows: string[] = [];
  let heldDenies: string[] = [];
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
  } else {
    const norm = normalizePermissions(targetHeld);
    heldAllows = norm.allows;
    heldDenies = norm.denies;
  }

  const list = Array.isArray(requested)
    ? requested
    : (typeof requested === "string" ? requested.split(",") : normalizePermissions(requested).allows);

  const allows: string[] = [];
  for (const entry of list) {
    const permission = normalizePermission(entry);
    if (!permission || heldDenies.some((deny) => permissionMatches(deny, permission))) continue;
    if (heldAllows.some((allow) => permissionMatches(allow, permission))) allows.push(permission);
  }

  return { allows: [...new Set(allows)].sort(), denies: [] };
}

export function hasPermission(user: any, required: string, roleRegistry: RoleRegistry = defaultRoleRegistry): boolean {
  if (!user) return false;
  const targetUser = user.principal || user;

  const primaryRole = (typeof targetUser.role === "string" ? targetUser.role : "").toLowerCase();
  if (primaryRole === SUPERADMIN_ROLE || (Array.isArray(targetUser.roles) && targetUser.roles.some((r: any) => String(r).toLowerCase() === SUPERADMIN_ROLE))) {
    return true;
  }

  const resolvedRequired = resolvePermission(required);
  if (!resolvedRequired) return false;

  const userDenies = (targetUser.overrides?.denies || targetUser.permissions?.denies || []).map(normalizePermission).filter(Boolean);
  if (userDenies.some((deny: string) => permissionMatches(deny, resolvedRequired))) return false;

  const userRoles = new Set(primaryRole ? [primaryRole] : []);
  if (Array.isArray(targetUser.roles)) {
    for (const r of targetUser.roles) {
      const cleanR = normalizePermission(r);
      if (cleanR) userRoles.add(cleanR);
    }
  }

  for (const roleName of userRoles) {
    if (roleRegistry.checkRoleHasPermission(roleName, resolvedRequired)) return true;
  }

  const userAllows = (targetUser.overrides?.allows || targetUser.permissions?.allows || (Array.isArray(targetUser.permissions) ? targetUser.permissions : [])).map(normalizePermission).filter(Boolean);
  return userAllows.some((allow: string) => permissionMatches(allow, resolvedRequired));
}
