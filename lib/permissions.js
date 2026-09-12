/**
 * MBKAuthe — Dynamic permission & role core (pure, in-memory).

 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 
*/

import { mbkautheVar } from "#config.js";

const SUPERADMIN_ROLE = "superadmin";
export const GLOBAL_APP_KEY = "global";

export function normalizePermission(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function resolvePermission(value) {
  const normalized = normalizePermission(value);
  if (normalized.split(".").length === 2 && !normalized.includes(":")) {
    const [service, action] = normalized.split(".");
    if (service && action) return `${GLOBAL_APP_KEY}:${service}:${action}`;
  }
  return normalized;
}

export function splitPermission(value) {
  const normalized = normalizePermission(value);
  return normalized ? normalized.split(":").map((s) => s.trim()) : [];
}

const segmentMatches = (a, b) => a === "*" || b === "*" || a === b;

export function permissionMatches(stored, required) {
  const s = normalizePermission(stored);
  const r = normalizePermission(required);
  if (!s || !r) return false;
  if (s === "*" || s === "*:*:*" || r === "*" || r === "*:*:*" || s === r) return true;

  const a = splitPermission(s);
  const b = splitPermission(r);
  return a.length === 3 && b.length === 3 && segmentMatches(a[0], b[0]) && segmentMatches(a[1], b[1]) && segmentMatches(a[2], b[2]);
}

export function normalizePermissions(permissions) {
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

export function resolveAppKey(appKey = null, fallbackAppKey = null) {
  const resolved = normalizePermission(appKey || mbkautheVar.APP_NAME || fallbackAppKey || "");
  if (!resolved) {
    throw new Error(
      "[mbkauthe] definePermissions/syncAppPermissions requires an app key. Set APP_NAME (mbkautheVar.APP_NAME), pass the `appKey` option, or provide `fallbackAppKey`."
    );
  }
  return resolved;
}

const MANIFEST_KEY = "__manifest";
const APP_KEY_KEY = "__appKey";
const ALL_PERMISSIONS_KEY = "__permissions";
const ROLES_KEY = "__roles";

export class RoleRegistry {
  constructor() {
    this.roles = new Map();
    this.wildcards = new Map();
  }

  setRole(roleName, permissions = []) {
    const role = normalizePermission(roleName);
    if (!role) return;
    const permSet = new Set();
    const wildcardList = [];
    for (const p of permissions) {
      const norm = normalizePermission(p);
      if (!norm) continue;
      permSet.add(norm);
      if (norm.includes("*")) wildcardList.push(norm);
    }
    this.roles.set(role, permSet);
    this.wildcards.set(role, wildcardList);
  }

  addRolePermissions(roleName, permissions = []) {
    const role = normalizePermission(roleName);
    if (!role) return;
    const current = this.roles.get(role) || new Set();
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

  deleteRole(roleName) {
    const role = normalizePermission(roleName);
    this.roles.delete(role);
    this.wildcards.delete(role);
  }

  getRolePermissions(roleName) {
    return this.roles.get(normalizePermission(roleName)) || new Set();
  }

  hasRole(roleName) {
    return this.roles.has(normalizePermission(roleName));
  }

  clear() {
    this.roles.clear();
    this.wildcards.clear();
  }

  loadRoles(rolesMap = {}) {
    if (Array.isArray(rolesMap)) {
      for (const item of rolesMap) {
        if (item?.name) this.setRole(item.name, item.permissions || []);
      }
    } else if (rolesMap && typeof rolesMap === "object") {
      for (const [name, perms] of Object.entries(rolesMap)) this.setRole(name, perms);
    }
  }

  checkRoleHasPermission(roleName, requiredPermission) {
    const role = normalizePermission(roleName);
    const permSet = this.roles.get(role);
    if (!permSet) return false;
    if (permSet.has(requiredPermission) || permSet.has("*") || permSet.has("*:*:*")) return true;
    const wildcards = this.wildcards.get(role);
    return Boolean(wildcards?.length && wildcards.some((w) => permissionMatches(w, requiredPermission)));
  }
}

export const defaultRoleRegistry = new RoleRegistry();

export function definePermissions(manifest, options = {}) {
  const isStructured = manifest && typeof manifest === "object" && manifest.permissions && typeof manifest.permissions === "object";
  const permissionsSource = isStructured ? manifest.permissions : (manifest || {});
  const rolesSource = isStructured && manifest.roles ? manifest.roles : (options?.roles || {});

  const appKey = resolveAppKey(
    (isStructured && manifest.appKey) || options?.appKey || null,
    options?.fallbackAppKey || null
  );

  const out = {};
  const allPermissions = [];

  for (const [service, actions] of Object.entries(permissionsSource)) {
    const serviceKey = normalizePermission(service);
    if (!serviceKey || !actions || typeof actions !== "object") continue;
    const serviceObj = {};
    for (const [action] of Object.entries(actions)) {
      const actionKey = normalizePermission(action);
      if (!actionKey) continue;
      const permission = `${appKey}:${serviceKey}:${actionKey}`;
      serviceObj[actionKey] = permission;
      allPermissions.push(permission);
    }
    out[serviceKey] = serviceObj;
  }

  const declaredRoles = {};
  if (rolesSource && typeof rolesSource === "object") {
    for (const [roleName, roleDef] of Object.entries(rolesSource)) {
      const cleanRole = normalizePermission(roleName);
      if (!cleanRole) continue;

      const rawPerms = Array.isArray(roleDef) ? roleDef : (roleDef?.permissions || []);
      const label = roleDef && typeof roleDef === "object" && typeof roleDef.label === "string" ? roleDef.label : cleanRole;
      const description = roleDef && typeof roleDef === "object" && typeof roleDef.description === "string" ? roleDef.description : "";

      const rolePerms = [];
      for (const p of rawPerms) {
        if (typeof p !== "string" || !p.trim()) continue;
        const normP = normalizePermission(p);
        if (normP === "*" || normP === "*:*:*") rolePerms.push(`${appKey}:*:*`);
        else if (normP.split(":").length === 3) rolePerms.push(normP);
        else if (normP.split(":").length === 2) rolePerms.push(`${appKey}:${normP}`);
        else if (normP.includes(".")) rolePerms.push(resolvePermission(normP));
        else rolePerms.push(`${appKey}:${normP}`);
      }

      declaredRoles[cleanRole] = { name: cleanRole, label, description, permissions: [...new Set(rolePerms)] };
    }
  }

  const defineHidden = (key, value) => Object.defineProperty(out, key, { value, enumerable: false, configurable: false, writable: false });
  defineHidden(MANIFEST_KEY, permissionsSource);
  defineHidden(APP_KEY_KEY, appKey);
  defineHidden(ALL_PERMISSIONS_KEY, allPermissions);
  defineHidden(ROLES_KEY, declaredRoles);

  return out;
}

export function defineGlobalPermissions(manifest) {
  return definePermissions(manifest, { appKey: GLOBAL_APP_KEY });
}

export const GlobalPermissions = defineGlobalPermissions({ basic: { access: "Basic global access" } });

export function collectPermissions(permissions, appKeyOverride = null) {
  const manifest = permissions?.[MANIFEST_KEY] || permissions;
  const appKey = appKeyOverride || (typeof permissions?.[APP_KEY_KEY] === "string" && permissions[APP_KEY_KEY]) || normalizePermission(mbkautheVar.APP_NAME || "");
  const source = manifest && typeof manifest === "object" && !Array.isArray(manifest) ? manifest : {};
  const collected = [];

  for (const [service, actions] of Object.entries(source)) {
    if (!actions || typeof actions !== "object") continue;
    for (const [action, label] of Object.entries(actions)) {
      const [serviceKey, actionKey] = [service.toLowerCase().trim(), typeof action === "string" ? action.toLowerCase().trim() : ""];
      if (!serviceKey || !actionKey) continue;
      collected.push({
        appKey,
        serviceKey,
        actionKey,
        label: typeof label === "string" ? label : "",
        permission: `${appKey}:${serviceKey}:${actionKey}`,
      });
    }
  }
  return collected;
}

export function collectRoles(permissions) {
  return permissions?.[ROLES_KEY] ? Object.values(permissions[ROLES_KEY]) : [];
}

export function buildEffectivePermissions({ roles = [], allows = [], denies = [], roleRegistry = defaultRoleRegistry } = {}) {
  const normalizedAllows = allows.map(normalizePermission).filter(Boolean);
  const normalizedDenies = denies.map(normalizePermission).filter(Boolean);
  const base = new Set();
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

export function intersectPermissions(held, requested, roleRegistry = defaultRoleRegistry) {
  let heldAllows = [];
  let heldDenies = [];

  if (held && typeof held === "object" && (held.role || held.roles || held.overrides)) {
    const effective = buildEffectivePermissions({
      roles: [held.role, ...(held.roles || [])].filter(Boolean),
      allows: held.overrides?.allows || [],
      denies: held.overrides?.denies || [],
      roleRegistry,
    });
    heldAllows = effective.allows;
    heldDenies = effective.denies;
  } else {
    const norm = normalizePermissions(held);
    heldAllows = norm.allows;
    heldDenies = norm.denies;
  }

  const list = Array.isArray(requested)
    ? requested
    : (typeof requested === "string" ? requested.split(",") : normalizePermissions(requested).allows);

  const allows = [];
  for (const entry of list) {
    const permission = normalizePermission(entry);
    if (!permission || heldDenies.some((deny) => permissionMatches(deny, permission))) continue;
    if (heldAllows.some((allow) => permissionMatches(allow, permission))) allows.push(permission);
  }

  return { allows: [...new Set(allows)].sort(), denies: [] };
}

export function hasPermission(user, required, roleRegistry = defaultRoleRegistry) {
  if (!user) return false;

  const primaryRole = (typeof user.role === "string" ? user.role : "").toLowerCase();
  if (primaryRole === SUPERADMIN_ROLE || (Array.isArray(user.roles) && user.roles.some((r) => String(r).toLowerCase() === SUPERADMIN_ROLE))) {
    return true;
  }

  const resolvedRequired = resolvePermission(required);
  if (!resolvedRequired) return false;

  const userDenies = (user.overrides?.denies || user.permissions?.denies || []).map(normalizePermission).filter(Boolean);
  if (userDenies.some((deny) => permissionMatches(deny, resolvedRequired))) return false;

  const userRoles = new Set(primaryRole ? [primaryRole] : []);
  if (Array.isArray(user.roles)) {
    for (const r of user.roles) {
      const cleanR = normalizePermission(r);
      if (cleanR) userRoles.add(cleanR);
    }
  }

  for (const roleName of userRoles) {
    if (roleRegistry.checkRoleHasPermission(roleName, resolvedRequired)) return true;
  }

  const userAllows = (user.overrides?.allows || user.permissions?.allows || []).map(normalizePermission).filter(Boolean);
  return userAllows.some((allow) => permissionMatches(allow, resolvedRequired));
}

export { SUPERADMIN_ROLE };
