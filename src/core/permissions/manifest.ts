import { mbkautheVar } from "../../config/env.js";
import { normalizePermission, resolvePermission } from "./matcher.js";
import { defaultRoleRegistry, GLOBAL_APP_KEY } from "./roleRegistry.js";
import type { DeclaredPermission, RoleDefinition } from "../types/permission.types.js";

export const MANIFEST_KEY = "__manifest";
export const APP_KEY_KEY = "__appKey";
export const ALL_PERMISSIONS_KEY = "__permissions";
export const ROLES_KEY = "__roles";

export function resolveAppKey(appKey: string | null = null, fallbackAppKey: string | null = null): string {
  const resolved = normalizePermission(appKey || mbkautheVar.APP_NAME || fallbackAppKey || "");
  if (!resolved) {
    throw new Error(
      "[mbkauthe] definePermissions/syncAppPermissions requires an app key. Set APP_NAME (mbkautheVar.APP_NAME), pass the `appKey` option, or provide `fallbackAppKey`."
    );
  }
  return resolved;
}

export function definePermissions(
  manifest: any,
  options: { appKey?: string | null; fallbackAppKey?: string | null; roles?: any } = {}
): any {
  const isStructured = manifest && typeof manifest === "object" && manifest.permissions && typeof manifest.permissions === "object";
  const permissionsSource = isStructured ? manifest.permissions : (manifest || {});
  const rolesSource = isStructured && manifest.roles ? manifest.roles : (options?.roles || {});

  const appKey = resolveAppKey(
    (isStructured && manifest.appKey) || options?.appKey || null,
    options?.fallbackAppKey || null
  );

  const out: Record<string, any> = {};
  const allPermissions: string[] = [];

  for (const [service, actions] of Object.entries(permissionsSource as Record<string, any>)) {
    const serviceKey = normalizePermission(service);
    if (!serviceKey || !actions || typeof actions !== "object") continue;
    const serviceObj: Record<string, string> = {};
    for (const [action] of Object.entries(actions as Record<string, any>)) {
      const actionKey = normalizePermission(action);
      if (!actionKey) continue;
      const permission = `${appKey}:${serviceKey}:${actionKey}`;
      serviceObj[actionKey] = permission;
      allPermissions.push(permission);
    }
    out[serviceKey] = serviceObj;
  }

  const declaredRoles: Record<string, any> = {};
  if (rolesSource && typeof rolesSource === "object") {
    for (const [roleName, roleDef] of Object.entries(rolesSource as Record<string, any>)) {
      const cleanRole = normalizePermission(roleName);
      if (!cleanRole) continue;

      const rawPerms: string[] = Array.isArray(roleDef) ? roleDef : (roleDef?.permissions || []);
      const label = roleDef && typeof roleDef === "object" && typeof roleDef.label === "string" ? roleDef.label : cleanRole;
      const description = roleDef && typeof roleDef === "object" && typeof roleDef.description === "string" ? roleDef.description : "";

      const rolePerms: string[] = [];
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
      defaultRoleRegistry.setRole(cleanRole, [...new Set(rolePerms)]);
    }
  }

  const defineHidden = (key: string, value: any) => Object.defineProperty(out, key, { value, enumerable: false, configurable: false, writable: false });
  defineHidden(MANIFEST_KEY, permissionsSource);
  defineHidden(APP_KEY_KEY, appKey);
  defineHidden(ALL_PERMISSIONS_KEY, allPermissions);
  defineHidden(ROLES_KEY, declaredRoles);

  return out;
}

export function defineGlobalPermissions(manifest: any, options: any = {}): any {
  return definePermissions(manifest, { ...options, appKey: GLOBAL_APP_KEY });
}

export const GlobalPermissions = defineGlobalPermissions({ basic: { access: "Basic global access" } });

export function collectPermissions(permissions: any, appKeyOverride: string | null = null): Array<DeclaredPermission & { appKey: string; permission: string }> {
  const manifest = permissions?.[MANIFEST_KEY] || permissions;
  const appKey = appKeyOverride || (typeof permissions?.[APP_KEY_KEY] === "string" && permissions[APP_KEY_KEY]) || normalizePermission(mbkautheVar.APP_NAME || "");
  const source = manifest && typeof manifest === "object" && !Array.isArray(manifest) ? manifest : {};
  const collected: Array<DeclaredPermission & { appKey: string; permission: string }> = [];

  for (const [service, actions] of Object.entries(source)) {
    if (!actions || typeof actions !== "object") continue;
    for (const [action, label] of Object.entries(actions as Record<string, any>)) {
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

export function collectRoles(permissions: any): RoleDefinition[] {
  return permissions?.[ROLES_KEY] ? Object.values(permissions[ROLES_KEY]) : [];
}

export default definePermissions;
