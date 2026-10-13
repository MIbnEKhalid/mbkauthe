import { mbkautheVar } from "../../config/env.js";
import { normalizePermission } from "./matcher.js";
import { defaultRoleRegistry, GLOBAL_APP_KEY } from "./roleRegistry.js";
import type { DeclaredPermission, RoleDefinition } from "../types/permission.types.js";

export const MANIFEST_KEY = "__manifest";
export const APP_KEY_KEY = "__appKey";
export const ALL_PERMISSIONS_KEY = "__permissions";
export const ROLES_KEY = "__roles";

export class PermissionDescriptorNode {
  public id: number = 0;

  constructor(
    public appKey: string,
    public serviceKey: string,
    public actionKey: string,
    public label: string = "",
    explicitId?: number
  ) {
    if (typeof explicitId === "number" && explicitId > 0) {
      this.id = explicitId;
    }
  }

  get key(): string {
    return `${this.appKey}:${this.serviceKey}:${this.actionKey}`;
  }

  valueOf(): number {
    return this.id;
  }

  toString(): string {
    return String(this.id || this.key);
  }
}

export function resolveAppKey(appKey: string | null = null, fallbackAppKey: string | null = null): string {
  const resolved = normalizePermission(appKey || fallbackAppKey || mbkautheVar.APP_NAME || "");
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
  const allPermissions: PermissionDescriptorNode[] = [];
  const nodesByKey: Map<string, PermissionDescriptorNode> = new Map();

  for (const [service, actions] of Object.entries(permissionsSource as Record<string, any>)) {
    const serviceKey = normalizePermission(service);
    if (!serviceKey || !actions || typeof actions !== "object") continue;
    const serviceObj: Record<string, PermissionDescriptorNode> = {};

    for (const [action, actionDef] of Object.entries(actions as Record<string, any>)) {
      const actionKey = normalizePermission(action);
      if (!actionKey) continue;

      let explicitId: number | undefined;
      let label = "";

      if (typeof actionDef === "number") {
        explicitId = actionDef;
      } else if (typeof actionDef === "string") {
        label = actionDef;
      } else if (actionDef && typeof actionDef === "object") {
        explicitId = typeof actionDef.id === "number" ? actionDef.id : undefined;
        label = typeof actionDef.label === "string" ? actionDef.label : "";
      }

      if (!explicitId || explicitId <= 0) {
        let hash = 5381;
        const fullKey = `${appKey}:${serviceKey}:${actionKey}`;
        for (let i = 0; i < fullKey.length; i++) {
          hash = (((hash << 5) + hash) + fullKey.charCodeAt(i)) & 0x7fffffff;
        }
        explicitId = hash === 0 ? 1 : hash;
      }

      const node = new PermissionDescriptorNode(appKey, serviceKey, actionKey, label, explicitId);
      serviceObj[actionKey] = node;
      allPermissions.push(node);
      nodesByKey.set(`${serviceKey}:${actionKey}`, node);
      nodesByKey.set(`${serviceKey}.${actionKey}`, node);
      nodesByKey.set(`${appKey}:${serviceKey}:${actionKey}`, node);

      defaultRoleRegistry.registerCatalogItem(explicitId, appKey, serviceKey, actionKey, label);
    }
    out[serviceKey] = serviceObj;
  }

  const declaredRoles: Record<string, any> = {};
  if (rolesSource && typeof rolesSource === "object") {
    for (const [roleName, roleDef] of Object.entries(rolesSource as Record<string, any>)) {
      const cleanRole = normalizePermission(roleName);
      if (!cleanRole) continue;

      const rawPerms: any[] = Array.isArray(roleDef) ? roleDef : (roleDef?.permissions || []);
      const label = roleDef && typeof roleDef === "object" && typeof roleDef.label === "string" ? roleDef.label : cleanRole;
      const description = roleDef && typeof roleDef === "object" && typeof roleDef.description === "string" ? roleDef.description : "";

      const roleNodes: PermissionDescriptorNode[] = [];
      for (const p of rawPerms) {
        if (!p) continue;
        if (p instanceof PermissionDescriptorNode) {
          roleNodes.push(p);
        } else if (typeof p === "number" && p > 0) {
          const matching = allPermissions.find((n) => n.id === p);
          if (matching) roleNodes.push(matching);
        } else if (typeof p === "string") {
          const normP = normalizePermission(p);
          if (normP === "*" || normP === "*:*:*" || normP === `${appKey}:*` || normP === `${appKey}:*:*`) {
            roleNodes.push(...allPermissions);
          } else if (normP.endsWith(":*")) {
            const prefix = normP.replace(/:*$/, "");
            for (const n of allPermissions) {
              if (n.serviceKey === prefix || `${n.appKey}:${n.serviceKey}` === prefix) {
                roleNodes.push(n);
              }
            }
          } else {
            const matched = nodesByKey.get(normP);
            if (matched) {
              roleNodes.push(matched);
            } else {
              const knownId = defaultRoleRegistry.getIdByKey(normP);
              if (knownId > 0) {
                const desc = defaultRoleRegistry.getDescriptorById(knownId);
                const globalNode = new PermissionDescriptorNode(
                  desc?.appKey || "global",
                  desc?.serviceKey || "basic",
                  desc?.actionKey || "access",
                  desc?.label || "",
                  knownId
                );
                roleNodes.push(globalNode);
              }
            }
          }
        }
      }

      const uniqueNodes = Array.from(new Set(roleNodes));

      declaredRoles[cleanRole] = {
        name: cleanRole,
        label,
        description,
        nodes: uniqueNodes,
        get permissions(): number[] {
          return this.nodes.map((n: any) => n.id).filter((id: number) => id > 0);
        },
      };

      const rolePermIds = uniqueNodes.map((n) => n.id).filter((id) => id > 0);
      if (rolePermIds.length > 0) {
        defaultRoleRegistry.setRole(cleanRole, rolePermIds);
      }
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

export const GlobalPermissions = defineGlobalPermissions({ basic: { access: { id: 1, label: "Basic global access" } } });

export function collectPermissions(permissions: any, appKeyOverride: string | null = null): Array<DeclaredPermission & { appKey: string; key: string; node?: PermissionDescriptorNode }> {
  const nodes: PermissionDescriptorNode[] = permissions?.[ALL_PERMISSIONS_KEY] || [];
  const appKey = appKeyOverride || (typeof permissions?.[APP_KEY_KEY] === "string" && permissions[APP_KEY_KEY]) || normalizePermission(mbkautheVar.APP_NAME || "");

  if (nodes.length > 0) {
    return nodes.map((node) => ({
      id: node.id || undefined,
      appKey: node.appKey || appKey,
      serviceKey: node.serviceKey,
      actionKey: node.actionKey,
      label: node.label,
      key: node.key,
      node,
    }));
  }

  const manifest = permissions?.[MANIFEST_KEY] || permissions;
  const source = manifest && typeof manifest === "object" && !Array.isArray(manifest) ? manifest : {};
  const collected: Array<DeclaredPermission & { appKey: string; key: string }> = [];

  for (const [service, actions] of Object.entries(source)) {
    if (!actions || typeof actions !== "object") continue;
    for (const [action, labelOrDef] of Object.entries(actions as Record<string, any>)) {
      const [serviceKey, actionKey] = [normalizePermission(service), normalizePermission(action)];
      if (!serviceKey || !actionKey) continue;
      const label = typeof labelOrDef === "string" ? labelOrDef : (labelOrDef && typeof labelOrDef.label === "string" ? labelOrDef.label : "");
      const id = typeof labelOrDef === "number" ? labelOrDef : (labelOrDef && typeof labelOrDef.id === "number" ? labelOrDef.id : undefined);
      collected.push({
        id,
        appKey,
        serviceKey,
        actionKey,
        label,
        key: `${appKey}:${serviceKey}:${actionKey}`,
      });
    }
  }
  return collected;
}

export function collectRoles(permissions: any): RoleDefinition[] {
  if (!permissions?.[ROLES_KEY]) return [];
  return Object.values(permissions[ROLES_KEY]).map((r: any) => ({
    name: r.name,
    label: r.label,
    description: r.description,
    get permissions(): number[] {
      if (Array.isArray(r.nodes) && r.nodes.length > 0) {
        return r.nodes.map((n: any) => n.id).filter((id: number) => id > 0);
      }
      return Array.isArray(r.permissions) ? r.permissions : [];
    },
    nodes: r.nodes,
  } as any));
}

export default definePermissions;