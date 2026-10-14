/**
 * MBKAuthe — Resource and Action Mask Definitions
 * Declares resources and deterministic action masks with zero runtime hashing.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { StandardActionBits } from "./bitmask.js";
import type { ActionDescriptor, ResourceDefinition, ResourceMasks } from "../types/permission.types.js";

export const STANDARD_NAME_TO_BIT: Record<string, number> = {
  view: StandardActionBits.VIEW,
  read: StandardActionBits.VIEW,
  list: StandardActionBits.VIEW,
  get: StandardActionBits.VIEW,

  create: StandardActionBits.CREATE,
  add: StandardActionBits.CREATE,
  new: StandardActionBits.CREATE,
  upload: StandardActionBits.CREATE,

  update: StandardActionBits.UPDATE,
  edit: StandardActionBits.UPDATE,
  patch: StandardActionBits.UPDATE,
  modify: StandardActionBits.UPDATE,

  delete: StandardActionBits.DELETE,
  remove: StandardActionBits.DELETE,
  destroy: StandardActionBits.DELETE,

  manage: StandardActionBits.MANAGE,
  admin: StandardActionBits.MANAGE,
};

/**
 * Computes a deterministic numeric ID from a canonical permission key (e.g. "chat:send" or "portal:dns:view").
 */
export function hashPermissionKey(key: string): number {
  const clean = String(key || "").trim().toLowerCase();
  const parts = clean.split(":");
  const canonicalKey = parts.length === 3 ? `${parts[1]}:${parts[2]}` : clean;
  let hash = 0;
  for (let i = 0; i < canonicalKey.length; i++) {
    hash = (Math.imul(31, hash) + canonicalKey.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) || 1;
}

/**
 * Deterministically resolves a permission identifier into a numeric ID.
 */
export function resolvePermissionId(permission: any): number {
  if (typeof permission === "number") return permission;
  if (!permission) return 0;
  if (typeof permission === "object") {
    if (typeof permission.id === "number" && permission.id > 0) return permission.id;
    if (typeof permission.mask === "number" && permission.mask > 0) return permission.mask;
    if (typeof permission.key === "string") return hashPermissionKey(permission.key);
  }
  if (typeof permission === "string") {
    return hashPermissionKey(permission);
  }
  return 0;
}

export function permissionIdMatches(a: any, b: any): boolean {
  const idA = resolvePermissionId(a);
  const idB = resolvePermissionId(b);
  return idA > 0 && idB > 0 && idA === idB;
}

/**
 * Creates a single immutable ActionDescriptor.
 */
export function createActionDescriptor(
  resource: string,
  action: string,
  mask: number,
  label?: string,
  appKey?: string
): ActionDescriptor {
  const fullKey = appKey ? `${appKey}:${resource}:${action}` : `${resource}:${action}`;
  const deterministicId = hashPermissionKey(fullKey);
  const desc: ActionDescriptor = {
    resource: String(resource),
    action: String(action),
    mask: Number(mask),
    id: deterministicId,
    key: fullKey,
    label: label || `${String(resource)} ${String(action)}`,
    valueOf(): number {
      return this.mask;
    },
    toString(): string {
      return fullKey;
    },
  };
  return Object.freeze(desc);
}

/**
 * Defines a single resource with deterministic action bit assignments.
 */
export function defineResource(
  name: string,
  rawActions: Record<string, string | number | { bit?: number; mask?: number; label?: string }>,
  options: { label?: string; app?: string } = {}
): ResourceDefinition {
  const resourceName = String(name || "").trim().toLowerCase();
  if (!resourceName) {
    throw new Error("[mbkauthe] Resource name cannot be empty");
  }

  const actions: Record<string, ActionDescriptor> = {};
  let usedBits = 0;
  let nextCustomBit = 5; // Start custom bits at 1 << 5 (32)

  // First pass: assign explicit or standard bits
  for (const [actionName, def] of Object.entries(rawActions)) {
    const cleanAction = actionName.trim().toLowerCase();
    if (!cleanAction) continue;

    let mask = 0;
    let label = "";

    if (typeof def === "number" && def > 0) {
      mask = def;
    } else if (typeof def === "string") {
      label = def;
      if (STANDARD_NAME_TO_BIT[cleanAction]) {
        mask = STANDARD_NAME_TO_BIT[cleanAction];
      }
    } else if (def && typeof def === "object") {
      label = def.label || "";
      if (typeof def.mask === "number" && def.mask > 0) {
        mask = def.mask;
      } else if (typeof def.bit === "number" && def.bit >= 0) {
        mask = 1 << def.bit;
      } else if (STANDARD_NAME_TO_BIT[cleanAction]) {
        mask = STANDARD_NAME_TO_BIT[cleanAction];
      }
    }

    if (mask > 0) {
      usedBits |= mask;
      actions[cleanAction] = createActionDescriptor(resourceName, cleanAction, mask, label, options.app);
    }
  }

  // Second pass: assign remaining actions to next available bit positions
  for (const [actionName, def] of Object.entries(rawActions)) {
    const cleanAction = actionName.trim().toLowerCase();
    if (actions[cleanAction]) continue;

    while (nextCustomBit < 30 && (usedBits & (1 << nextCustomBit)) !== 0) {
      nextCustomBit++;
    }

    if (nextCustomBit >= 30) {
      throw new Error(`[mbkauthe] Resource "${resourceName}" exceeded maximum 30 distinct action bits.`);
    }

    const mask = 1 << nextCustomBit;
    usedBits |= mask;
    nextCustomBit++;

    const label = typeof def === "string" ? def : (def as any)?.label || "";
    actions[cleanAction] = createActionDescriptor(resourceName, cleanAction, mask, label, options.app);
  }

  // Calculate composite allMask for wildcards
  let allMask = 0;
  for (const desc of Object.values(actions)) {
    allMask |= desc.mask;
  }

  actions["*"] = createActionDescriptor(resourceName, "*", allMask, `All ${resourceName} actions`, options.app);
  actions["all"] = actions["*"];

  return Object.freeze({
    name: resourceName,
    label: options.label || resourceName,
    app: options.app,
    actions: Object.freeze(actions),
    allMask,
  });
}

/**
 * Defines a complete catalog of resources from a manifest.
 * Used by consuming applications to declare their permissions interface.
 */
export function defineResources(
  manifest: Record<string, Record<string, any>>,
  options: { app?: string; fallbackAppKey?: string; roles?: Record<string, any> } = {}
): any {
  const result: Record<string, any> = {};
  const definitions: Record<string, ResourceDefinition> = {};
  const appKey = options.app || options.fallbackAppKey || "portal";

  for (const [resKey, actionDefs] of Object.entries(manifest || {})) {
    if (!actionDefs || typeof actionDefs !== "object") continue;
    const itemApp = (actionDefs as any)?.__app || (actionDefs as any)?.app || appKey;
    const itemLabel = (actionDefs as any)?.__label || (actionDefs as any)?.label;
    const cleanActionDefs: Record<string, any> = {};
    for (const [k, v] of Object.entries(actionDefs)) {
      if (k === "__app" || k === "app" || k === "__label" || k === "label") continue;
      cleanActionDefs[k] = v;
    }
    const def = defineResource(resKey, cleanActionDefs, { app: itemApp, label: itemLabel });
    definitions[def.name] = def;

    // Attach actions directly so callers use Permissions.tasks.view
    const resourceObj: Record<string, ActionDescriptor> = { ...def.actions };
    (resourceObj as any).__definition = def;
    result[def.name] = resourceObj;
  }

  const allPermissions: ActionDescriptor[] = [];
  for (const def of Object.values(definitions)) {
    for (const [actKey, actionDesc] of Object.entries(def.actions)) {
      if (actKey !== "*" && actKey !== "all") {
        allPermissions.push(actionDesc);
      }
    }
  }

  result.__appKey = appKey;
  result.__permissions = allPermissions;
  result.__definitions = definitions;
  result.__roles = parseRoleDeclarations(definitions, options.roles);

  return result;
}

/**
 * Parses role manifests into pure resource bitmask maps.
 * Handles wildcards: "tasks:*" -> { tasks: tasksDef.allMask }
 */
export function parseRoleDeclarations(
  definitions: Record<string, ResourceDefinition>,
  rolesSource: Record<string, any> = {}
): Record<string, { label?: string; description?: string; permissions: ResourceMasks }> {
  const roles: Record<string, { label?: string; description?: string; permissions: ResourceMasks }> = {};

  for (const [roleName, roleDef] of Object.entries(rolesSource || {})) {
    const cleanRole = roleName.trim().toLowerCase();
    if (!cleanRole) continue;

    const label = typeof roleDef?.label === "string" ? roleDef.label : cleanRole;
    const description = typeof roleDef?.description === "string" ? roleDef.description : "";
    const rawList: any[] = Array.isArray(roleDef) ? roleDef : (roleDef?.permissions || []);

    const masks: ResourceMasks = {};

    // If permissions was already a map of { [resource]: maskNumber }
    if (roleDef?.permissions && typeof roleDef.permissions === "object" && !Array.isArray(roleDef.permissions)) {
      for (const [res, mask] of Object.entries(roleDef.permissions)) {
        if (typeof mask === "number") masks[res] = mask;
      }
    } else {
      for (const item of rawList) {
        if (!item) continue;
        if (typeof item === "object" && item.resource && typeof item.mask === "number") {
          masks[item.resource] = (masks[item.resource] || 0) | item.mask;
        } else if (typeof item === "string") {
          const str = item.trim().toLowerCase();
          if (str === "*" || str === "*:*") {
            for (const [res, def] of Object.entries(definitions)) {
              masks[res] = def.allMask;
            }
          } else if (str.includes(":")) {
            const [resPart, actPart] = str.split(":");
            const res = resPart.trim();
            const act = actPart.trim();
            const def = definitions[res];
            if (def) {
              if (act === "*") {
                masks[res] = def.allMask;
              } else if (def.actions[act]) {
                masks[res] = (masks[res] || 0) | def.actions[act].mask;
              }
            }
          }
        }
      }
    }

    roles[cleanRole] = { label, description, permissions: masks };
  }

  return roles;
}

// Canonical aliases for backward-compatible naming
export const definePermissions = defineResources;

export const GlobalAccess = createActionDescriptor("global", "access", 1, "Basic global access");
export const GlobalPermissions = Object.freeze({
  basic: Object.freeze({
    access: GlobalAccess,
  }),
});
