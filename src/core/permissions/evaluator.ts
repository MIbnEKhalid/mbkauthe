/**
 * MBKAuthe — Pure Bitmask Authorization Evaluator
 * Nanosecond-speed evaluation using direct bitwise operators.
 * Zero database access, zero runtime string hashing, zero allocations.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { hasAction } from "./bitmask.js";
import { STANDARD_NAME_TO_BIT } from "./resource.js";
import type { ActionDescriptor, PermissionTarget, ResourceMasks } from "../types/permission.types.js";

export const SUPERADMIN_ROLE = "superadmin";

export interface EvaluatorContext {
  isSuperadmin?: boolean;
  role?: string;
  roles?: string[];
  masks?: ResourceMasks;
  allowedApps?: string[];
}

/**
 * Resolves a permission target to a resource name and required action mask.
 */
export function resolveTarget(target: PermissionTarget, explicitMask?: number): { resource: string; mask: number } | null {
  if (!target) return null;

  if (typeof target === "object") {
    if (typeof (target as any).resource === "string" && typeof (target as any).mask === "number") {
      return { resource: (target as any).resource, mask: (target as any).mask };
    }
  }

  if (typeof target === "string") {
    const raw = target.trim().toLowerCase();
    if (!raw) return null;

    if (raw === "basic.access" || raw === "global:basic:access" || raw === "global.access" || raw === "global:access") {
      return { resource: "global", mask: 1 };
    }

    if (typeof explicitMask === "number" && explicitMask > 0) {
      return { resource: raw, mask: explicitMask };
    }

    if (raw.includes(":")) {
      const parts = raw.split(":");
      // support "service:action" or "app:service:action"
      const resource = parts.length === 3 ? parts[1] : parts[0];
      const action = parts.length === 3 ? parts[2] : parts[1];
      const mask = (typeof explicitMask === "number" && explicitMask > 0)
        ? explicitMask
        : (STANDARD_NAME_TO_BIT[action] || 1);
      return { resource, mask };
    }

    if (raw.includes(".")) {
      const parts = raw.split(".");
      const resource = parts[0];
      const action = parts[1];
      const mask = (typeof explicitMask === "number" && explicitMask > 0)
        ? explicitMask
        : (STANDARD_NAME_TO_BIT[action] || 1);
      return { resource, mask };
    }

    return { resource: raw, mask: (typeof explicitMask === "number" && explicitMask > 0) ? explicitMask : 1 };
  }

  return null;
}

/**
 * Evaluates whether the user has the required action mask for a given resource.
 */
export function evaluatePermission(
  context: EvaluatorContext,
  resourceOrTarget: string | PermissionTarget,
  actionMask?: number
): boolean {
  // 1. SuperAdmin bypass: instant return, zero mask checking
  if (context.isSuperadmin) return true;

  const resolved = resolveTarget(resourceOrTarget, actionMask);
  if (!resolved || resolved.mask <= 0) return false;

  // 2. Any authenticated non-guest user inherently possesses basic global access
  if (resolved.resource === "global" && (resolved.mask & 1) === 1) {
    if (context.role && context.role !== "guest") return true;
    if (Array.isArray(context.roles) && context.roles.length > 0 && !context.roles.every((r) => r === "guest")) return true;
  }

  const userMasks = context.masks;
  if (!userMasks) return false;

  const userMask = userMasks[resolved.resource];
  if (userMask && hasAction(userMask, resolved.mask)) {
    return true;
  }

  // Check raw string key in masks if passed as target string
  if (typeof resourceOrTarget === "string") {
    const rawKey = resourceOrTarget.trim().toLowerCase();
    if (userMasks[rawKey] && hasAction(userMasks[rawKey], resolved.mask)) {
      return true;
    }
  }

  return false;
}

/**
 * Evaluates role membership.
 */
export function evaluateRole(context: EvaluatorContext, requiredRoles: string | string[]): boolean {
  if (context.isSuperadmin) return true;

  const userRoles = new Set<string>();
  if (context.role) userRoles.add(context.role.toLowerCase());
  if (Array.isArray(context.roles)) {
    for (const r of context.roles) {
      if (typeof r === "string" && r.trim()) userRoles.add(r.trim().toLowerCase());
    }
  }

  const list = (Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles])
    .map((r) => (typeof r === "string" ? r.trim().toLowerCase() : String(r)));

  if (list.includes("any") || list.includes("*")) {
    return userRoles.size > 0;
  }

  return list.some((req) => userRoles.has(req));
}

/**
 * Evaluates application boundary access.
 */
export function evaluateAppAccess(context: EvaluatorContext, targetApp?: string): boolean {
  if (context.isSuperadmin) return true;
  if (!targetApp) return true;

  const cleanApp = targetApp.trim().toLowerCase();
  const allowed = context.allowedApps || [];
  return allowed.some((a) => String(a).trim().toLowerCase() === cleanApp);
}
