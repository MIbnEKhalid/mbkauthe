/**
 * MBKAuthe — Bitmask Authorization Service
 * Pure bitmask evaluation service with zero DB lookups and nanosecond execution.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { AuthContext, AuthPrincipal, principalFromUser } from "../context/AuthContext.js";
import { evaluatePermission, evaluateRole, evaluateAppAccess, SUPERADMIN_ROLE } from "./evaluator.js";
import { STANDARD_NAME_TO_BIT } from "./resource.js";
import type { ActionDescriptor, PermissionTarget, ResourceMasks } from "../types/permission.types.js";
import { mbkautheVar } from "../../config/index.js";

export type PolicyFn = (context: AuthContext) => boolean | Promise<boolean>;

export class RoleRegistry {
  private roles = new Map<string, ResourceMasks>();

  setRole(roleName: string, permissions: string[] | ResourceMasks): this {
    const cleanRole = String(roleName || "").trim().toLowerCase();
    if (Array.isArray(permissions)) {
      const masks: ResourceMasks = {};
      for (const p of permissions) {
        const raw = String(p || "").trim().toLowerCase();
        masks[raw] = 1;
        if (raw.includes(":")) {
          const parts = raw.split(":");
          const res = parts.length === 3 ? parts[1] : parts[0];
          const act = parts.length === 3 ? parts[2] : parts[1];
          masks[res] = (masks[res] || 0) | (STANDARD_NAME_TO_BIT[act] || 1);
        }
      }
      this.roles.set(cleanRole, masks);
    } else if (permissions && typeof permissions === "object") {
      this.roles.set(cleanRole, permissions);
    }
    return this;
  }

  getRoleMasks(roleName: string): ResourceMasks {
    return this.roles.get(String(roleName || "").trim().toLowerCase()) || {};
  }
}

export class AuthorizationService {
  constructor(private roleRegistry?: RoleRegistry) {}

  /**
   * Extracts evaluation context from target (AuthContext, AuthPrincipal, or session user).
   */
  private extractContext(target: AuthContext | AuthPrincipal | any) {
    if (!target) {
      return { isSuperadmin: false, role: "guest", roles: ["guest"], masks: {}, allowedApps: [] };
    }

    const principal: AuthPrincipal =
      target instanceof AuthContext ? target.principal || (target as any) : target.principal || target;

    const role = (principal.role || "").toLowerCase();
    const roles: string[] = Array.isArray(principal.roles)
      ? principal.roles.map((r: any) => String(r).toLowerCase())
      : [role];

    const isSuperadmin = role === SUPERADMIN_ROLE || roles.includes(SUPERADMIN_ROLE);

    // Extract precomputed resource masks from principal.perms or principal.permissions
    let masks: ResourceMasks = {};
    if (principal.perms && typeof principal.perms === "object" && Object.keys(principal.perms).length > 0) {
      masks = { ...principal.perms };
    } else if (principal.permissions && typeof principal.permissions === "object" && !Array.isArray(principal.permissions) && Object.keys(principal.permissions).length > 0) {
      masks = { ...principal.permissions };
    } else if (this.roleRegistry) {
      for (const r of roles) {
        const rMasks = this.roleRegistry.getRoleMasks(r);
        for (const [k, v] of Object.entries(rMasks)) {
          masks[k] = (masks[k] || 0) | v;
        }
      }
    }

    // Apply explicit user overrides if present
    if (principal.overrides) {
      const allows = Array.isArray(principal.overrides.allows)
        ? principal.overrides.allows
        : Object.keys(principal.overrides.allows || {});
      const denies = Array.isArray(principal.overrides.denies)
        ? principal.overrides.denies
        : Object.keys(principal.overrides.denies || {});

      for (const allow of allows) {
        const raw = String(allow).trim().toLowerCase();
        masks[raw] = 1;
        if (raw.includes(":")) {
          const parts = raw.split(":");
          const res = parts.length === 3 ? parts[1] : parts[0];
          const act = parts.length === 3 ? parts[2] : parts[1];
          masks[res] = (masks[res] || 0) | (STANDARD_NAME_TO_BIT[act] || 1);
        }
      }

      for (const deny of denies) {
        const raw = String(deny).trim().toLowerCase();
        delete masks[raw];
        if (raw.includes(":")) {
          const parts = raw.split(":");
          const res = parts.length === 3 ? parts[1] : parts[0];
          const act = parts.length === 3 ? parts[2] : parts[1];
          const bit = STANDARD_NAME_TO_BIT[act] || 1;
          if (masks[res]) {
            masks[res] = masks[res] & ~bit;
            if (masks[res] <= 0) delete masks[res];
          }
        }
      }
    }

    const allowedApps = (principal.allowed_apps || []).map((a: any) => String(a).toLowerCase());

    return { isSuperadmin, role, roles, masks, allowedApps };
  }

  /**
   * Returns true if target has the SuperAdmin role.
   */
  isSuperadmin(target: AuthContext | AuthPrincipal | any): boolean {
    return this.extractContext(target).isSuperadmin;
  }

  /**
   * Evaluates if target satisfies any of the required roles.
   */
  hasRole(target: AuthContext | AuthPrincipal | any, role: string): boolean {
    return this.hasAnyRole(target, [role]);
  }

  hasAnyRole(target: AuthContext | AuthPrincipal | any, requiredRoles: string | string[]): boolean {
    const ctx = this.extractContext(target);
    return evaluateRole(ctx, requiredRoles);
  }

  isRoleDenied(target: AuthContext | AuthPrincipal | any, notAllowedRole?: string | null): boolean {
    if (!notAllowedRole || typeof notAllowedRole !== "string") return false;
    const ctx = this.extractContext(target);
    if (ctx.isSuperadmin) return false;
    const denied = notAllowedRole.trim().toLowerCase();
    return ctx.role === denied || ctx.roles.includes(denied);
  }

  /**
   * Evaluates if target has the required resource action permission.
   * Can accept:
   *   hasPermission(ctx, Permissions.tasks.view)
   *   hasPermission(ctx, "tasks", StandardActions.VIEW)
   *   hasPermission(ctx, "tasks", 1)
   */
  hasPermission(
    target: AuthContext | AuthPrincipal | any,
    resourceOrTarget: string | PermissionTarget,
    actionMask?: number
  ): boolean {
    const ctx = this.extractContext(target);
    return evaluatePermission(ctx, resourceOrTarget, actionMask);
  }

  hasAllPermissions(
    target: AuthContext | AuthPrincipal | any,
    targets: (PermissionTarget | [string, number])[]
  ): boolean {
    const ctx = this.extractContext(target);
    if (ctx.isSuperadmin) return true;
    return targets.every((t) => {
      if (Array.isArray(t)) return evaluatePermission(ctx, t[0], t[1]);
      return evaluatePermission(ctx, t);
    });
  }

  hasAnyPermission(
    target: AuthContext | AuthPrincipal | any,
    targets: (PermissionTarget | [string, number])[]
  ): boolean {
    const ctx = this.extractContext(target);
    if (ctx.isSuperadmin) return true;
    return targets.some((t) => {
      if (Array.isArray(t)) return evaluatePermission(ctx, t[0], t[1]);
      return evaluatePermission(ctx, t);
    });
  }

  canAccessApp(target: AuthContext | AuthPrincipal | any, appKey?: string): boolean {
    const ctx = this.extractContext(target);
    return evaluateAppAccess(ctx, appKey || mbkautheVar.APP_NAME);
  }

  async evaluatePolicy(target: AuthContext | AuthPrincipal | any, policy: PolicyFn): Promise<boolean> {
    const authContext = target instanceof AuthContext ? target : new AuthContext({ principal: target });
    try {
      return Boolean(await policy(authContext));
    } catch {
      return false;
    }
  }
}

export const authorizationService = new AuthorizationService();
