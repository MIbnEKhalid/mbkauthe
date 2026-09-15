/**
 * MBKAuthe — Dedicated Pure Authorization Service
 * Responsible for all authorization decisions: Roles, Permissions, Policies, and App Access.
 * Consumes an AuthContext or AuthPrincipal without performing authentication or database calls.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { AuthContext, AuthPrincipal, principalFromUser } from "../context/AuthContext.js";
import { RoleRegistry, defaultRoleRegistry, SUPERADMIN_ROLE } from "./roleRegistry.js";
import { resolvePermission, permissionMatches, normalizePermission } from "./matcher.js";
import { mbkautheVar } from "../../config/index.js";

export type PolicyFn = (context: AuthContext) => boolean | Promise<boolean>;

export class AuthorizationService {
  constructor(private roleRegistry: RoleRegistry = defaultRoleRegistry) {}

  /**
   * Helper to extract an AuthPrincipal from either an AuthContext, an AuthPrincipal, or legacy user object.
   */
  private extractPrincipal(target: AuthContext | AuthPrincipal | any): AuthPrincipal {
    if (!target) return principalFromUser(null);
    if (target instanceof AuthContext) {
      return target.principal || principalFromUser(null);
    }
    if (target.principal && typeof target.principal === "object") {
      return target.principal;
    }
    return principalFromUser(target);
  }

  /**
   * Helper to ensure an AuthContext is available for policy checks.
   */
  private toAuthContext(target: AuthContext | AuthPrincipal | any): AuthContext {
    if (target instanceof AuthContext) return target;
    const principal = this.extractPrincipal(target);
    return new AuthContext({
      isAuthenticated: Boolean(principal.username),
      principal,
      authMethod: target?.authMethod || "session",
    });
  }

  /**
   * Returns true if the principal has the SuperAdmin role (case-insensitive).
   */
  isSuperadmin(target: AuthContext | AuthPrincipal | any): boolean {
    const principal = this.extractPrincipal(target);
    const primaryRole = (principal.role || "").toLowerCase();
    if (primaryRole === SUPERADMIN_ROLE) return true;

    if (Array.isArray(principal.roles)) {
      return principal.roles.some((r: any) => String(r).toLowerCase() === SUPERADMIN_ROLE);
    }
    return false;
  }

  /**
   * Checks if the principal has a specific role.
   */
  hasRole(target: AuthContext | AuthPrincipal | any, role: string): boolean {
    return this.hasAnyRole(target, [role]);
  }

  /**
   * Checks if the principal satisfies any of the required roles (or wildcard / any / *).
   */
  hasAnyRole(target: AuthContext | AuthPrincipal | any, requiredRoles: string | string[]): boolean {
    const principal = this.extractPrincipal(target);
    if (this.isSuperadmin(principal)) return true;

    const userRoles = new Set<string>();
    if (principal.role) userRoles.add(principal.role.toLowerCase());
    if (Array.isArray(principal.roles)) {
      for (const r of principal.roles) {
        if (typeof r === "string" && r.trim()) userRoles.add(r.trim().toLowerCase());
      }
    }

    const list = (Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles])
      .map((r) => (typeof r === "string" ? r.trim().toLowerCase() : String(r)));

    if (list.includes("any") || list.includes("*")) {
      return userRoles.size > 0;
    }

    return list.some((reqRole) => userRoles.has(reqRole));
  }

  /**
   * Checks if the principal has a explicitly forbidden/denied role.
   */
  isRoleDenied(target: AuthContext | AuthPrincipal | any, notAllowedRole?: string | null): boolean {
    if (!notAllowedRole || typeof notAllowedRole !== "string") return false;
    const principal = this.extractPrincipal(target);
    const deniedNorm = notAllowedRole.trim().toLowerCase();
    const primaryRole = (principal.role || "").toLowerCase();

    if (primaryRole === deniedNorm) return true;
    if (Array.isArray(principal.roles) && principal.roles.some((r) => String(r).toLowerCase() === deniedNorm)) {
      return true;
    }
    return false;
  }

  /**
   * Evaluates if the principal is authorized for a specific permission.
   */
  hasPermission(
    target: AuthContext | AuthPrincipal | any,
    required: string,
    registry: RoleRegistry = this.roleRegistry
  ): boolean {
    const principal = this.extractPrincipal(target);
    if (!principal || !principal.username) return false;

    // 1. SuperAdmin bypass
    if (this.isSuperadmin(principal)) return true;

    const resolvedRequired = resolvePermission(required);
    if (!resolvedRequired) return false;

    // 2. Deny overrides always win
    const userDenies = (
      principal.overrides?.denies ||
      (principal.permissions as any)?.denies ||
      []
    ).map(normalizePermission).filter(Boolean);

    if (userDenies.some((deny: string) => permissionMatches(deny, resolvedRequired))) {
      return false;
    }

    // 3. Role-based permissions
    const userRoles = new Set<string>();
    if (principal.role) userRoles.add(principal.role.toLowerCase());
    if (Array.isArray(principal.roles)) {
      for (const r of principal.roles) {
        const clean = normalizePermission(r);
        if (clean) userRoles.add(clean);
      }
    }

    for (const roleName of userRoles) {
      if (registry.checkRoleHasPermission(roleName, resolvedRequired)) {
        return true;
      }
    }

    // 4. User Allow overrides
    const userAllows = (
      principal.overrides?.allows ||
      (principal.permissions as any)?.allows ||
      (Array.isArray(principal.permissions) ? principal.permissions : [])
    ).map(normalizePermission).filter(Boolean);

    return userAllows.some((allow: string) => permissionMatches(allow, resolvedRequired));
  }

  /**
   * Evaluates if the principal has all of the required permissions.
   */
  hasAllPermissions(
    target: AuthContext | AuthPrincipal | any,
    requiredList: string[],
    registry: RoleRegistry = this.roleRegistry
  ): boolean {
    return requiredList.every((p) => this.hasPermission(target, p, registry));
  }

  /**
   * Evaluates if the principal has at least one of the required permissions.
   */
  hasAnyPermission(
    target: AuthContext | AuthPrincipal | any,
    requiredList: string[],
    registry: RoleRegistry = this.roleRegistry
  ): boolean {
    return requiredList.some((p) => this.hasPermission(target, p, registry));
  }

  /**
   * Checks if the principal is authorized to access a given application.
   */
  canAccessApp(target: AuthContext | AuthPrincipal | any, appKey?: string): boolean {
    const principal = this.extractPrincipal(target);
    if (this.isSuperadmin(principal)) return true;

    const targetApp = (appKey || mbkautheVar.APP_NAME || "").toLowerCase().trim();
    if (!targetApp) return true;

    const allowed = principal.allowed_apps || principal.user_allowed_apps || [];
    return Array.isArray(allowed) && allowed.some((app: any) => String(app).toLowerCase().trim() === targetApp);
  }

  /**
   * Evaluates an arbitrary authorization policy function against the AuthContext.
   */
  async evaluatePolicy(target: AuthContext | AuthPrincipal | any, policy: PolicyFn): Promise<boolean> {
    const context = this.toAuthContext(target);
    try {
      return Boolean(await policy(context));
    } catch {
      return false;
    }
  }
}

export const authorizationService = new AuthorizationService();
