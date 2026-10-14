/**
 * MBKAuthe — Unified AuthContext & Principal Domain Model
 * High-performance, bitmask-aware authorization context.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type { AuthUser } from "../types/user.types.js";
import type { ResourceMasks, PermissionTarget, UserPermissionOverrides } from "../types/permission.types.js";
import { evaluatePermission, evaluateRole, SUPERADMIN_ROLE } from "../permissions/evaluator.js";

export interface AuthPrincipal {
  id?: string | number;
  user_id?: string | number;
  username: string;
  role: string;
  roles?: string[];
  full_name?: string;
  email?: string;
  image?: string | null;
  is_active?: boolean | number;
  is_enabled?: boolean | null;
  allowed_apps?: string[];
  user_allowed_apps?: string[];
  perms?: ResourceMasks;
  permissions?: ResourceMasks | any;
  overrides?: UserPermissionOverrides | any;
  perm_version?: number;
  must_change_password?: boolean;
  [key: string]: any;
}

export interface AuthSessionInfo {
  id: string;
  expiresAt?: Date | string | null;
  meta?: any;
  ip?: string;
  userAgent?: string;
  appKey?: string;
}

export interface AuthTokenInfo {
  id?: string | number;
  prefix?: string;
  name?: string;
  scopes?: string[];
  expiresAt?: Date | string | null;
  lastUsedAt?: Date | string | null;
}

export type AuthMethod = "session" | "api-token" | "oauth" | "cli" | "basic" | "none";

export interface AuthContextOptions {
  isAuthenticated?: boolean;
  authMethod?: AuthMethod;
  principal?: AuthPrincipal | null;
  session?: AuthSessionInfo | null;
  token?: AuthTokenInfo | null;
  appKey?: string;
  attributes?: Record<string, any>;
  permissions?: any;
}

export class AuthContext {
  public readonly isAuthenticated: boolean;
  public readonly authMethod: AuthMethod;
  public readonly principal: AuthPrincipal | null;
  public readonly session: AuthSessionInfo | null;
  public readonly token: AuthTokenInfo | null;
  public readonly appKey: string | null;
  public readonly attributes: Readonly<Record<string, any>>;

  public readonly user: AuthUser | null;
  public readonly permissions: ResourceMasks | any;
  public readonly type: "session" | "api-token" | string;

  constructor(options: AuthContextOptions = {}) {
    this.isAuthenticated = options.isAuthenticated ?? Boolean(options.principal?.username);
    this.authMethod = options.authMethod || (this.isAuthenticated ? "session" : "none");
    this.principal = options.principal || null;
    this.session = options.session || null;
    this.token = options.token || null;
    this.appKey = options.appKey || null;
    this.attributes = Object.freeze({ ...(options.attributes || {}) });

    this.user = (this.principal as unknown as AuthUser) || null;
    this.permissions = options.permissions !== undefined ? options.permissions : (this.principal?.perms || this.principal?.permissions || {});
    this.type = this.authMethod === "api-token" ? "api-token" : "session";
  }

  get username(): string {
    return this.principal?.username || "";
  }

  get userId(): string | number | null {
    return this.principal?.user_id || this.principal?.id || null;
  }

  get email(): string | null {
    return this.principal?.email || null;
  }

  get fullName(): string | null {
    return this.principal?.full_name || null;
  }

  get role(): string {
    return (this.principal?.role || "").toLowerCase();
  }

  get roles(): string[] {
    const list = new Set<string>();
    if (this.principal?.role) list.add(this.principal.role.toLowerCase());
    if (Array.isArray(this.principal?.roles)) {
      for (const r of this.principal.roles) {
        if (typeof r === "string" && r.trim()) list.add(r.trim().toLowerCase());
      }
    }
    return Array.from(list);
  }

  get masks(): ResourceMasks {
    if (this.principal?.perms && typeof this.principal.perms === "object") {
      return this.principal.perms;
    }
    if (this.permissions && typeof this.permissions === "object" && !Array.isArray(this.permissions)) {
      return this.permissions;
    }
    return {};
  }

  get mustChangePassword(): boolean {
    return Boolean(this.principal?.must_change_password);
  }

  isSuperadmin(): boolean {
    return this.role === SUPERADMIN_ROLE || this.roles.includes(SUPERADMIN_ROLE);
  }

  isAdmin(): boolean {
    return this.isSuperadmin() || this.role === "admin" || this.roles.includes("admin");
  }

  hasRole(...roles: string[]): boolean {
    return evaluateRole({ isSuperadmin: this.isSuperadmin(), role: this.role, roles: this.roles }, roles);
  }

  hasPermission(resourceOrTarget: string | PermissionTarget, actionMask?: number): boolean {
    if (!this.isAuthenticated) return false;
    return evaluatePermission(
      { isSuperadmin: this.isSuperadmin(), masks: this.masks },
      resourceOrTarget,
      actionMask
    );
  }

  can(resourceOrTarget: string | PermissionTarget, actionMask?: number): boolean {
    return this.hasPermission(resourceOrTarget, actionMask);
  }

  hasAllPermissions(...targets: (PermissionTarget | [string, number])[]): boolean {
    if (!this.isAuthenticated) return false;
    if (this.isSuperadmin()) return true;
    return targets.every((t) => {
      if (Array.isArray(t)) return this.hasPermission(t[0], t[1]);
      return this.hasPermission(t);
    });
  }

  hasAnyPermission(...targets: (PermissionTarget | [string, number])[]): boolean {
    if (!this.isAuthenticated) return false;
    if (this.isSuperadmin()) return true;
    return targets.some((t) => {
      if (Array.isArray(t)) return this.hasPermission(t[0], t[1]);
      return this.hasPermission(t);
    });
  }

  getMask(resource: string): number {
    return this.masks[resource.toLowerCase()] || 0;
  }

  with(updates: Partial<AuthContextOptions>): AuthContext {
    return new AuthContext({
      isAuthenticated: updates.isAuthenticated ?? this.isAuthenticated,
      authMethod: updates.authMethod ?? this.authMethod,
      principal: updates.principal !== undefined ? updates.principal : this.principal,
      session: updates.session !== undefined ? updates.session : this.session,
      token: updates.token !== undefined ? updates.token : this.token,
      appKey: updates.appKey !== undefined ? updates.appKey : (this.appKey || undefined),
      attributes: { ...this.attributes, ...(updates.attributes || {}) },
      permissions: updates.permissions !== undefined ? updates.permissions : this.permissions,
    });
  }
}

export function createAnonymousContext(appKey?: string): AuthContext {
  return new AuthContext({
    isAuthenticated: false,
    authMethod: "none",
    principal: null,
    appKey,
  });
}

export function principalFromUser(user: any): AuthPrincipal {
  if (!user || typeof user !== "object") {
    return {
      username: "",
      role: "guest",
      is_active: false,
      perms: {},
    };
  }

  const username = String(user.username || user.name || "").trim();
  const role = String(user.role || "normaluser").trim();
  const id = user.user_id !== undefined ? user.user_id : user.id;

  let roles: string[] = [];
  if (Array.isArray(user.roles)) {
    roles = user.roles.map((r: any) => String(r).trim().toLowerCase()).filter(Boolean);
  } else if (role) {
    roles = [role.toLowerCase()];
  }

  let allowedApps: string[] = [];
  if (Array.isArray(user.allowed_apps)) {
    allowedApps = user.allowed_apps.map((a: any) => String(a).trim().toLowerCase()).filter(Boolean);
  } else if (Array.isArray(user.user_allowed_apps)) {
    allowedApps = user.user_allowed_apps.map((a: any) => String(a).trim().toLowerCase()).filter(Boolean);
  }

  const perms: ResourceMasks = user.perms || user.permissions || {};

  return {
    id,
    user_id: id,
    username,
    role,
    roles,
    full_name: user.full_name || user.name || username,
    email: user.email,
    image: user.image || null,
    is_active: user.is_active !== undefined ? Boolean(user.is_active) : true,
    is_enabled: user.is_enabled !== undefined ? Boolean(user.is_enabled) : null,
    allowed_apps: allowedApps,
    user_allowed_apps: allowedApps,
    perms,
    permissions: perms,
    overrides: user.overrides,
    perm_version: Number(user.perm_version || 1),
    must_change_password: Boolean(user.must_change_password),
    ...user,
  };
}

export function createAuthContext(options: AuthContextOptions = {}): AuthContext {
  return new AuthContext(options);
}

export function createSessionAuthContext(user: any, sessionInfo?: Partial<AuthSessionInfo>): AuthContext {
  const principal = principalFromUser(user);
  return new AuthContext({
    isAuthenticated: Boolean(principal.username),
    authMethod: "session",
    principal,
    session: sessionInfo ? { id: sessionInfo.id || user.session_id || "", ...sessionInfo } : (user.session_id ? { id: user.session_id } : null),
    permissions: principal.perms,
  });
}

export function createTokenAuthContext(tokenUser: any, tokenInfo?: Partial<AuthTokenInfo>): AuthContext {
  const principal = principalFromUser(tokenUser);
  return new AuthContext({
    isAuthenticated: Boolean(principal.username),
    authMethod: "api-token",
    principal,
    token: tokenInfo ? { id: tokenInfo.id || tokenUser.id, ...tokenInfo } : (tokenUser.id ? { id: tokenUser.id } : null),
    permissions: principal.perms,
  });
}
