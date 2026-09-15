/**
 * MBKAuthe — Unified AuthContext & Principal Domain Model
 * Defines the clean boundary representing the authenticated principal, session, and token information.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type { AuthUser } from "../types/user.types.js";

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
  overrides?: {
    allows: string[];
    denies: string[];
  };
  permissions?: {
    allows?: string[];
    denies?: string[];
  } | string[] | Record<string, boolean>;
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

  // Compatibility getter for legacy user object access
  public readonly user: AuthUser | null;
  public readonly permissions: any;
  public readonly type: "session" | "api-token" | string;

  constructor(options: AuthContextOptions = {}) {
    this.isAuthenticated = options.isAuthenticated ?? Boolean(options.principal?.username);
    this.authMethod = options.authMethod || (this.isAuthenticated ? "session" : "none");
    this.principal = options.principal || null;
    this.session = options.session || null;
    this.token = options.token || null;
    this.appKey = options.appKey || null;
    this.attributes = Object.freeze({ ...(options.attributes || {}) });

    // Backwards-compatible properties
    this.user = (this.principal as unknown as AuthUser) || null;
    this.permissions = options.permissions !== undefined ? options.permissions : (this.principal?.permissions || null);
    this.type = this.authMethod === "api-token" ? "api-token" : "session";
  }

  /**
   * Retrieves the username of the authenticated principal or empty string if unauthenticated.
   */
  get username(): string {
    return this.principal?.username || "";
  }

  /**
   * Retrieves the primary role of the principal.
   */
  get role(): string {
    return (this.principal?.role || "").toLowerCase();
  }

  /**
   * Retrieves all roles assigned to the principal.
   */
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

  /**
   * Clones this context with updated attributes or properties.
   */
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

/**
 * Creates an unauthenticated / anonymous AuthContext.
 */
export function createAnonymousContext(appKey?: string): AuthContext {
  return new AuthContext({
    isAuthenticated: false,
    authMethod: "none",
    principal: null,
    appKey,
  });
}

/**
 * Normalizes any user-like input object into a standardized AuthPrincipal.
 */
export function principalFromUser(user: any): AuthPrincipal {
  if (!user || typeof user !== "object") {
    return {
      username: "",
      role: "guest",
      is_active: false,
    };
  }

  const username = String(user.username || user.name || "").trim();
  const role = String(user.role || "normaluser").trim();
  const id = user.user_id !== undefined ? user.user_id : user.id;

  let roles: string[] = [];
  if (Array.isArray(user.roles)) {
    roles = user.roles.map((r: any) => String(r).trim().toLowerCase()).filter(Boolean);
  }

  let allowedApps: string[] = [];
  if (Array.isArray(user.allowed_apps)) {
    allowedApps = user.allowed_apps.map((a: any) => String(a).trim().toLowerCase()).filter(Boolean);
  } else if (Array.isArray(user.user_allowed_apps)) {
    allowedApps = user.user_allowed_apps.map((a: any) => String(a).trim().toLowerCase()).filter(Boolean);
  }

  let overrides: { allows: string[]; denies: string[] } | undefined;
  if (user.overrides && typeof user.overrides === "object") {
    overrides = {
      allows: Array.isArray(user.overrides.allows) ? user.overrides.allows.map(String) : [],
      denies: Array.isArray(user.overrides.denies) ? user.overrides.denies.map(String) : [],
    };
  }

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
    overrides,
    permissions: user.permissions,
    ...user,
  };
}

/**
 * Creates an AuthContext instance from provided options.
 */
export function createAuthContext(options: AuthContextOptions = {}): AuthContext {
  return new AuthContext(options);
}

/**
 * Creates an AuthContext for a session-based authenticated user.
 */
export function createSessionAuthContext(user: any, sessionInfo?: Partial<AuthSessionInfo>): AuthContext {
  const principal = principalFromUser(user);
  return new AuthContext({
    isAuthenticated: Boolean(principal.username),
    authMethod: "session",
    principal,
    session: sessionInfo ? { id: sessionInfo.id || user.session_id || "", ...sessionInfo } : (user.session_id ? { id: user.session_id } : null),
    permissions: principal.permissions,
  });
}

/**
 * Creates an AuthContext for an API token-authenticated principal.
 */
export function createTokenAuthContext(tokenUser: any, tokenInfo?: Partial<AuthTokenInfo>): AuthContext {
  const principal = principalFromUser(tokenUser);
  return new AuthContext({
    isAuthenticated: Boolean(principal.username),
    authMethod: "api-token",
    principal,
    token: tokenInfo ? { id: tokenInfo.id || tokenUser.id, ...tokenInfo } : (tokenUser.id ? { id: tokenUser.id } : null),
    permissions: principal.overrides || principal.permissions,
  });
}
