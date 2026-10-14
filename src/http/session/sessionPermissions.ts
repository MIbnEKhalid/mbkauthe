/**
 * MBKAuthe — Session Permission & Role Hydration (Bitmask Engine)
 * Attaches assigned roles and resource action bitmasks to the express session user object.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { permissionRepository } from "../../db/repositories/PermissionRepository.js";
import type { SessionUser } from "../../core/types/index.js";
import type { UserAuthorizationSnapshot } from "../../core/types/permission.types.js";

export const SUPERADMIN_SNAPSHOT: UserAuthorizationSnapshot = Object.freeze({
  role: "superadmin",
  roles: ["superadmin"],
  masks: {},
  isSuperadmin: true,
  perm_version: 1,
});

export const EMPTY_SNAPSHOT: UserAuthorizationSnapshot = Object.freeze({
  role: "guest",
  roles: ["guest"],
  masks: {},
  isSuperadmin: false,
  perm_version: 1,
});

/**
 * Attaches roles and precomputed resource action masks to `sessionUser`.
 */
export async function attachSessionPermissions(
  sessionUser?: Partial<SessionUser> | any,
  username?: string | null,
  knownRole: string | null = null
): Promise<UserAuthorizationSnapshot> {
  if (!username) {
    if (sessionUser) {
      sessionUser.roles = ["guest"];
      sessionUser.perms = {};
      sessionUser.permissions = {};
    }
    return EMPTY_SNAPSHOT;
  }

  const effectiveRole = (knownRole || sessionUser?.role || "").trim().toLowerCase();

  if (effectiveRole === "superadmin") {
    if (sessionUser) {
      sessionUser.roles = ["superadmin"];
      sessionUser.perms = {};
      sessionUser.permissions = {};
      sessionUser.isSuperadmin = true;
    }
    return SUPERADMIN_SNAPSHOT;
  }

  // Fast path: if sessionUser already carries hydrated bitmasks, return without DB lookup
  if (
    sessionUser &&
    sessionUser.perms &&
    typeof sessionUser.perms === "object" &&
    Array.isArray(sessionUser.roles) &&
    sessionUser.roles.length > 0 &&
    (knownRole ? sessionUser.roles.includes(effectiveRole) : true)
  ) {
    return {
      role: sessionUser.role || effectiveRole,
      roles: sessionUser.roles,
      masks: sessionUser.perms,
      isSuperadmin: false,
      perm_version: sessionUser.perm_version || 1,
    };
  }

  try {
    const snapshot = await permissionRepository.computeEffectiveForUser(username, effectiveRole || null);
    if (sessionUser) {
      sessionUser.role = snapshot.role;
      sessionUser.roles = snapshot.roles;
      sessionUser.perms = snapshot.masks;
      sessionUser.permissions = snapshot.masks;
      sessionUser.overrides = snapshot.overrides;
      sessionUser.perm_version = snapshot.perm_version;
      sessionUser.isSuperadmin = snapshot.isSuperadmin;
    }
    return snapshot;
  } catch (err: any) {
    console.error(`[mbkauthe] Failed to hydrate bitmask permissions for "${username}":`, err?.message || err);
    if (sessionUser) {
      sessionUser.roles = [effectiveRole || "normaluser"];
      sessionUser.perms = {};
      sessionUser.permissions = {};
    }
    return EMPTY_SNAPSHOT;
  }
}

/**
 * True when the session user carries no permissions (and is not superadmin).
 */
export function hasNoSessionPermissions(sessionUser?: Partial<SessionUser> | any): boolean {
  if (!sessionUser) return true;
  if (sessionUser.role === "superadmin" || (Array.isArray(sessionUser.roles) && sessionUser.roles.includes("superadmin"))) {
    return false;
  }
  const perms = sessionUser.perms || sessionUser.permissions;
  if (!perms || typeof perms !== "object") return true;
  return Object.keys(perms).length === 0;
}

export default attachSessionPermissions;
