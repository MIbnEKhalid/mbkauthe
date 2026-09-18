/**
 * MBKAuthe — Session permission & role hydration helper.
 * Attaches assigned roles and allow/deny overrides to the express session user object.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { permissionRepository } from "../../db/repositories/PermissionRepository.js";
import type { EffectivePermissionsResult, SessionUser } from "../../core/types/index.js";

const MISSING_OBJECT_RE = /no such table|no such column|relation .* does not exist|column .* does not exist|does not exist|no such database/i;

const EMPTY_PERMISSIONS: EffectivePermissionsResult = Object.freeze({
  roles: [],
  overrides: { allows: [], denies: [] },
  effective: { allows: [], denies: [] },
  perm_version: 1,
});

function resetSessionUserPermissions(sessionUser?: Partial<SessionUser> | null): EffectivePermissionsResult {
  if (sessionUser) {
    sessionUser.roles = sessionUser.roles || [];
    sessionUser.overrides = { allows: [], denies: [] };
    sessionUser.permissions = { allows: [], denies: [] };
  }
  return EMPTY_PERMISSIONS;
}

export const SUPERADMIN_PERMISSIONS: EffectivePermissionsResult = Object.freeze({
  roles: ["superadmin"],
  overrides: { allows: ["*"], denies: [] },
  effective: { allows: ["*"], denies: [] },
  perm_version: 1,
});

/**
 * Attach roles and permission overrides to `sessionUser`.
 */
export async function attachSessionPermissions(
  sessionUser?: Partial<SessionUser> | null,
  username?: string | null,
  knownRole: string | null = null
): Promise<EffectivePermissionsResult> {
  if (!username) return resetSessionUserPermissions(sessionUser);

  const effectiveRole = (knownRole || sessionUser?.role || "").trim().toLowerCase();
  if (effectiveRole === "superadmin") {
    if (sessionUser) {
      sessionUser.roles = ["superadmin"];
      sessionUser.overrides = { allows: ["*"], denies: [] };
      sessionUser.permissions = { allows: ["*"], denies: [] };
    }
    return SUPERADMIN_PERMISSIONS;
  }

  try {
    const snapshot = await permissionRepository.computeEffectiveForUser(username, effectiveRole || null);
    if (sessionUser) {
      sessionUser.roles = snapshot.roles;
      sessionUser.overrides = snapshot.overrides;
      sessionUser.permissions = snapshot.effective;
    }
    return snapshot;
  } catch (err: any) {
    if (!MISSING_OBJECT_RE.test(err?.message || "")) {
      console.error(`[mbkauthe] Failed to compute effective permissions for "${username}":`, err);
    }
    return resetSessionUserPermissions(sessionUser);
  }
}

/**
 * True when the session carries no effective permissions or roles.
 */
export function hasNoSessionPermissions(sessionUser?: Partial<SessionUser> | null): boolean {
  const noRoles = !sessionUser?.roles?.length;
  const perms = sessionUser?.permissions as { allows?: string[]; denies?: string[] } | undefined;
  const noPerms = !perms || (!perms.allows?.length && !perms.denies?.length);
  return noRoles && noPerms;
}

export default attachSessionPermissions;
