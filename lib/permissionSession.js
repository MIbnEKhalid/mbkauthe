/**
 * MBKAuthe — Session permission caching helper.
 *
 * Computes a user's effective permissions from the database and stores them on
 * the session user object (`req.session.user.permissions`). This runs ONLY at
 * session creation / login / explicit session reload — never during the normal
 * request authorization path (`hasPermission`/`permChk`/`sessPerm` are pure
 * in-memory and perform no database access).
 *
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { permissionRepository } from "./db/PermissionRepository.js";

const MISSING_OBJECT_RE = /no such table|no such column|relation .* does not exist|column .* does not exist|does not exist|no such database/i;

function isEmptyPermissions(perms) {
  return !perms || (Array.isArray(perms?.allows) && perms.allows.length === 0 && Array.isArray(perms?.denies) && perms.denies.length === 0);
}

/**
 * Compute a user's effective permissions and cache them on `sessionUser`.
 *
 * Permission caching is best-effort and non-fatal: if the permission tables or
 * columns are not yet present (pre-upgrade database) the session still works
 * and simply carries an empty permission set — existing role/session checks are
 * unaffected. This mirrors the additive, backward-compatible design of the
 * dynamic permission model.
 *
 * @param {object|null|undefined} sessionUser - `req.session.user` (mutated in place)
 * @param {string} username
 * @returns {Promise<{ allows: string[], denies: string[] }>}
 */
export async function attachSessionPermissions(sessionUser, username) {
  if (!username) {
    if (sessionUser) sessionUser.permissions = { allows: [], denies: [] };
    return { allows: [], denies: [] };
  }

  try {
    const effective = await permissionRepository.computeEffectiveForUser(username);
    const permissions = {
      allows: effective.allows,
      denies: effective.denies,
    };
    if (sessionUser) sessionUser.permissions = permissions;
    return permissions;
  } catch (err) {
    const message = err?.message || "";
    if (!MISSING_OBJECT_RE.test(message)) {
      console.error(`[mbkauthe] Failed to compute effective permissions for "${username}":`, err);
    }
    if (sessionUser) sessionUser.permissions = { allows: [], denies: [] };
    return { allows: [], denies: [] };
  }
}

/**
 * True when the session carries no effective permissions at all (used for
 * telemetry/debug; NOT the authorization decision — see hasPermission).
 */
export function hasNoSessionPermissions(sessionUser) {
  return isEmptyPermissions(sessionUser?.permissions);
}

export default attachSessionPermissions;
