/**
 * MBKAuthe — Dynamic permission core (pure, in-memory).
 *
 * Permissions use the form `app:service:action` and are resolved into
 * concrete permission strings by `definePermissions()`. `hasPermission()`
 * performs the in-memory authorization decision — it is pure, synchronous,
 * and MUST NEVER touch the database or the network.
 *
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { mbkautheVar } from "#config.js";

const SUPERADMIN_ROLE = "superadmin";
export const GLOBAL_APP_KEY = "global";

/**
 * Normalize a permission string to lowercase segments for comparison.
 * @param {*} value
 * @returns {string}
 */
export function normalizePermission(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}

/**
 * Resolve the two-segment `service.action` shorthand to a global permission.
 * Fully-qualified `app:service:action` permissions are returned unchanged.
 *
 * @param {*} value
 * @returns {string}
 */
export function resolvePermission(value) {
  const normalized = normalizePermission(value);
  if (normalized.split(".").length === 2 && !normalized.includes(":")) {
    const [service, action] = normalized.split(".");
    if (service && action) return `${GLOBAL_APP_KEY}:${service}:${action}`;
  }
  return normalized;
}

/**
 * Split `app:service:action` into its three segments.
 * @param {*} value
 * @returns {string[]}
 */
export function splitPermission(value) {
  const normalized = normalizePermission(value);
  if (!normalized) return [];
  return normalized.split(":").map((s) => s.trim());
}

function segmentMatches(a, b) {
  return a === "*" || b === "*" || a === b;
}

/**
 * Wildcard-aware segment matcher for `app:service:action` permission strings.
 * Any of the three segments may be `*` on either side.
 *
 * @param {string} stored - a permission held by the user (may contain `*`)
 * @param {string} required - the permission being requested (may contain `*`)
 * @returns {boolean}
 */
export function permissionMatches(stored, required) {
  const a = splitPermission(stored);
  const b = splitPermission(required);
  if (a.length !== 3 || b.length !== 3) return false;
  return (
    segmentMatches(a[0], b[0]) &&
    segmentMatches(a[1], b[1]) &&
    segmentMatches(a[2], b[2])
  );
}

/**
 * Coerce a `user.permissions` value into a normalized `{ allows, denies }`
 * shape. Plain string arrays are treated as a backward-compatible allow list.
 *
 * @param {*} permissions
 * @returns {{ allows: string[], denies: string[] }}
 */
export function normalizePermissions(permissions) {
  if (Array.isArray(permissions)) {
    return {
      allows: permissions.map(normalizePermission).filter(Boolean),
      denies: [],
    };
  }
  if (permissions && typeof permissions === "object") {
    const allows = Array.isArray(permissions.allows) ? permissions.allows : [];
    const denies = Array.isArray(permissions.denies) ? permissions.denies : [];
    return {
      allows: allows.map(normalizePermission).filter(Boolean),
      denies: denies.map(normalizePermission).filter(Boolean),
    };
  }
  if (typeof permissions === "string" && permissions.trim()) {
    return { allows: [normalizePermission(permissions)], denies: [] };
  }
  return { allows: [], denies: [] };
}

/**
 * Resolve the app key used for permission prefixing.
 *
 * Resolution order: explicit `appKey` > configured `mbkautheVar.APP_NAME` >
 * `fallbackAppKey` (per-app default) > throw.
 * @param {string|null} [appKey]
 * @param {string|null} [fallbackAppKey]
 * @returns {string}
 */
export function resolveAppKey(appKey = null, fallbackAppKey = null) {
  const resolved = normalizePermission(appKey || mbkautheVar.APP_NAME || fallbackAppKey || "");
  if (!resolved) {
    throw new Error(
      "[mbkauthe] definePermissions/syncAppPermissions requires an app key. Set APP_NAME (mbkautheVar.APP_NAME), pass the `appKey` option, or provide `fallbackAppKey`."
    );
  }
  return resolved;
}

const MANIFEST_KEY = "__manifest";
const APP_KEY_KEY = "__appKey";
const ALL_PERMISSIONS_KEY = "__permissions";

/**
 * Define an application's permission manifest.
 *
 * ```js
 * export const Permissions = definePermissions({
 *   posts: {
 *     create: "Create posts",
 *     edit:   "Edit posts",
 *     delete: "Delete posts",
 *   },
 *   comments: {
 *     moderate: "Moderate comments",
 *   },
 * });
 *
 * Permissions.posts.delete; // -> "blog:posts:delete"
 * ```
 *
 * The app key is taken from the existing mbkauthe configuration
 * (`mbkautheVar.APP_NAME`) unless overridden via the `appKey` option; a
 * `fallbackAppKey` can be supplied for applications that may not set APP_NAME.
 *
 * The returned object carries the raw manifest and the resolved app key on
 * non-enumerable properties (`__manifest`, `__appKey`, `__permissions`) so
 * `syncAppPermissions(Permissions)` and the catalog can introspect it without
 * polluting the developer-facing `Permissions.*` API.
 *
 * @param {Record<string, Record<string, string>>} manifest - service -> action -> label
 * @param {{ appKey?: string, fallbackAppKey?: string }} [options]
 * @returns {Record<string, Record<string, string>> & { __manifest: object, __appKey: string, __permissions: string[] }}
 */
export function definePermissions(manifest, options = {}) {
  const appKey = resolveAppKey(options?.appKey || null, options?.fallbackAppKey || null);
  const source =
    manifest && typeof manifest === "object" && !Array.isArray(manifest)
      ? manifest
      : {};

  const out = {};
  const allPermissions = [];

  for (const [service, actions] of Object.entries(source)) {
    const serviceKey = normalizePermission(service);
    if (!serviceKey || !actions || typeof actions !== "object") continue;
    const serviceObj = {};
    for (const [action] of Object.entries(actions)) {
      const actionKey = normalizePermission(action);
      if (!actionKey) continue;
      const permission = `${appKey}:${serviceKey}:${actionKey}`;
      serviceObj[actionKey] = permission;
      allPermissions.push(permission);
    }
    out[serviceKey] = serviceObj;
  }

  Object.defineProperty(out, MANIFEST_KEY, {
    value: source,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  Object.defineProperty(out, APP_KEY_KEY, {
    value: appKey,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  Object.defineProperty(out, ALL_PERMISSIONS_KEY, {
    value: allPermissions,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return out;
}

/**
 * Define permissions shared by every application under the reserved `global`
 * app key. These permissions are cataloged by the auth schema, not an app
 * manifest sync.
 *
 * @param {Record<string, Record<string, string>>} manifest
 * @returns {Record<string, Record<string, string>>}
 */
export function defineGlobalPermissions(manifest) {
  return definePermissions(manifest, { appKey: GLOBAL_APP_KEY });
}

export const GlobalPermissions = defineGlobalPermissions({
  basic: { access: "Basic global access" },
});

/**
 * Collect every declared permission from a `definePermissions()` result (or a
 * raw `service -> action -> label` manifest).
 * @param {object} permissions
 * @param {string|null} [appKeyOverride] - explicit app key to use (overrides the
 *   manifest's own app key / configured APP_NAME)
 * @returns {Array<{ appKey: string, serviceKey: string, actionKey: string, label: string, permission: string }>}
 */
export function collectPermissions(permissions, appKeyOverride = null) {
  const hasHiddenManifest = permissions && Object.prototype.hasOwnProperty.call(permissions, MANIFEST_KEY);
  const manifest = hasHiddenManifest ? permissions[MANIFEST_KEY] : permissions;
  const appKey = appKeyOverride
    || (permissions && typeof permissions[APP_KEY_KEY] === "string" && permissions[APP_KEY_KEY])
    || normalizePermission(mbkautheVar.APP_NAME || "");
  const source = manifest && typeof manifest === "object" && !Array.isArray(manifest) ? manifest : {};
  const collected = [];
  for (const [service, actions] of Object.entries(source)) {
    if (!actions || typeof actions !== "object") continue;
    for (const [action, label] of Object.entries(actions)) {
      if (typeof action !== "string" || !action.trim()) continue;
      const serviceKey = service.toLowerCase().trim();
      const actionKey = action.toLowerCase().trim();
      if (!serviceKey || !actionKey) continue;
      collected.push({
        appKey,
        serviceKey,
        actionKey,
        label: typeof label === "string" ? label : "",
        permission: `${appKey}:${serviceKey}:${actionKey}`,
      });
    }
  }
  return collected;
}

/**
 * Pure effective-permission builder.
 *
 * Rule set:
 *   template permissions (union across every assigned template)
 *     -> user allow overrides may grant otherwise-uninherited permissions
 *     -> user deny overrides always win
 *
 * @param {object} input
 * @param {Array<string|string[]>} [input.templates] - per-template permission lists
 * @param {string[]} [input.allows] - user allow overrides (concrete permissions)
 * @param {string[]} [input.denies] - user deny overrides (concrete permissions)
 * @returns {{ allows: string[], denies: string[] }}
 */
export function buildEffectivePermissions({ templates = [], allows = [], denies = [] } = {}) {
  const normalizedAllows = allows.map(normalizePermission).filter(Boolean);
  const normalizedDenies = denies.map(normalizePermission).filter(Boolean);

  // 1. Union all template permission bundles.
  const base = new Set();
  for (const bundle of templates) {
    const list = Array.isArray(bundle) ? bundle : [bundle];
    for (const permission of list) {
      const normalized = normalizePermission(permission);
      if (normalized) base.add(normalized);
    }
  }

  // 2. Deny always wins: a deny override removes a permission even when the
  //    user was granted it via a template or an allow override.
  for (const deny of normalizedDenies) {
    for (const permission of [...base]) {
      if (permissionMatches(deny, permission)) base.delete(permission);
    }
  }

  // 3. Allow overrides grant otherwise-uninherited permissions.
  for (const allow of normalizedAllows) {
    const denied = normalizedDenies.some((deny) => permissionMatches(deny, allow));
    if (!denied) base.add(allow);
  }

  return {
    allows: [...base].sort(),
    denies: [...new Set(normalizedDenies)].sort(),
  };
}

/**
 * Restrict a requested permission set to the permissions actually held by the
 * owner (cap semantics).
 *
 * Used to scope API tokens: a token may only carry a subset of the owner's
 * effective permissions and can never escalate beyond them. Wildcards are
 * honoured on both sides (`portal:*:*` held grants any portal permission) and
 * an explicit owner deny always removes the permission.
 *
 * SuperAdmin handling is the caller's responsibility (a superadmin holds every
 * permission conceptually but has no stored allow list).
 *
 * @param {*} held - the owner's `user.permissions` (allows/denies or string[])
 * @param {Array<string>|string} requested - the token's requested permissions
 * @returns {{ allows: string[], denies: string[] }}
 */
export function intersectPermissions(held, requested) {
  const { allows: heldAllows, denies: heldDenies } = normalizePermissions(held);

  const list = Array.isArray(requested)
    ? requested
    : typeof requested === "string"
      ? requested.split(",")
      : normalizePermissions(requested).allows;

  const allows = [];
  for (const entry of list) {
    const permission = normalizePermission(entry);
    if (!permission) continue;
    if (heldDenies.some((deny) => permissionMatches(deny, permission))) continue;
    if (heldAllows.some((allow) => permissionMatches(allow, permission))) {
      allows.push(permission);
    }
  }

  return { allows: [...new Set(allows)].sort(), denies: [] };
}

/**
 * In-memory authorization decision.
 *
 * ```text
 * SuperAdmin        -> allow
 * Explicit deny     -> deny
 * Matching allow    -> allow
 * Otherwise         -> deny
 * ```
 *
 * `user.permissions` is expected to be the session-cached value computed at
 * login/session refresh. This function performs NO database or network access.
 *
 * @param {{ role?: string, permissions?: any }|null|undefined} user
 * @param {string} required - permission string (may contain `*` segments)
 * @returns {boolean}
 */
export function hasPermission(user, required) {
  if (!user) return false;

  // SuperAdmin is a system-level bypass and never needs stored permissions.
  if (typeof user.role === "string" && user.role.toLowerCase() === SUPERADMIN_ROLE) {
    return true;
  }

  const resolvedRequired = resolvePermission(required);
  if (!resolvedRequired) return false;

  const perms = user.permissions;
  if (perms == null) return false;

  const { allows, denies } = normalizePermissions(perms);

  // Deny always wins.
  if (denies.length > 0 && denies.some((deny) => permissionMatches(deny, resolvedRequired))) {
    return false;
  }

  if (allows.length > 0 && allows.some((allow) => permissionMatches(allow, resolvedRequired))) {
    return true;
  }

  return false;
}

export { SUPERADMIN_ROLE };
