/**
 * MBKAuthe — Automatic permission catalog and unified role synchronization.
 *
 * Host applications call `syncAppPermissions(Permissions)` once at startup
 * (where `Permissions` is the result of `definePermissions()`). It:
 *   1. Extracts every declared permission from the manifest.
 *   2. Upserts them into `mbkcore_permission_catalog` (is_active = true).
 *   3. Marks previously registered permissions of the same app that are no
 *      longer declared as is_active = false (never hard-deletes).
 *   4. Contributes application-declared default role permissions into unified
 *      roles in `mbkcore_roles` & `mbkcore_role_permissions`.
 *   5. Hydrates the in-memory RoleRegistry.
 *   6. Is idempotent and safe to run repeatedly.
 *
 * This is an administrative/startup operation — NEVER a request-path
 * authorization operation.
 *
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { permissionRepository } from "./repositories/PermissionRepository.js";
import { collectPermissions, collectRoles, defaultRoleRegistry, GLOBAL_APP_KEY, resolveAppKey } from "./permissions.js";

/**
 * Synchronize an application's permission & role manifest into the database
 * and hydrate the in-memory RoleRegistry.
 */
export async function syncAppPermissions(Permissions, options = {}) {
  const repo = options?.repository || permissionRepository;
  const appKey = resolveAppKey(options?.appKey || null, options?.fallbackAppKey || null);
  if (appKey === GLOBAL_APP_KEY) {
    throw new Error("[mbkauthe] Global permissions are built into the catalog and cannot be synchronized by an app.");
  }

  // Ensure built-in global permission exists in catalog
  if (typeof repo.ensureGlobalPermission === "function") {
    try {
      await repo.ensureGlobalPermission();
    } catch (err) {
      console.warn("[mbkauthe] Failed to ensure global permission:", err?.message || err);
    }
  }

  // 1. Sync catalog permissions
  const declaredMap = new Map(collectPermissions(Permissions, appKey).map((p) => [`${p.serviceKey}:${p.actionKey}`, p]));
  await repo.syncCatalogForApp(appKey, [...declaredMap.values()].map(({ serviceKey, actionKey, label }) => ({ serviceKey, actionKey, label })));

  // 2. Sync declared application roles
  const declaredRoles = collectRoles(Permissions);
  for (const { name, permissions, label, description } of declaredRoles) {
    await repo.contributeRolePermissions(name, permissions, { label, description, is_system: false });
  }

  // 3. Hydrate in-memory RoleRegistry
  await repo.loadAllRolesIntoRegistry(defaultRoleRegistry);

  // Count inactive catalog items for reporting
  const appCatalog = await repo.listCatalogByApp(appKey);
  const deactivated = appCatalog.filter((row) => !row.is_active).length;

  return {
    appKey,
    synced: declaredMap.size,
    deactivated,
    rolesSynced: declaredRoles.length,
  };
}

export default syncAppPermissions;

