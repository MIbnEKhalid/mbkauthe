/**
 * MBKAuthe — Automatic permission catalog synchronization.
 *
 * Host applications call `syncAppPermissions(Permissions)` once at startup
 * (where `Permissions` is the result of `definePermissions()`). It:
 *   1. Extracts every declared permission from the manifest.
 *   2. Upserts them into `mbkcore_permission_catalog` (is_active = true).
 *   3. Marks previously registered permissions of the same app that are no
 *      longer declared as is_active = false (never hard-deletes).
 *   4. Is idempotent and safe to run repeatedly.
 *
 * This is an administrative/startup operation — NEVER a request-path
 * authorization operation.
 *
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { permissionRepository } from "./db/PermissionRepository.js";
import { collectPermissions, GLOBAL_APP_KEY, resolveAppKey } from "./permissions.js";

/**
 * Synchronize an application's permission manifest into the catalog.
 *
 * The app key resolution matches `definePermissions` (explicit `appKey` >
 * configured `APP_NAME` > `fallbackAppKey`), so a manifest and its sync call
 * stay consistent even when the environment does not set APP_NAME.
 *
 * @param {object} Permissions - result of `definePermissions()` (or a raw
 *   `service -> action -> label` manifest).
 * @param {{ appKey?: string, fallbackAppKey?: string, repository?: object }} [options]
 * @returns {Promise<{ appKey: string, synced: number, deactivated: number }>}
 */
export async function syncAppPermissions(Permissions, options = {}) {
  const repo = options?.repository || permissionRepository;
  const appKey = resolveAppKey(options?.appKey || null, options?.fallbackAppKey || null);
  if (appKey === GLOBAL_APP_KEY) {
    throw new Error("[mbkauthe] Global permissions are built into the catalog and cannot be synchronized by an app.");
  }
  const declared = collectPermissions(Permissions, appKey);

  const declaredMap = new Map();
  for (const perm of declared) {
    declaredMap.set(`${perm.serviceKey}:${perm.actionKey}`, perm);
  }

  await repo.syncCatalogForApp(
    appKey,
    [...declaredMap.values()].map((perm) => ({
      serviceKey: perm.serviceKey,
      actionKey: perm.actionKey,
      label: perm.label,
    }))
  );

  // For reporting: count how many app catalog rows ended up inactive.
  const appCatalog = await repo.listCatalogByApp(appKey);
  const deactivated = appCatalog.filter((row) => !row.is_active).length;

  return { appKey, synced: declaredMap.size, deactivated };
}

export default syncAppPermissions;
