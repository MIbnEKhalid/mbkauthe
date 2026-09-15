/**
 * MBKAuthe — Permission catalog and role database synchronization service.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { permissionRepository, PermissionRepository } from "../db/repositories/PermissionRepository.js";
import { defaultRoleRegistry, GLOBAL_APP_KEY } from "../core/permissions/roleRegistry.js";
import { collectPermissions, collectRoles, resolveAppKey } from "../core/permissions/manifest.js";
import type { PermissionManifest } from "../core/types/permission.types.js";

export interface SyncAppPermissionsOptions {
  repository?: PermissionRepository;
  appKey?: string | null;
  fallbackAppKey?: string | null;
}

export interface SyncResult {
  appKey: string;
  synced: number;
  deactivated: number;
  rolesSynced: number;
}

/**
 * Synchronize an application's permission & role manifest into the database
 * and hydrate the in-memory RoleRegistry.
 */
export async function syncAppPermissions(
  Permissions: PermissionManifest,
  options: SyncAppPermissionsOptions = {}
): Promise<SyncResult> {
  const repo = options?.repository || permissionRepository;
  const appKey = resolveAppKey(options?.appKey || null, options?.fallbackAppKey || null);
  if (appKey === GLOBAL_APP_KEY) {
    throw new Error("[mbkauthe] Global permissions are built into the catalog and cannot be synchronized by an app.");
  }

  // Ensure built-in global permission exists in catalog
  if (typeof repo.ensureGlobalPermission === "function") {
    try {
      await repo.ensureGlobalPermission();
    } catch (err: any) {
      console.warn("[mbkauthe] Failed to ensure global permission:", err?.message || err);
    }
  }

  // 1. Sync catalog permissions
  const declaredMap = new Map(
    collectPermissions(Permissions, appKey).map((p) => [`${p.serviceKey}:${p.actionKey}`, p])
  );
  await repo.syncCatalogForApp(
    appKey,
    [...declaredMap.values()].map(({ serviceKey, actionKey, label }) => ({ serviceKey, actionKey, label }))
  );

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
