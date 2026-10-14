/**
 * MBKAuthe — Role & Permission Sync Service (Bitmask Engine)
 * Synchronizes declared application resource masks and roles into mbkcore_roles.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { permissionRepository, PermissionRepository } from "../db/repositories/PermissionRepository.js";

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
 * Synchronizes an application's resource and role declarations into mbkcore_roles.
 */
export async function syncAppPermissions(
  Permissions: any,
  options: SyncAppPermissionsOptions = {}
): Promise<SyncResult> {
  const repo = options?.repository || permissionRepository;
  const appKey = options?.appKey || options?.fallbackAppKey || "app";

  const declaredRoles = Permissions?.__roles || {};
  let rolesSynced = 0;

  for (const [name, roleDef] of Object.entries(declaredRoles as Record<string, any>)) {
    try {
      const existing = await repo.getRoleByName(name);
      if (!existing) {
        await repo.createRole(name, {
          label: roleDef.label || name,
          description: roleDef.description || "",
          permissions: roleDef.permissions || {},
          is_system: false,
        });
        rolesSynced++;
      } else {
        const merged = { ...(existing.permissions || {}), ...(roleDef.permissions || {}) };
        await repo.setRolePermissions(name, merged);
        rolesSynced++;
      }
    } catch (err: any) {
      console.warn(`[mbkauthe] Failed to sync role "${name}":`, err?.message || err);
    }
  }

  let catalogSynced = 0;
  if (typeof (repo as any).syncCatalogPermissions === "function") {
    try {
      catalogSynced = await (repo as any).syncCatalogPermissions(Permissions?.__definitions || {}, appKey);
    } catch (err: any) {
      console.warn(`[mbkauthe] Failed to sync permission catalog:`, err?.message || err);
    }
  }

  const resourceCount = Object.keys(Permissions?.__definitions || {}).length;

  return {
    appKey,
    synced: catalogSynced || resourceCount,
    deactivated: 0,
    rolesSynced,
  };
}

export default syncAppPermissions;
