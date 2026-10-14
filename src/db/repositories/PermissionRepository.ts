/**
 * MBKAuthe — Pure Bitmask Permission Repository
 * High-performance persistence for roles and user authorization snapshots.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { dblogin, dialect } from "../pool.js";
import { BaseRepository, BaseRepositoryOptions } from "./BaseRepository.js";
import { combineResourceMasks, applyOverrides } from "../../core/permissions/bitmask.js";
import type { ResourceMasks, RoleDefinition, UserPermissionOverrides, UserAuthorizationSnapshot } from "../../core/types/permission.types.js";

const toBool = (val: unknown): boolean => Boolean(val === 1 || val === true || val === "1" || val === "true");

export class PermissionRepository extends BaseRepository {
  private effectiveCache = new Map<string, { snapshot: UserAuthorizationSnapshot; expiresAt: number }>();
  private effectiveCacheTtlMs = 60 * 1000;
  private schemaEnsured = false;

  constructor(options: BaseRepositoryOptions = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
  }

  get dialectName(): string {
    return this.dialect?.name || "postgres";
  }

  invalidateEffectiveCache(username?: string): void {
    if (username) {
      this.effectiveCache.delete(username.toLowerCase());
    } else {
      this.effectiveCache.clear();
    }
  }

  /**
   * Ensures permissions column exists on mbkcore_roles and mbkcore_users
   */
  async ensureSchema(): Promise<void> {
    if (this.schemaEnsured) return;
    try {
      const isSqlite = this.dialectName === "sqlite";
      if (!isSqlite) {
        await this.executeRaw({
          name: "perm-ensure-roles-col",
          text: `ALTER TABLE mbkcore_roles ADD COLUMN IF NOT EXISTS permissions jsonb DEFAULT '{}'::jsonb`,
          values: [],
        }).catch(() => {});
        await this.executeRaw({
          name: "perm-ensure-users-col",
          text: `ALTER TABLE mbkcore_users ADD COLUMN IF NOT EXISTS perm_overrides jsonb DEFAULT '{}'::jsonb,
                                              ADD COLUMN IF NOT EXISTS extra_roles jsonb DEFAULT '[]'::jsonb`,
          values: [],
        }).catch(() => {});
      }
      this.schemaEnsured = true;
    } catch {
      this.schemaEnsured = true;
    }
  }

  // ---------------------------------------------------------------- Roles

  async listRoles(): Promise<RoleDefinition[]> {
    await this.ensureSchema();
    const result = await this.executeRaw({
      name: "permission-list-roles",
      text: "SELECT id, name, label, description, is_system, permissions, created_at, updated_at FROM mbkcore_roles ORDER BY name",
      values: [],
    });

    return (result.rows || []).map((r: any) => {
      let perms: ResourceMasks = {};
      if (typeof r.permissions === "string") {
        try { perms = JSON.parse(r.permissions); } catch { perms = {}; }
      } else if (r.permissions && typeof r.permissions === "object") {
        perms = r.permissions;
      }

      return {
        id: r.id,
        name: String(r.name).toLowerCase(),
        label: r.label || r.name,
        description: r.description || "",
        is_system: toBool(r.is_system),
        permissions: perms,
        created_at: r.created_at,
        updated_at: r.updated_at,
      };
    });
  }

  async getRoleByName(name: string): Promise<RoleDefinition | null> {
    await this.ensureSchema();
    const cleanName = String(name || "").trim().toLowerCase();
    const result = await this.executeRaw({
      name: "permission-get-role",
      text: "SELECT id, name, label, description, is_system, permissions, created_at, updated_at FROM mbkcore_roles WHERE LOWER(name) = $1 LIMIT 1",
      values: [cleanName],
    });

    const row = result.rows?.[0];
    if (!row) return null;

    let perms: ResourceMasks = {};
    if (typeof row.permissions === "string") {
      try { perms = JSON.parse(row.permissions); } catch { perms = {}; }
    } else if (row.permissions && typeof row.permissions === "object") {
      perms = row.permissions;
    }

    return {
      id: row.id,
      name: String(row.name).toLowerCase(),
      label: row.label || row.name,
      description: row.description || "",
      is_system: toBool(row.is_system),
      permissions: perms,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  async setRolePermissions(roleName: string, permissions: ResourceMasks): Promise<void> {
    await this.ensureSchema();
    this.invalidateEffectiveCache();
    const cleanName = String(roleName || "").trim().toLowerCase();
    const isSqlite = this.dialectName === "sqlite";
    const permVal = isSqlite ? JSON.stringify(permissions) : JSON.stringify(permissions);

    await this.executeRaw({
      name: "permission-set-role-permissions",
      text: `UPDATE mbkcore_roles
             SET permissions = $1,
                 updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"}
             WHERE LOWER(name) = $2`,
      values: [permVal, cleanName],
    });
  }

  async createRole(name: string, options: { label?: string; description?: string; permissions?: ResourceMasks; is_system?: boolean } = {}): Promise<RoleDefinition> {
    await this.ensureSchema();
    const cleanName = String(name || "").trim().toLowerCase();
    const isSqlite = this.dialectName === "sqlite";
    const permVal = JSON.stringify(options.permissions || {});

    const text = isSqlite
      ? `INSERT INTO mbkcore_roles (name, label, description, is_system, permissions)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, label, description, is_system, permissions, created_at, updated_at`
      : `INSERT INTO mbkcore_roles (name, label, description, is_system, permissions)
         VALUES ($1, $2, $3, $4, $5::jsonb)
         RETURNING id, name, label, description, is_system, permissions, created_at, updated_at`;

    const result = await this.executeRaw({
      name: "permission-create-role",
      text,
      values: [cleanName, options.label || cleanName, options.description || "", options.is_system ? 1 : 0, permVal],
    });

    const r = result.rows?.[0];
    return {
      id: r?.id,
      name: cleanName,
      label: r?.label || cleanName,
      description: r?.description || "",
      is_system: toBool(r?.is_system),
      permissions: options.permissions || {},
      created_at: r?.created_at,
      updated_at: r?.updated_at,
    };
  }

  async deleteRole(name: string): Promise<void> {
    await this.ensureSchema();
    this.invalidateEffectiveCache();
    const cleanName = String(name || "").trim().toLowerCase();
    await this.executeRaw({
      name: "permission-delete-role",
      text: "DELETE FROM mbkcore_roles WHERE LOWER(name) = $1 AND is_system = false",
      values: [cleanName],
    });
  }

  // ---------------------------------------------------- User Role & Overrides

  async getUserRole(username: string): Promise<{ role: string; roles: string[]; perm_version: number; overrides?: UserPermissionOverrides }> {
    await this.ensureSchema();
    const cleanUser = String(username || "").trim().toLowerCase();
    const result = await this.executeRaw({
      name: "permission-get-user-role",
      text: "SELECT role, extra_roles, perm_version, perm_overrides FROM mbkcore_users WHERE LOWER(username) = $1 LIMIT 1",
      values: [cleanUser],
    });

    const row = result.rows?.[0];
    const role = (row?.role || "normaluser").toLowerCase();
    const perm_version = Number(row?.perm_version || 1);

    let roles = [role];
    if (row?.extra_roles) {
      try {
        const extra = typeof row.extra_roles === "string" ? JSON.parse(row.extra_roles) : row.extra_roles;
        if (Array.isArray(extra)) {
          roles = Array.from(new Set([role, ...extra.map((r: any) => String(r).toLowerCase())]));
        }
      } catch {
        /* ignore */
      }
    }

    let overrides: UserPermissionOverrides | undefined;
    if (row?.perm_overrides) {
      try {
        overrides = typeof row.perm_overrides === "string" ? JSON.parse(row.perm_overrides) : row.perm_overrides;
      } catch {
        /* ignore */
      }
    }

    return { role, roles, perm_version, overrides };
  }

  async setUserRole(username: string, role: string, extraRoles: string[] = []): Promise<void> {
    await this.ensureSchema();
    const cleanUser = String(username || "").trim().toLowerCase();
    const cleanRole = String(role || "normaluser").trim().toLowerCase();
    this.invalidateEffectiveCache(cleanUser);

    const isSqlite = this.dialectName === "sqlite";
    const extraVal = JSON.stringify(extraRoles.map((r) => r.toLowerCase()));

    await this.executeRaw({
      name: "permission-set-user-role",
      text: `UPDATE mbkcore_users
             SET role = $1,
                 extra_roles = $2,
                 perm_version = (COALESCE(perm_version, 1) + 1),
                 updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"}
             WHERE LOWER(username) = $3`,
      values: [cleanRole, extraVal, cleanUser],
    });
  }

  async setUserOverrides(username: string, overrides: UserPermissionOverrides): Promise<void> {
    await this.ensureSchema();
    const cleanUser = String(username || "").trim().toLowerCase();
    this.invalidateEffectiveCache(cleanUser);

    const isSqlite = this.dialectName === "sqlite";
    const overVal = JSON.stringify(overrides);

    await this.executeRaw({
      name: "permission-set-user-overrides",
      text: `UPDATE mbkcore_users
             SET perm_overrides = $1,
                 perm_version = (COALESCE(perm_version, 1) + 1),
                 updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"}
             WHERE LOWER(username) = $2`,
      values: [overVal, cleanUser],
    });
  }

  async bumpPermissionVersion(username: string): Promise<void> {
    const cleanUser = String(username || "").trim().toLowerCase();
    this.invalidateEffectiveCache(cleanUser);
    const isSqlite = this.dialectName === "sqlite";
    await this.executeRaw({
      name: "permission-bump-version",
      text: `UPDATE mbkcore_users SET perm_version = (COALESCE(perm_version, 1) + 1),
             updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"} WHERE LOWER(username) = $1`,
      values: [cleanUser],
    });
  }

  // ------------------------------------------------ Effective Permission Computation

  async computeEffectiveForUser(username: string, knownRole?: string | null): Promise<UserAuthorizationSnapshot> {
    const cleanUser = String(username || "").trim().toLowerCase();
    const cleanKnownRole = String(knownRole || "").trim().toLowerCase();

    // Fast path: superadmin
    if (cleanKnownRole === "superadmin") {
      return {
        role: "superadmin",
        roles: ["superadmin"],
        masks: {},
        isSuperadmin: true,
        perm_version: 1,
      };
    }

    // Check memory cache
    if (cleanUser) {
      const cached = this.effectiveCache.get(cleanUser);
      if (cached && Date.now() < cached.expiresAt) {
        return cached.snapshot;
      }
    }

    const { role, roles, perm_version, overrides } = await this.getUserRole(cleanUser);

    if (role === "superadmin" || roles.includes("superadmin")) {
      const superSnap: UserAuthorizationSnapshot = {
        role: "superadmin",
        roles,
        masks: {},
        isSuperadmin: true,
        perm_version,
      };
      if (cleanUser) this.effectiveCache.set(cleanUser, { snapshot: superSnap, expiresAt: Date.now() + this.effectiveCacheTtlMs });
      return superSnap;
    }

    // Fetch all roles assigned to user
    const roleMasks: ResourceMasks[] = [];
    for (const r of roles) {
      const roleDef = await this.getRoleByName(r);
      if (roleDef && roleDef.permissions) {
        roleMasks.push(roleDef.permissions);
      }
    }

    // Combine role masks and apply overrides
    const baseMasks = combineResourceMasks(...roleMasks);
    const finalMasks = applyOverrides(baseMasks, overrides);

    const snapshot: UserAuthorizationSnapshot = {
      role,
      roles,
      masks: finalMasks,
      overrides,
      isSuperadmin: false,
      perm_version,
    };

    if (cleanUser) {
      this.effectiveCache.set(cleanUser, { snapshot, expiresAt: Date.now() + this.effectiveCacheTtlMs });
    }

    return snapshot;
  }

  // ------------------------------------------------ Permission Catalog (Management Only)

  async syncCatalogPermissions(definitions: Record<string, any>, fallbackApp: string = "app"): Promise<number> {
    const isSqlite = this.dialectName === "sqlite";
    const items: Array<{ appKey: string; resKey: string; actKey: string; label: string; permKey: string; mask: number }> = [];

    for (const [resKey, def] of Object.entries(definitions || {})) {
      const appKey = (def as any)?.app || fallbackApp;
      for (const [actKey, desc] of Object.entries((def as any)?.actions || {})) {
        if (actKey === "*" || actKey === "all") continue;
        const actionDesc = desc as any;
        const permKey = actionDesc.key || `${appKey}:${resKey}:${actKey}`;
        const label = actionDesc.label || `${resKey} ${actKey}`;
        const mask = Number(actionDesc.mask) || 1;
        items.push({ appKey, resKey, actKey, label, permKey, mask });
      }
    }

    if (!items.length) return 0;
    const chunkSize = 50;
    let synced = 0;

    for (let i = 0; i < items.length; i += chunkSize) {
      const chunk = items.slice(i, i + chunkSize);
      const values: any[] = [];
      const placeholders = chunk.map((item, idx) => {
        const offset = idx * 6;
        values.push(item.appKey, item.resKey, item.actKey, item.label, item.permKey, item.mask);
        return `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, $${offset + 6}, ${isSqlite ? "1" : "true"})`;
      }).join(", ");

      const text = isSqlite
        ? `INSERT INTO mbkcore_permission_catalog (app_key, service_key, action_key, label, permission, mask, is_active)
           VALUES ${placeholders}
           ON CONFLICT (permission) DO UPDATE SET
             label = excluded.label,
             mask = excluded.mask,
             app_key = excluded.app_key,
             service_key = excluded.service_key,
             action_key = excluded.action_key,
             is_active = 1,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`
        : `INSERT INTO mbkcore_permission_catalog (app_key, service_key, action_key, label, permission, mask, is_active)
           VALUES ${placeholders}
           ON CONFLICT (permission) DO UPDATE SET
             label = EXCLUDED.label,
             mask = EXCLUDED.mask,
             app_key = EXCLUDED.app_key,
             service_key = EXCLUDED.service_key,
             action_key = EXCLUDED.action_key,
             is_active = true,
             updated_at = now()`;

      try {
        await this.executeRaw({
          name: `perm-sync-catalog-chunk-${i}`,
          text,
          values,
        });
        synced += chunk.length;
      } catch {
        // Gracefully continue if catalog table not migrated in isolated unit tests
      }
    }
    return synced;
  }
}

export const permissionRepository = new PermissionRepository();
export default permissionRepository;
