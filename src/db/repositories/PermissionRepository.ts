/**
 * MBKAuthe — Numeric ID Permission Repository
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { dblogin, dialect } from "../pool.js";
import { BaseRepository, BaseRepositoryOptions } from "./BaseRepository.js";
import { normalizePermission, resolvePermissionId } from "../../core/permissions/matcher.js";
import { buildEffectivePermissions, GLOBAL_APP_KEY, defaultRoleRegistry, RoleRegistry } from "../../core/permissions/roleRegistry.js";
import type { CatalogPermission, RoleDefinition, UserPermissionOverride, UserRoleAssignment, EffectivePermissionsResult, DeclaredPermission, PermissionTarget } from "../../core/types/permission.types.js";

const GLOBAL_PERMISSION: DeclaredPermission & { appKey: string; id: number } = {
  id: 1,
  appKey: GLOBAL_APP_KEY,
  serviceKey: "basic",
  actionKey: "access",
  label: "Basic global access",
};

const toBool = (val: unknown): boolean => Boolean(val === 1 || val === true || val === "1" || val === "true");

export interface UpsertCatalogOptions {
  id?: number;
  appKey: string;
  serviceKey: string;
  actionKey: string;
  label?: string | null;
}

export interface RoleCreateOptions {
  label?: string;
  description?: string;
  is_system?: boolean;
}

export class PermissionRepository extends BaseRepository {
  private effectiveCache = new Map<string, { snapshot: EffectivePermissionsResult; expiresAt: number }>();
  private effectiveCacheTtlMs = 60 * 1000;

  constructor(options: BaseRepositoryOptions = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
  }

  invalidateEffectiveCache(username?: string): void {
    if (username) {
      this.effectiveCache.delete(username.toLowerCase());
    } else {
      this.effectiveCache.clear();
    }
  }

  get dialectName(): string {
    return this.dialect?.name || "postgres";
  }

  async ensureGlobalPermission(): Promise<void> {
    await this.upsertCatalogPermission(GLOBAL_PERMISSION);
  }

  // ---------------------------------------------------------------- Catalog

  async upsertCatalogPermission({ id, appKey, serviceKey, actionKey, label = null }: UpsertCatalogOptions): Promise<CatalogPermission> {
    const isSqlite = this.dialectName === "sqlite";
    const cleanApp = normalizePermission(appKey);
    const cleanService = normalizePermission(serviceKey);
    const cleanAction = normalizePermission(actionKey);

    let result: any;
    if (typeof id === "number" && id > 0) {
      const text = isSqlite
        ? `INSERT INTO mbkcore_permission_catalog (id, app_key, service_key, action_key, label, is_active)
           VALUES ($1, $2, $3, $4, $5, 1)
           ON CONFLICT(app_key, service_key, action_key)
           DO UPDATE SET label = excluded.label, is_active = 1, updated_at = CURRENT_TIMESTAMP
           RETURNING id, app_key, service_key, action_key, label, is_active`
        : `INSERT INTO mbkcore_permission_catalog (id, app_key, service_key, action_key, label, is_active)
           VALUES ($1, $2, $3, $4, $5, true)
           ON CONFLICT (app_key, service_key, action_key)
           DO UPDATE SET label = EXCLUDED.label, is_active = true, updated_at = now()
           RETURNING id, app_key, service_key, action_key, label, is_active`;
      result = await this.executeRaw({ name: "permission-upsert-catalog-id", text, values: [id, cleanApp, cleanService, cleanAction, label] });
    } else {
      const text = isSqlite
        ? `INSERT INTO mbkcore_permission_catalog (app_key, service_key, action_key, label, is_active)
           VALUES ($1, $2, $3, $4, 1)
           ON CONFLICT(app_key, service_key, action_key)
           DO UPDATE SET label = excluded.label, is_active = 1, updated_at = CURRENT_TIMESTAMP
           RETURNING id, app_key, service_key, action_key, label, is_active`
        : `INSERT INTO mbkcore_permission_catalog (app_key, service_key, action_key, label, is_active)
           VALUES ($1, $2, $3, $4, true)
           ON CONFLICT (app_key, service_key, action_key)
           DO UPDATE SET label = EXCLUDED.label, is_active = true, updated_at = now()
           RETURNING id, app_key, service_key, action_key, label, is_active`;
      result = await this.executeRaw({ name: "permission-upsert-catalog", text, values: [cleanApp, cleanService, cleanAction, label] });
    }

    const row = result.rows?.[0];
    const permId = Number(row?.id || id || 0);
    defaultRoleRegistry.registerCatalogItem(permId, cleanApp, cleanService, cleanAction, label || undefined);

    return {
      id: permId,
      app_key: cleanApp,
      service_key: cleanService,
      action_key: cleanAction,
      label: row?.label || label,
      is_active: true,
      permission: `${cleanApp}:${cleanService}:${cleanAction}`,
    };
  }

  async deactivateAllCatalogPermissionsForApp(appKey: string): Promise<{ rowCount: number }> {
    if (String(appKey).trim().toLowerCase() === GLOBAL_APP_KEY) return { rowCount: 0 };
    const isSqlite = this.dialectName === "sqlite";
    const result = await this.executeRaw({
      name: "permission-deactivate-app",
      text: `UPDATE mbkcore_permission_catalog SET is_active = ${isSqlite ? "0" : "false"}, updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"} WHERE app_key = $1`,
      values: [appKey],
    });
    return { rowCount: result.rowCount || 0 };
  }

  async syncCatalogForApp(appKey: string, declared: Array<DeclaredPermission & { node?: any }> = []): Promise<Map<string, number>> {
    const idMap = new Map<string, number>();

    await this.withTransaction(async (txRepo) => {
      const pRepo = txRepo as unknown as PermissionRepository;
      await pRepo.deactivateAllCatalogPermissionsForApp(appKey);
      for (const perm of declared) {
        const saved = await pRepo.upsertCatalogPermission({
          id: perm.id,
          appKey,
          serviceKey: perm.serviceKey,
          actionKey: perm.actionKey,
          label: perm.label,
        });
        idMap.set(`${perm.serviceKey}:${perm.actionKey}`, saved.id);
        idMap.set(`${appKey}:${perm.serviceKey}:${perm.actionKey}`, saved.id);
        if (perm.node) {
          perm.node.id = saved.id;
        }
      }
    });

    return idMap;
  }

  async listCatalog(): Promise<CatalogPermission[]> {
    const result = await this.executeRaw({
      name: "permission-list-catalog",
      text: `SELECT id, app_key, service_key, action_key, label, is_active, updated_at
             FROM mbkcore_permission_catalog
             ORDER BY id, app_key, service_key, action_key`,
      values: [],
    });
    return (result.rows || []).map((row: any) => ({
      id: Number(row.id),
      app_key: row.app_key,
      service_key: row.service_key,
      action_key: row.action_key,
      label: row.label,
      is_active: toBool(row.is_active),
      updated_at: row.updated_at,
      permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
    }));
  }

  async listActiveCatalog(): Promise<CatalogPermission[]> {
    const catalog = await this.listCatalog();
    return catalog.filter((row) => row.is_active);
  }

  async listCatalogByApp(appKey: string): Promise<CatalogPermission[]> {
    const result = await this.executeRaw({
      name: "permission-list-catalog-app",
      text: `SELECT id, app_key, service_key, action_key, label, is_active, updated_at
             FROM mbkcore_permission_catalog
             WHERE app_key = $1
             ORDER BY id, service_key, action_key`,
      values: [appKey],
    });
    return (result.rows || []).map((row: any) => ({
      id: Number(row.id),
      app_key: row.app_key,
      service_key: row.service_key,
      action_key: row.action_key,
      label: row.label,
      is_active: toBool(row.is_active),
      permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
    }));
  }

  async lookupCatalogPermission(permission: string | number): Promise<CatalogPermission | null> {
    if (typeof permission === "number") {
      const result = await this.executeRaw({
        name: "permission-lookup-catalog-by-id",
        text: `SELECT id, app_key, service_key, action_key, label, is_active, updated_at
               FROM mbkcore_permission_catalog WHERE id = $1 LIMIT 1`,
        values: [permission],
      });
      const row = result.rows?.[0];
      return row ? {
        id: Number(row.id),
        app_key: row.app_key,
        service_key: row.service_key,
        action_key: row.action_key,
        label: row.label,
        is_active: toBool(row.is_active),
        updated_at: row.updated_at,
        permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
      } : null;
    }

    const segments = String(permission || "").split(":");
    if (segments.length !== 3) return null;
    const [appKey, serviceKey, actionKey] = segments.map((s) => String(s).trim().toLowerCase());
    if (!appKey || !serviceKey || !actionKey) return null;

    const result = await this.executeRaw({
      name: "permission-lookup-catalog-by-key",
      text: `SELECT id, app_key, service_key, action_key, label, is_active, updated_at
             FROM mbkcore_permission_catalog
             WHERE app_key = $1 AND service_key = $2 AND action_key = $3 LIMIT 1`,
      values: [appKey, serviceKey, actionKey],
    });
    const row = result.rows?.[0];
    return row ? {
      id: Number(row.id),
      app_key: row.app_key,
      service_key: row.service_key,
      action_key: row.action_key,
      label: row.label,
      is_active: toBool(row.is_active),
      updated_at: row.updated_at,
      permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
    } : null;
  }

  async isCatalogPermissionActive(permission: string | number): Promise<boolean> {
    const found = await this.lookupCatalogPermission(permission);
    return Boolean(found && found.is_active);
  }

  async ensureCatalogPermissionId(target: PermissionTarget | any): Promise<number> {
    let appKey = "";
    let serviceKey = "";
    let actionKey = "";
    let label = "";

    if (typeof target === "string" && target.includes(":")) {
      const parts = target.trim().toLowerCase().split(":");
      if (parts.length === 3) {
        [appKey, serviceKey, actionKey] = parts;
        label = `${serviceKey} ${actionKey}`;
      }
    } else if (target && typeof target === "object" && target.appKey && target.serviceKey && target.actionKey) {
      appKey = target.appKey;
      serviceKey = target.serviceKey;
      actionKey = target.actionKey;
      label = target.label || `${serviceKey} ${actionKey}`;
    }

    if (appKey && serviceKey && actionKey) {
      const existing = await this.lookupCatalogPermission(`${appKey}:${serviceKey}:${actionKey}`);
      if (existing) return existing.id;

      const saved = await this.upsertCatalogPermission({
        appKey,
        serviceKey,
        actionKey,
        label,
      });
      defaultRoleRegistry.registerCatalogItem(saved.id, appKey, serviceKey, actionKey, label);
      return saved.id;
    }

    const directId = resolvePermissionId(target, defaultRoleRegistry);
    if (directId > 0) {
      const existing = await this.lookupCatalogPermission(directId);
      if (existing) return existing.id;
    }

    return directId > 0 ? directId : 0;
  }

  // ---------------------------------------------------------------- Roles

  async listRoles(): Promise<RoleDefinition[]> {
    const rolesResult = await this.executeRaw({
      name: "permission-list-roles",
      text: "SELECT id, name, label, description, is_system, created_at, updated_at FROM mbkcore_roles ORDER BY name",
      values: [],
    });
    const roles = rolesResult.rows || [];
    if (roles.length === 0) return [];

    const permsResult = await this.executeRaw({
      name: "permission-list-role-perms",
      text: "SELECT role_name, permission_id FROM mbkcore_role_permissions ORDER BY role_name, permission_id",
      values: [],
    });

    const permsByRole = new Map<string, number[]>();
    for (const row of permsResult.rows || []) {
      const list = permsByRole.get(row.role_name) || [];
      list.push(Number(row.permission_id));
      permsByRole.set(row.role_name, list);
    }

    return roles.map((r: any) => ({
      id: r.id,
      name: r.name,
      label: r.label || r.name,
      description: r.description || "",
      is_system: toBool(r.is_system),
      permissions: permsByRole.get(r.name) || [],
      created_at: r.created_at,
      updated_at: r.updated_at,
    }));
  }

  async getRoleByName(name: string): Promise<RoleDefinition | null> {
    const cleanName = normalizePermission(name);
    const result = await this.executeRaw({
      name: "permission-get-role",
      text: "SELECT id, name, label, description, is_system, created_at, updated_at FROM mbkcore_roles WHERE name = $1 LIMIT 1",
      values: [cleanName],
    });
    const row = result.rows?.[0];
    if (!row) return null;

    const permsResult = await this.executeRaw({
      name: "permission-get-role-perms",
      text: "SELECT permission_id FROM mbkcore_role_permissions WHERE role_name = $1 ORDER BY permission_id",
      values: [cleanName],
    });

    return {
      id: row.id,
      name: row.name,
      label: row.label || row.name,
      description: row.description || "",
      is_system: toBool(row.is_system),
      permissions: (permsResult.rows || []).map((p: any) => Number(p.permission_id)),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  async createRole(name: string, permissions: (number | PermissionTarget)[] = [], options: RoleCreateOptions = {}): Promise<RoleDefinition | null> {
    const cleanName = normalizePermission(name);
    const label = options.label || cleanName;
    const description = options.description || "";
    const isSystem = options.is_system ? 1 : 0;
    const isSqlite = this.dialectName === "sqlite";

    const text = isSqlite
      ? `INSERT INTO mbkcore_roles (name, label, description, is_system)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT(name) DO UPDATE SET label = excluded.label, description = excluded.description`
      : `INSERT INTO mbkcore_roles (name, label, description, is_system)
         VALUES ($1, $2, $3, ${isSystem ? "true" : "false"})
         ON CONFLICT (name) DO UPDATE SET label = EXCLUDED.label, description = EXCLUDED.description, updated_at = now()`;

    await this.executeRaw({
      name: "permission-create-role",
      text,
      values: [cleanName, label, description, ...(isSqlite ? [isSystem] : [])],
    });

    if (permissions?.length) {
      await this.setRolePermissions(cleanName, permissions);
    }

    await this.loadAllRolesIntoRegistry();
    return this.getRoleByName(cleanName);
  }

  async setRolePermissions(roleName: string, permissions: (number | PermissionTarget)[] = []): Promise<void> {
    const cleanName = normalizePermission(roleName);
    const resolvedIds: number[] = [];
    for (const p of permissions) {
      const id = await this.ensureCatalogPermissionId(p);
      if (id > 0) resolvedIds.push(id);
    }
    const cleanPermIds = Array.from(new Set(resolvedIds));

    await this.withTransaction(async (txRepo) => {
      await txRepo.executeRaw({
        name: "permission-clear-role-perms",
        text: "DELETE FROM mbkcore_role_permissions WHERE role_name = $1",
        values: [cleanName],
      });

      for (const permId of cleanPermIds) {
        await txRepo.executeRaw({
          name: "permission-insert-role-perm",
          text: txRepo.dialect?.name === "sqlite"
            ? "INSERT INTO mbkcore_role_permissions (role_name, permission_id) VALUES ($1, $2) ON CONFLICT(role_name, permission_id) DO NOTHING"
            : "INSERT INTO mbkcore_role_permissions (role_name, permission_id) VALUES ($1, $2) ON CONFLICT (role_name, permission_id) DO NOTHING",
          values: [cleanName, permId],
        });
      }
    });

    defaultRoleRegistry.setRole(cleanName, cleanPermIds);
  }

  async contributeRolePermissions(roleName: string, permissions: (number | PermissionTarget)[] = [], options: RoleCreateOptions = {}): Promise<void> {
    const cleanName = normalizePermission(roleName);
    const resolvedIds: number[] = [];
    for (const p of permissions) {
      const id = await this.ensureCatalogPermissionId(p);
      if (id > 0) resolvedIds.push(id);
    }
    const cleanPermIds = Array.from(new Set(resolvedIds));

    await this.withTransaction(async (txRepo) => {
      const isSqlite = txRepo.dialect?.name === "sqlite";
      await txRepo.executeRaw({
        name: "permission-ensure-role",
        text: isSqlite
          ? `INSERT INTO mbkcore_roles (name, label, description, is_system)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(name) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`
          : `INSERT INTO mbkcore_roles (name, label, description, is_system)
             VALUES ($1, $2, $3, ${options.is_system ? "true" : "false"})
             ON CONFLICT (name) DO UPDATE SET updated_at = now()`,
        values: [cleanName, options.label || cleanName, options.description || "", ...(isSqlite ? [options.is_system ? 1 : 0] : [])],
      });

      for (const permId of cleanPermIds) {
        await txRepo.executeRaw({
          name: "permission-insert-role-perm-contrib",
          text: isSqlite
            ? "INSERT INTO mbkcore_role_permissions (role_name, permission_id) VALUES ($1, $2) ON CONFLICT(role_name, permission_id) DO NOTHING"
            : "INSERT INTO mbkcore_role_permissions (role_name, permission_id) VALUES ($1, $2) ON CONFLICT (role_name, permission_id) DO NOTHING",
          values: [cleanName, permId],
        });
      }
    });

    defaultRoleRegistry.addRolePermissions(cleanName, cleanPermIds);
  }

  async deleteRole(name: string): Promise<void> {
    const cleanName = normalizePermission(name);
    await this.executeRaw({ name: "permission-delete-role", text: "DELETE FROM mbkcore_roles WHERE name = $1", values: [cleanName] });
    defaultRoleRegistry.deleteRole(cleanName);
  }

  async loadAllRolesIntoRegistry(registry: RoleRegistry = defaultRoleRegistry): Promise<RoleRegistry> {
    try {
      const isSqlite = this.dialectName === "sqlite";
      // 1. Load catalog items into registry
      const catResult = await this.executeRaw({
        name: "permission-load-all-catalog",
        text: `SELECT id, app_key, service_key, action_key, label FROM mbkcore_permission_catalog WHERE is_active = ${isSqlite ? "1" : "true"}`,
        values: [],
      });
      for (const c of catResult.rows || []) {
        registry.registerCatalogItem(Number(c.id), c.app_key, c.service_key, c.action_key, c.label);
      }

      // 2. Load role permissions
      const permsResult = await this.executeRaw({
        name: "permission-load-all-role-perms",
        text: "SELECT role_name, permission_id FROM mbkcore_role_permissions",
        values: [],
      });

      const roleMap = new Map<string, number[]>();
      for (const row of permsResult.rows || []) {
        const list = roleMap.get(row.role_name) || [];
        list.push(Number(row.permission_id));
        roleMap.set(row.role_name, list);
      }

      for (const [role, perms] of roleMap.entries()) {
        registry.setRole(role, perms);
      }
      registry.isLoaded = true;
      return registry;
    } catch (err: any) {
      registry.isLoaded = true;
      const msg = err?.message || "";
      if (!/no such table|relation .* does not exist|does not exist/i.test(msg)) {
        console.error("[mbkauthe] Failed to hydrate RoleRegistry:", err);
      }
      return registry;
    }
  }

  async resolveCanonicalUserId(userIdOrUsername: string, txRepo?: PermissionRepository): Promise<string | null> {
    if (!userIdOrUsername) return null;
    const executor = txRepo || this;
    const res = await executor.executeRaw({
      name: "permission-resolve-canonical-user-id",
      text: "SELECT user_id FROM mbkcore_users WHERE user_id = $1 OR username = $1 LIMIT 1",
      values: [userIdOrUsername],
    });
    return res.rows?.[0]?.user_id || null;
  }

  // ----------------------------------------------------------- User Overrides

  async listOverridesForUser(userIdOrUsername: string): Promise<UserPermissionOverride[]> {
    const isSqlite = this.dialectName === "sqlite";
    const text = isSqlite
      ? `SELECT permission_id, effect, granted_by, created_at
         FROM mbkcore_user_permission_overrides
         WHERE username = $1
         ORDER BY effect ASC, permission_id ASC`
      : `SELECT o.permission_id, o.effect, o.granted_by_id AS granted_by, o.created_at
         FROM mbkcore_user_permission_overrides o
         JOIN mbkcore_users u ON u.user_id = o.user_id
         WHERE u.user_id = $1 OR u.username = $1
         ORDER BY o.effect ASC, o.permission_id ASC`;
    const result = await this.executeRaw({
      name: "permission-list-overrides",
      text,
      values: [userIdOrUsername],
    });
    return (result.rows || []).map((row: any) => ({
      permission_id: Number(row.permission_id),
      effect: row.effect,
      granted_by: row.granted_by || row.granted_by_id || null,
      created_at: row.created_at,
    }));
  }

  async setOverride(userIdOrUsername: string, permission: number | PermissionTarget, effect: "allow" | "deny", grantedByIdOrUsername: string | null = null): Promise<any> {
    this.invalidateEffectiveCache(userIdOrUsername);
    const permId = await this.ensureCatalogPermissionId(permission);
    if (permId <= 0) return null;

    const isSqlite = this.dialectName === "sqlite";
    if (isSqlite) {
      const text = `INSERT INTO mbkcore_user_permission_overrides (username, permission_id, effect, granted_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT(username, permission_id) DO UPDATE SET effect = excluded.effect, granted_by = excluded.granted_by`;
      return this.executeRaw({
        name: "permission-set-override",
        text,
        values: [userIdOrUsername, permId, effect, grantedByIdOrUsername],
      });
    }

    const canonicalUserId = (await this.resolveCanonicalUserId(userIdOrUsername)) || userIdOrUsername;
    const canonicalGrantedBy = grantedByIdOrUsername ? (await this.resolveCanonicalUserId(grantedByIdOrUsername)) : null;

    const text = `INSERT INTO mbkcore_user_permission_overrides (user_id, permission_id, effect, granted_by_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, permission_id) DO UPDATE SET effect = EXCLUDED.effect, granted_by_id = EXCLUDED.granted_by_id`;

    return this.executeRaw({
      name: "permission-set-override",
      text,
      values: [canonicalUserId, permId, effect, canonicalGrantedBy],
    });
  }

  async removeOverride(userIdOrUsername: string, permission: number | PermissionTarget): Promise<any> {
    this.invalidateEffectiveCache(userIdOrUsername);
    const permId = await this.ensureCatalogPermissionId(permission);
    if (permId <= 0) return null;

    const isSqlite = this.dialectName === "sqlite";
    if (isSqlite) {
      return this.executeRaw({
        name: "permission-remove-override",
        text: "DELETE FROM mbkcore_user_permission_overrides WHERE username = $1 AND permission_id = $2",
        values: [userIdOrUsername, permId],
      });
    }

    const canonicalUserId = (await this.resolveCanonicalUserId(userIdOrUsername)) || userIdOrUsername;
    return this.executeRaw({
      name: "permission-remove-override",
      text: "DELETE FROM mbkcore_user_permission_overrides WHERE user_id = $1 AND permission_id = $2",
      values: [canonicalUserId, permId],
    });
  }

  async clearOverridesForUser(userIdOrUsername: string): Promise<any> {
    this.invalidateEffectiveCache(userIdOrUsername);
    const isSqlite = this.dialectName === "sqlite";
    if (isSqlite) {
      return this.executeRaw({
        name: "permission-clear-overrides",
        text: "DELETE FROM mbkcore_user_permission_overrides WHERE username = $1",
        values: [userIdOrUsername],
      });
    }

    const canonicalUserId = (await this.resolveCanonicalUserId(userIdOrUsername)) || userIdOrUsername;
    return this.executeRaw({
      name: "permission-clear-overrides",
      text: "DELETE FROM mbkcore_user_permission_overrides WHERE user_id = $1",
      values: [canonicalUserId],
    });
  }

  async replaceOverridesForUser(userIdOrUsername: string, overrides: Array<{ permission_id: number; effect: string }> = [], grantedByIdOrUsername: string | null = null): Promise<void> {
    this.invalidateEffectiveCache(userIdOrUsername);
    const isSqlite = this.dialectName === "sqlite";
    const canonicalUserId = isSqlite ? userIdOrUsername : ((await this.resolveCanonicalUserId(userIdOrUsername)) || userIdOrUsername);
    const canonicalGrantedBy = isSqlite ? grantedByIdOrUsername : (grantedByIdOrUsername ? (await this.resolveCanonicalUserId(grantedByIdOrUsername)) : null);

    await this.withTransaction(async (txRepo) => {
      const pRepo = txRepo as unknown as PermissionRepository;
      await pRepo.clearOverridesForUser(userIdOrUsername);
      for (const item of overrides) {
        const permId = await pRepo.ensureCatalogPermissionId(item.permission_id);
        const effect = String(item.effect || "").toLowerCase();
        if (permId > 0 && ["allow", "deny"].includes(effect)) {
          await pRepo.setOverride(canonicalUserId, permId, effect as any, canonicalGrantedBy);
        }
      }
      await pRepo.bumpPermissionVersion(userIdOrUsername);
    });
  }

  // ---------------------------------------------------- User Role Assignment

  async getUserRole(username: string): Promise<UserRoleAssignment> {
    const userRow = await this.executeRaw({
      name: "permission-get-user-primary-role",
      text: "SELECT role, perm_version FROM mbkcore_users WHERE username = $1 LIMIT 1",
      values: [username],
    });
    const primaryRole = userRow.rows?.[0]?.role ? normalizePermission(userRow.rows[0].role) : "normaluser";
    const permVersion = Number(userRow.rows?.[0]?.perm_version ?? 1);
    return { role: primaryRole, roles: [primaryRole], perm_version: permVersion };
  }

  async getUserRoles(username: string): Promise<UserRoleAssignment> {
    return this.getUserRole(username);
  }

  async setUserRole(username: string, role: string): Promise<void> {
    this.invalidateEffectiveCache(username);
    const cleanRole = normalizePermission(role) || "normaluser";
    const isSqlite = this.dialectName === "sqlite";
    await this.executeRaw({
      name: "permission-set-user-role",
      text: `UPDATE mbkcore_users
             SET role = $1,
                 perm_version = (COALESCE(perm_version, 1) + 1),
                 updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"}
             WHERE username = $2`,
      values: [cleanRole, username],
    });
  }

  async setUserRoles(username: string, roles: string[] | string = []): Promise<void> {
    const role = Array.isArray(roles) && roles.length > 0 ? roles[0] : (typeof roles === "string" ? roles : "normaluser");
    return this.setUserRole(username, role);
  }

  async bumpPermissionVersion(username: string): Promise<any> {
    this.invalidateEffectiveCache(username);
    const isSqlite = this.dialectName === "sqlite";
    return this.executeRaw({
      name: "permission-bump-version",
      text: `UPDATE mbkcore_users SET perm_version = (COALESCE(perm_version, 1) + 1),
             updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"} WHERE username = $1`,
      values: [username],
    });
  }

  async computeEffectiveForUser(username: string, knownRole: string | null = null): Promise<EffectivePermissionsResult> {
    const cleanRole = normalizePermission(knownRole);
    if (cleanRole === "superadmin") {
      return {
        roles: ["superadmin"],
        overrides: { allows: [0], denies: [] },
        effective: { allows: [0], denies: [] },
        perm_version: 1,
      };
    }

    const cacheKey = username ? username.toLowerCase() : "";
    if (cacheKey) {
      const cached = this.effectiveCache.get(cacheKey);
      if (cached && Date.now() < cached.expiresAt) {
        if (!knownRole || (cached.snapshot.roles && cached.snapshot.roles.includes(cleanRole))) {
          return cached.snapshot;
        }
      }
    }

    const { role, roles, perm_version } = knownRole
      ? { role: cleanRole, roles: [cleanRole], perm_version: 1 }
      : await this.getUserRoles(username);

    if (role === "superadmin") {
      const superSnapshot: EffectivePermissionsResult = {
        roles: ["superadmin"],
        overrides: { allows: [0], denies: [] },
        effective: { allows: [0], denies: [] },
        perm_version,
      };
      if (cacheKey) this.effectiveCache.set(cacheKey, { snapshot: superSnapshot, expiresAt: Date.now() + this.effectiveCacheTtlMs });
      return superSnapshot;
    }

    if (defaultRoleRegistry.roles.size === 0 && !defaultRoleRegistry.isLoaded) {
      await this.loadAllRolesIntoRegistry(defaultRoleRegistry);
    }

    const overrides = await this.listOverridesForUser(username);
    const denies = overrides.filter((o) => o.effect === "deny").map((o) => o.permission_id);
    const allows = overrides.filter((o) => o.effect === "allow").map((o) => o.permission_id);
    const effective = buildEffectivePermissions({ roles, allows, denies, roleRegistry: defaultRoleRegistry });
    const snapshot: EffectivePermissionsResult = { roles, overrides: { allows, denies }, effective, perm_version };

    if (cacheKey) {
      this.effectiveCache.set(cacheKey, { snapshot, expiresAt: Date.now() + this.effectiveCacheTtlMs });
    }

    return snapshot;
  }
}

export const permissionRepository = new PermissionRepository();
export default permissionRepository;
