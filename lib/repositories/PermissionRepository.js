/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { dblogin, dialect } from "#pool.js";
import { BaseRepository } from "./BaseRepository.js";
import { buildEffectivePermissions, GLOBAL_APP_KEY, defaultRoleRegistry, normalizePermission } from "../permissions.js";

const GLOBAL_PERMISSION = {
  appKey: GLOBAL_APP_KEY,
  serviceKey: "basic",
  actionKey: "access",
  label: "Basic global access",
};

const toBool = (val) => Boolean(val === 1 || val === true || val === "1" || val === "true");

export class PermissionRepository extends BaseRepository {
  constructor(options = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
    this.ensureGlobalPermission().catch((err) => {
      const msg = err?.message || "";
      if (!/no such table|relation .* does not exist|does not exist/i.test(msg)) {
        console.error("[mbkauthe] Failed to ensure built-in global permission:", err);
      }
    });
  }

  get dialectName() {
    return this.dialect?.name || "postgres";
  }

  async ensureGlobalPermission() {
    await this.upsertCatalogPermission(GLOBAL_PERMISSION);
  }

  // ---------------------------------------------------------------- Catalog

  async upsertCatalogPermission({ appKey, serviceKey, actionKey, label = null }) {
    const isSqlite = this.dialectName === "sqlite";
    const text = isSqlite
      ? `INSERT INTO mbkcore_permission_catalog (app_key, service_key, action_key, label, is_active)
         VALUES ($1, $2, $3, $4, 1)
         ON CONFLICT(app_key, service_key, action_key)
         DO UPDATE SET label = excluded.label, is_active = 1, updated_at = CURRENT_TIMESTAMP`
      : `INSERT INTO mbkcore_permission_catalog (app_key, service_key, action_key, label, is_active)
         VALUES ($1, $2, $3, $4, true)
         ON CONFLICT (app_key, service_key, action_key)
         DO UPDATE SET label = EXCLUDED.label, is_active = true, updated_at = now()`;
    return this.executeRaw({ name: "permission-upsert-catalog", text, values: [appKey, serviceKey, actionKey, label] });
  }

  async deactivateAllCatalogPermissionsForApp(appKey) {
    if (String(appKey).trim().toLowerCase() === GLOBAL_APP_KEY) return { rowCount: 0 };
    const isSqlite = this.dialectName === "sqlite";
    return this.executeRaw({
      name: "permission-deactivate-app",
      text: `UPDATE mbkcore_permission_catalog SET is_active = ${isSqlite ? "0" : "false"}, updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"} WHERE app_key = $1`,
      values: [appKey],
    });
  }

  async syncCatalogForApp(appKey, declared = []) {
    await this.withTransaction(async (txRepo) => {
      await txRepo.deactivateAllCatalogPermissionsForApp(appKey);
      for (const perm of declared) {
        await txRepo.upsertCatalogPermission({
          appKey,
          serviceKey: perm.serviceKey,
          actionKey: perm.actionKey,
          label: perm.label,
        });
      }
    });
  }

  async listCatalog() {
    const result = await this.executeRaw({
      name: "permission-list-catalog",
      text: `SELECT id, app_key, service_key, action_key, label, is_active, updated_at
             FROM mbkcore_permission_catalog
             ORDER BY app_key, service_key, action_key`,
      values: [],
    });
    return (result.rows || []).map((row) => ({
      id: row.id,
      app_key: row.app_key,
      service_key: row.service_key,
      action_key: row.action_key,
      label: row.label,
      is_active: toBool(row.is_active),
      updated_at: row.updated_at,
      permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
    }));
  }

  async listActiveCatalog() {
    const catalog = await this.listCatalog();
    return catalog.filter((row) => row.is_active);
  }

  async listCatalogByApp(appKey) {
    const result = await this.executeRaw({
      name: "permission-list-catalog-app",
      text: `SELECT id, app_key, service_key, action_key, label, is_active, updated_at
             FROM mbkcore_permission_catalog
             WHERE app_key = $1
             ORDER BY service_key, action_key`,
      values: [appKey],
    });
    return (result.rows || []).map((row) => ({
      id: row.id,
      app_key: row.app_key,
      service_key: row.service_key,
      action_key: row.action_key,
      label: row.label,
      is_active: toBool(row.is_active),
      permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
    }));
  }

  async lookupCatalogPermission(permission) {
    const segments = String(permission || "").split(":");
    if (segments.length !== 3) return null;
    const [appKey, serviceKey, actionKey] = segments.map((s) => String(s).trim().toLowerCase());
    if (!appKey || !serviceKey || !actionKey) return null;

    const result = await this.executeRaw({
      name: "permission-lookup-catalog",
      text: `SELECT app_key, service_key, action_key, is_active FROM mbkcore_permission_catalog
             WHERE app_key = $1 AND service_key = $2 AND action_key = $3 LIMIT 1`,
      values: [appKey, serviceKey, actionKey],
    });
    const row = result.rows?.[0];
    return row ? { permission: `${row.app_key}:${row.service_key}:${row.action_key}`, is_active: toBool(row.is_active) } : null;
  }

  async isCatalogPermissionActive(permission) {
    const found = await this.lookupCatalogPermission(permission);
    return Boolean(found?.is_active);
  }

  // ---------------------------------------------------------------- Roles

  async listRoles() {
    const rolesResult = await this.executeRaw({
      name: "permission-list-roles",
      text: "SELECT id, name, label, description, is_system, created_at, updated_at FROM mbkcore_roles ORDER BY name",
      values: [],
    });
    const roles = rolesResult.rows || [];
    if (roles.length === 0) return [];

    const permsResult = await this.executeRaw({
      name: "permission-list-role-perms",
      text: "SELECT role_name, permission FROM mbkcore_role_permissions ORDER BY role_name, permission",
      values: [],
    });

    const permsByRole = new Map();
    for (const row of permsResult.rows || []) {
      const list = permsByRole.get(row.role_name) || [];
      list.push(row.permission);
      permsByRole.set(row.role_name, list);
    }

    return roles.map((r) => ({
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

  async getRoleByName(name) {
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
      text: "SELECT permission FROM mbkcore_role_permissions WHERE role_name = $1 ORDER BY permission",
      values: [cleanName],
    });

    return {
      id: row.id,
      name: row.name,
      label: row.label || row.name,
      description: row.description || "",
      is_system: toBool(row.is_system),
      permissions: (permsResult.rows || []).map((p) => p.permission),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  async createRole(name, permissions = [], options = {}) {
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

  async setRolePermissions(roleName, permissions = []) {
    const cleanName = normalizePermission(roleName);
    const cleanPerms = [...new Set(permissions.map(normalizePermission).filter(Boolean))];

    await this.withTransaction(async (txRepo) => {
      await txRepo.executeRaw({
        name: "permission-clear-role-perms",
        text: "DELETE FROM mbkcore_role_permissions WHERE role_name = $1",
        values: [cleanName],
      });

      for (const perm of cleanPerms) {
        await txRepo.executeRaw({
          name: "permission-insert-role-perm",
          text: txRepo.dialectName === "sqlite"
            ? "INSERT INTO mbkcore_role_permissions (role_name, permission) VALUES ($1, $2) ON CONFLICT(role_name, permission) DO NOTHING"
            : "INSERT INTO mbkcore_role_permissions (role_name, permission) VALUES ($1, $2) ON CONFLICT (role_name, permission) DO NOTHING",
          values: [cleanName, perm],
        });
      }
    });

    await this.loadAllRolesIntoRegistry();
  }

  async contributeRolePermissions(roleName, permissions = [], options = {}) {
    const cleanName = normalizePermission(roleName);
    const cleanPerms = [...new Set(permissions.map(normalizePermission).filter(Boolean))];

    await this.withTransaction(async (txRepo) => {
      const isSqlite = txRepo.dialectName === "sqlite";
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

      for (const perm of cleanPerms) {
        await txRepo.executeRaw({
          name: "permission-insert-role-perm-contrib",
          text: isSqlite
            ? "INSERT INTO mbkcore_role_permissions (role_name, permission) VALUES ($1, $2) ON CONFLICT(role_name, permission) DO NOTHING"
            : "INSERT INTO mbkcore_role_permissions (role_name, permission) VALUES ($1, $2) ON CONFLICT (role_name, permission) DO NOTHING",
          values: [cleanName, perm],
        });
      }
    });

    defaultRoleRegistry.addRolePermissions(cleanName, cleanPerms);
  }

  async deleteRole(name) {
    const cleanName = normalizePermission(name);
    await this.executeRaw({ name: "permission-delete-role", text: "DELETE FROM mbkcore_roles WHERE name = $1", values: [cleanName] });
    defaultRoleRegistry.deleteRole(cleanName);
  }

  async loadAllRolesIntoRegistry(registry = defaultRoleRegistry) {
    try {
      const permsResult = await this.executeRaw({
        name: "permission-load-all-role-perms",
        text: "SELECT role_name, permission FROM mbkcore_role_permissions",
        values: [],
      });

      const roleMap = new Map();
      for (const row of permsResult.rows || []) {
        const list = roleMap.get(row.role_name) || [];
        list.push(row.permission);
        roleMap.set(row.role_name, list);
      }

      registry.clear();
      for (const [role, perms] of roleMap.entries()) registry.setRole(role, perms);
      return registry;
    } catch (err) {
      const msg = err?.message || "";
      if (!/no such table|relation .* does not exist|does not exist/i.test(msg)) {
        console.error("[mbkauthe] Failed to hydrate RoleRegistry:", err);
      }
      return registry;
    }
  }

  // -------------------------------------------------------------- Overrides

  async listOverridesForUser(username) {
    const result = await this.executeRaw({
      name: "permission-list-user-overrides",
      text: `SELECT permission, effect, granted_by, created_at
             FROM mbkcore_user_permission_overrides
             WHERE username = $1
             ORDER BY effect, permission`,
      values: [username],
    });
    return (result.rows || []).map((row) => ({
      permission: row.permission,
      effect: row.effect,
      granted_by: row.granted_by,
      created_at: row.created_at,
    }));
  }

  async setOverride(username, permission, effect, grantedBy = null) {
    const effectValue = String(effect || "").toLowerCase();
    if (!["allow", "deny"].includes(effectValue)) {
      throw new Error(`[mbkauthe] Invalid override effect "${effect}" (expected allow|deny)`);
    }
    const isSqlite = this.dialectName === "sqlite";
    const text = isSqlite
      ? `INSERT INTO mbkcore_user_permission_overrides (username, permission, effect, granted_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT(username, permission)
         DO UPDATE SET effect = excluded.effect, granted_by = excluded.granted_by, created_at = CURRENT_TIMESTAMP`
      : `INSERT INTO mbkcore_user_permission_overrides (username, permission, effect, granted_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (username, permission)
         DO UPDATE SET effect = EXCLUDED.effect, granted_by = EXCLUDED.granted_by, created_at = now()`;
    return this.executeRaw({
      name: "permission-set-override",
      text,
      values: [username, permission, effectValue, grantedBy],
    });
  }

  async removeOverride(username, permission) {
    return this.executeRaw({
      name: "permission-remove-override",
      text: "DELETE FROM mbkcore_user_permission_overrides WHERE username = $1 AND permission = $2",
      values: [username, permission],
    });
  }

  async clearOverridesForUser(username) {
    return this.executeRaw({
      name: "permission-clear-overrides",
      text: "DELETE FROM mbkcore_user_permission_overrides WHERE username = $1",
      values: [username],
    });
  }

  async replaceOverridesForUser(username, overrides = [], grantedBy = null) {
    await this.withTransaction(async (txRepo) => {
      await txRepo.clearOverridesForUser(username);
      for (const item of overrides) {
        const perm = normalizePermission(item.permission);
        const effect = String(item.effect || "").toLowerCase();
        if (perm && ["allow", "deny"].includes(effect)) {
          await txRepo.setOverride(username, perm, effect, grantedBy);
        }
      }
      await txRepo.bumpPermissionVersion(username);
    });
  }

  // ---------------------------------------------------- User Role Assignment

  async getUserRole(username) {
    const userRow = await this.executeRaw({
      name: "permission-get-user-primary-role",
      text: "SELECT role, perm_version FROM mbkcore_users WHERE username = $1 LIMIT 1",
      values: [username],
    });
    const primaryRole = userRow.rows?.[0]?.role ? normalizePermission(userRow.rows[0].role) : "normaluser";
    const permVersion = Number(userRow.rows?.[0]?.perm_version ?? 1);
    return { role: primaryRole, roles: [primaryRole], perm_version: permVersion };
  }

  async getUserRoles(username) {
    return this.getUserRole(username);
  }

  async setUserRole(username, role) {
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

  async setUserRoles(username, roles = []) {
    const role = Array.isArray(roles) && roles.length > 0 ? roles[0] : (typeof roles === "string" ? roles : "normaluser");
    return this.setUserRole(username, role);
  }

  async bumpPermissionVersion(username) {
    const isSqlite = this.dialectName === "sqlite";
    return this.executeRaw({
      name: "permission-bump-version",
      text: `UPDATE mbkcore_users SET perm_version = (COALESCE(perm_version, 1) + 1),
             updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"} WHERE username = $1`,
      values: [username],
    });
  }

  // ------------------------------------------------- Effective permissions

  async computeEffectiveForUser(username) {
    await this.loadAllRolesIntoRegistry();
    const { roles, perm_version } = await this.getUserRoles(username);
    const overrides = await this.listOverridesForUser(username);
    const denies = overrides.filter((o) => o.effect === "deny").map((o) => o.permission);
    const allows = overrides.filter((o) => o.effect === "allow").map((o) => o.permission);
    const effective = buildEffectivePermissions({ roles, allows, denies, roleRegistry: defaultRoleRegistry });
    return { roles, overrides: { allows, denies }, effective, perm_version };
  }
}

export const permissionRepository = new PermissionRepository();
export default permissionRepository;
