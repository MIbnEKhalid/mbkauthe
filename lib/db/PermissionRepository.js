/**
 * MBKAuthe — Permission repository.
 *
 * Owns the raw persistence for the dynamic permission model:
 *   - `mbkcore_permission_catalog`        (the permission catalog)
 *   - `mbkcore_permission_templates`      (named reusable permission bundles)
 *   - `mbkcore_user_permission_overrides` (per-user allow/deny exceptions)
 *   - `mbkcore_users.permission_templates` / `.perm_version`
 *
 * Effective permissions are only computed at login / session refresh and are
 * cached on the session. This repository is deliberately NEVER used on the
 * normal request authorization path (see `hasPermission`).
 *
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { dblogin, dialect } from "#pool.js";
import { BaseRepository } from "./BaseRepository.js";
import { buildEffectivePermissions, GLOBAL_APP_KEY } from "../permissions.js";

const TABLES = ["mbkcore_permission_catalog", "mbkcore_permission_templates", "mbkcore_user_permission_overrides"];
const GLOBAL_PERMISSION = {
  appKey: GLOBAL_APP_KEY,
  serviceKey: "basic",
  actionKey: "access",
  label: "Basic global access",
};

function parseJsonValue(value) {
  if (value == null) return null;
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

function parseJsonArray(value) {
  const parsed = parseJsonValue(value);
  return Array.isArray(parsed) ? parsed : [];
}

function toJsonColumn(dialectName, value) {
  // Always hand the driver a JSON string; PostgreSQL needs the ::jsonb cast
  // (the SQLite adapter strips the cast when it translates the statement).
  return JSON.stringify(value ?? []);
}

function toBool(value) {
  if (value === 1 || value === true) return true;
  if (value === 0 || value === false) return false;
  return Boolean(value);
}

export class PermissionRepository extends BaseRepository {
  constructor(options = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
    this.ensureGlobalPermission().catch((err) => {
      const message = err?.message || "";
      if (!/no such table|relation .* does not exist|does not exist/i.test(message)) {
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

  /**
   * Upsert a catalog permission (used by syncAppPermissions). Marks active.
   * @param {{ appKey: string, serviceKey: string, actionKey: string, label?: string }} input
   */
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
    if (String(appKey).trim().toLowerCase() === GLOBAL_APP_KEY) {
      return { rowCount: 0 };
    }
    const isSqlite = this.dialectName === "sqlite";
    return this.executeRaw({
      name: "permission-deactivate-app",
      text: `UPDATE mbkcore_permission_catalog SET is_active = ${isSqlite ? "0" : "false"}, updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"}
             WHERE app_key = $1`,
      values: [appKey],
    });
  }

  /**
   * Synchronize the catalog for one application. Deactivates app permissions
   * that are no longer declared and (re)activates declared ones. Never deletes.
   * @param {string} appKey
   * @param {Array<{ serviceKey: string, actionKey: string, label?: string }>} declared
   */
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

  /** @returns {Promise<Array<Record<string, any>>>} */
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

  /** Active catalog permissions only (used to build token permission pickers). */
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

  /**
   * Look up a full permission string in the catalog.
   * @returns {Promise<{ permission: string, is_active: boolean } | null>}
   */
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
    if (!row) return null;
    return {
      permission: `${row.app_key}:${row.service_key}:${row.action_key}`,
      is_active: toBool(row.is_active),
    };
  }

  /** True when the permission exists in the catalog AND is active. */
  async isCatalogPermissionActive(permission) {
    const found = await this.lookupCatalogPermission(permission);
    return Boolean(found?.is_active);
  }

  // -------------------------------------------------------------- Templates

  /** @returns {Promise<Array<{ name: string, permissions: string[] }>>} */
  async listTemplates() {
    const result = await this.executeRaw({
      name: "permission-list-templates",
      text: `SELECT id, name, permissions, created_at, updated_at
             FROM mbkcore_permission_templates
             ORDER BY name`,
      values: [],
    });
    return (result.rows || []).map((row) => ({
      id: row.id,
      name: row.name,
      permissions: parseJsonArray(row.permissions),
      created_at: row.created_at,
      updated_at: row.updated_at,
    }));
  }

  async getTemplateByName(name) {
    const result = await this.executeRaw({
      name: "permission-get-template",
      text: `SELECT id, name, permissions, created_at, updated_at
             FROM mbkcore_permission_templates WHERE name = $1 LIMIT 1`,
      values: [name],
    });
    const row = result.rows?.[0];
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      permissions: parseJsonArray(row.permissions),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  async createTemplate(name, permissions = []) {
    return this.executeRaw({
      name: "permission-create-template",
      text: `INSERT INTO mbkcore_permission_templates (name, permissions)
             VALUES ($1, $2::jsonb)`,
      values: [name, toJsonColumn(this.dialectName, permissions)],
    });
  }

  async updateTemplatePermissions(name, permissions = []) {
    const isSqlite = this.dialectName === "sqlite";
    return this.executeRaw({
      name: "permission-update-template",
      text: `UPDATE mbkcore_permission_templates SET permissions = $2::jsonb, updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"} WHERE name = $1`,
      values: [name, toJsonColumn(this.dialectName, permissions)],
    });
  }

  async deleteTemplate(name) {
    return this.executeRaw({
      name: "permission-delete-template",
      text: `DELETE FROM mbkcore_permission_templates WHERE name = $1`,
      values: [name],
    });
  }

  // -------------------------------------------------------------- Overrides

  /** @returns {Promise<Array<{ permission: string, effect: 'allow'|'deny', granted_by: string|null, created_at: any }>>} */
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
      text: `DELETE FROM mbkcore_user_permission_overrides WHERE username = $1 AND permission = $2`,
      values: [username, permission],
    });
  }

  async clearOverridesForUser(username) {
    return this.executeRaw({
      name: "permission-clear-overrides",
      text: `DELETE FROM mbkcore_user_permission_overrides WHERE username = $1`,
      values: [username],
    });
  }

  // ------------------------------------------- User template assignment/version

  async getUserPermissionTemplates(username) {
    const result = await this.executeRaw({
      name: "permission-get-user-templates",
      text: `SELECT permission_templates, perm_version FROM mbkcore_users WHERE username = $1 LIMIT 1`,
      values: [username],
    });
    const row = result.rows?.[0];
    if (!row) return { templates: [], perm_version: 1 };
    return {
      templates: parseJsonArray(row.permission_templates),
      perm_version: Number(row.perm_version ?? 1),
    };
  }

  /**
   * Assign a set of permission templates to a user and bump their perm_version.
   * @param {string} username
   * @param {string[]} templateNames
   */
  async setUserPermissionTemplates(username, templateNames = []) {
    const isSqlite = this.dialectName === "sqlite";
    const names = [...new Set(templateNames.map((n) => String(n).trim()).filter(Boolean))];
    return this.executeRaw({
      name: "permission-set-user-templates",
      text: `UPDATE mbkcore_users
             SET permission_templates = $2::jsonb, perm_version = (COALESCE(perm_version, 1) + 1),
                 updated_at = ${isSqlite ? "CURRENT_TIMESTAMP" : "now()"}
             WHERE username = $1`,
      values: [username, toJsonColumn(this.dialectName, names)],
    });
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

  /**
   * Load a user's assigned templates and overrides and compute effective
   * permissions. Called ONLY at login/session refresh (never on the request
   * authorization path).
   *
   * @param {string} username
   * @returns {Promise<{ templates: string[], allows: string[], denies: string[], perm_version: number }>}
   */
  async computeEffectiveForUser(username) {
    const { templates: assignedTemplateNames, perm_version } = await this.getUserPermissionTemplates(username);

    let templateBundles = [];
    if (assignedTemplateNames.length > 0) {
      const templateRows = await this.getTemplatePermissionsByName(assignedTemplateNames);
      templateBundles = templateRows.map((row) => row.permissions);
    }

    const overrides = await this.listOverridesForUser(username);
    const denies = overrides.filter((o) => o.effect === "deny").map((o) => o.permission);
    const allows = overrides.filter((o) => o.effect === "allow").map((o) => o.permission);

    const effective = buildEffectivePermissions({ templates: templateBundles, allows, denies });

    return {
      templates: assignedTemplateNames,
      allows: effective.allows,
      denies: effective.denies,
      perm_version,
    };
  }

  async getTemplatePermissionsByName(names = []) {
    const clean = [...new Set(names.map((n) => String(n).trim()).filter(Boolean))];
    if (clean.length === 0) return [];
    const placeholders = clean.map((_, i) => `$${i + 1}`).join(", ");
    const result = await this.executeRaw({
      name: "permission-templates-by-names",
      text: `SELECT name, permissions FROM mbkcore_permission_templates WHERE name IN (${placeholders})`,
      values: clean,
    });
    return (result.rows || []).map((row) => ({
      name: row.name,
      permissions: parseJsonArray(row.permissions),
    }));
  }
}

export const permissionRepository = new PermissionRepository();
export default permissionRepository;
