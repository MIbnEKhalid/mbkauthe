/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { BaseRepository } from "./BaseRepository.js";

const OAUTH_PROVIDERS = {
  github: { table: "mbkcore_user_github", idColumn: "github_id", queryName: "github-login-get-user" },
  google: { table: "mbkcore_user_google", idColumn: "google_id", queryName: "google-login-get-user" }
};

export function normalizeUserRow(row) {
  if (!row || typeof row !== "object") return row;
  let permissions = row.permissions;
  if (typeof permissions === "string") {
    try { permissions = JSON.parse(permissions); } catch {}
  }

  return {
    ...row,
    role: typeof row.role === "string" ? row.role.toLowerCase() : row.role,
    is_active: row.is_active !== undefined ? Boolean(row.is_active) : undefined,
    is_enabled: row.is_enabled !== undefined && row.is_enabled !== null ? Boolean(row.is_enabled) : null,
    user_allowed_apps: row.user_allowed_apps !== undefined ? row.user_allowed_apps : row.allowed_apps,
    permissions,
  };
}

export class AuthRepository extends BaseRepository {
  buildSessionUserSelect({ includeProfile = false, includeTwoFA = false } = {}) {
    const fields = ["s.id as sid", "s.expires_at", "u.username", "u.user_id", "u.is_active", "u.role", "u.allowed_apps"];
    if (includeProfile) fields.push("u.full_name", "u.image");
    if (includeTwoFA) fields.push("tfa.is_enabled");
    return fields.join(", ");
  }

  resolveOAuthProvider(provider) {
    const config = OAUTH_PROVIDERS[String(provider || "").toLowerCase()];
    if (!config) throw new Error(`Unsupported OAuth provider: ${provider}`);
    return config;
  }

  async fetchActiveSession(session_id) {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_sessions s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: "multi-session-fetch", text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteAppSessionById(session_id, query_name = "invalidate-app-session") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_sessions WHERE id = $1", values: [session_id] });
  }

  async deleteSessionBySid(session_id, query_name = "login-delete-old-session-before-regen") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_session WHERE sid = $1", values: [session_id] });
  }

  async getSessionsWithUsersByIds(session_ids, query_name = "multi-session-fetch-many") {
    if (!Array.isArray(session_ids) || session_ids.length === 0) return [];
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_sessions s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.id = ANY($1)`;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_ids] });
    return (result.rows || []).map(normalizeUserRow);
  }

  async touchTrustedDevice(device_token_hash, username) {
    if (this.dialect.name === "sqlite") {
      const updated = await this.executeRaw({
        name: "check-trusted-device-update",
        text: `UPDATE mbkcore_trusted_devices SET last_used = CURRENT_TIMESTAMP
               WHERE device_token = $1 AND username = $2 AND expires_at > CURRENT_TIMESTAMP
               RETURNING username, expires_at`,
        values: [device_token_hash, username]
      });
      const row = updated.rows?.[0];
      if (!row) return null;

      const userResult = await this.executeRaw({
        name: "check-trusted-device-user",
        text: "SELECT user_id, is_active, role, allowed_apps FROM mbkcore_users WHERE username = $1 AND is_active = 1",
        values: [row.username]
      });
      const userRow = userResult.rows?.[0];
      return userRow ? normalizeUserRow({ ...row, ...userRow }) : null;
    }

    const query = `
      UPDATE mbkcore_trusted_devices td
      SET last_used = NOW()
      FROM mbkcore_users u
      WHERE td.device_token = $1
        AND td.username = $2
        AND td.expires_at > NOW()
        AND u.username = td.username
        AND u.is_active = TRUE
      RETURNING td.username, td.expires_at, u.user_id, u.is_active, u.role, u.allowed_apps
    `;
    const result = await this.executeRaw({ name: "check-trusted-device", text: query, values: [device_token_hash, username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async cleanupAndCountUserSessions(username, query_name = "cleanup-and-count-user-sessions") {
    if (this.dialect.name === "sqlite") {
      await this.executeRaw({
        name: `${query_name}-delete`,
        text: "DELETE FROM mbkcore_sessions WHERE username = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()",
        values: [username]
      });
      const result = await this.executeRaw({
        name: `${query_name}-count`,
        text: "SELECT COUNT(*) AS count FROM mbkcore_sessions WHERE username = $1",
        values: [username]
      });
      return Number(result.rows?.[0]?.count ?? 0);
    }

    const query = `
      WITH deleted AS (
        DELETE FROM mbkcore_sessions
        WHERE username = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()
      )
      SELECT COUNT(*)::int AS count
      FROM mbkcore_sessions
      WHERE username = $1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [username] });
    return Number(result.rows?.[0]?.count ?? 0);
  }

  async deleteOldestSessionsForUser(username, limit, query_name = "prune-oldest-user-session") {
    if (!Number.isFinite(limit) || limit <= 0) return 0;
    const query = "DELETE FROM mbkcore_sessions WHERE id IN (SELECT id FROM mbkcore_sessions WHERE username = $1 ORDER BY created_at ASC LIMIT $2)";
    const result = await this.executeRaw({ name: query_name, text: query, values: [username, limit] });
    return result.rowCount || 0;
  }

  async deleteExpiredSessionsForUser(username) {
    const query = this.sql`
      DELETE FROM ${this.table("mbkcore_sessions")}
      WHERE ${this.ident("username")} = ${this.value(username)}
        AND ${this.ident("expires_at")} IS NOT NULL
        AND ${this.ident("expires_at")} <= ${this.now()}
    `;
    const result = await this.execute("cleanup-expired-user-sessions", query);
    return result.rowCount || 0;
  }

  async countActiveSessionsForUser(username) {
    const query = this.sql`
      SELECT ${this.columns([`COUNT(*) AS ${this.quoteIdentifier("count")}`])}
      FROM ${this.table("mbkcore_sessions")}
      WHERE ${this.ident("username")} = ${this.value(username)}
    `;
    const result = await this.execute("count-user-sessions", query);
    return Number(result.rows?.[0]?.count ?? 0);
  }

  async getOldestSessionIds(username, limit) {
    if (!Number.isFinite(limit) || limit <= 0) return [];
    const query = this.sql`
      SELECT ${this.column("id")}
      FROM ${this.table("mbkcore_sessions")}
      WHERE ${this.ident("username")} = ${this.value(username)}
      ORDER BY ${this.ident("created_at")} ASC
      ${this.limit(limit)}
    `;
    const result = await this.execute("oldest-user-sessions", query);
    return (result.rows || []).map((row) => row.id).filter(Boolean);
  }

  async insertAppSession(username, expires_at, meta) {
    const result = await this.executeRaw({
      name: "insert-app-session",
      text: "INSERT INTO mbkcore_sessions (username, expires_at, meta) VALUES ($1, $2, $3) RETURNING id",
      values: [username, expires_at, meta]
    });
    return result.rows?.[0] || null;
  }

  async updateLastLoginReturnProfile(username) {
    const result = await this.executeRaw({
      name: "login-update-last-login-return-profile",
      text: "UPDATE mbkcore_users SET last_login = NOW() WHERE username = $1 RETURNING full_name, image",
      values: [username]
    });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async touchUserLastLogin(username) {
    return this.executeRaw({
      name: "login-update-last-login",
      text: "UPDATE mbkcore_users SET last_login = NOW() WHERE username = $1",
      values: [username]
    });
  }

  async getUserProfileByUsername(username, query_name = "login-get-fullname-and-image") {
    const result = await this.executeRaw({ name: query_name, text: "SELECT full_name, image FROM mbkcore_users WHERE username = $1 LIMIT 1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async insertTrustedDevice({ username, device_token_hash, device_name, user_agent, ip_address, expires_at }) {
    return this.executeRaw({
      name: "insert-trusted-device",
      text: "INSERT INTO mbkcore_trusted_devices (username, device_token, device_name, user_agent, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
      values: [username, device_token_hash, device_name, user_agent, ip_address, expires_at]
    });
  }

  async getUserWithTwoFA(username, query_name = "login-get-user") {
    const query = `
      SELECT u.username, u.user_id, u.password_hash, u.is_active, u.role, u.allowed_apps,
             tfa.is_enabled, u.full_name, u.image
      FROM mbkcore_users u
      LEFT JOIN mbkcore_two_factor tfa ON u.username = tfa.username
      WHERE u.username = $1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getTwoFASecret(username) {
    const result = await this.executeRaw({ name: "verify-2fa-secret", text: "SELECT tfa.two_fa_secret FROM mbkcore_two_factor tfa WHERE tfa.username = $1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteSessionsByIds(session_ids, query_name = "delete-sessions-by-ids") {
    if (!Array.isArray(session_ids) || session_ids.length === 0) return 0;
    const result = await this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_sessions WHERE id = ANY($1)", values: [session_ids] });
    return result.rowCount || 0;
  }

  async getOAuthUserByProviderId(provider, provider_id) {
    const { table, idColumn, queryName } = this.resolveOAuthProvider(provider);
    const query = `SELECT ug.*, u.username, u.user_id, u.role, u.is_active, u.allowed_apps, tfa.is_enabled
                   FROM ${table} ug
                   JOIN mbkcore_users u ON ug.username = u.username
                   LEFT JOIN mbkcore_two_factor tfa ON u.username = tfa.username
                   WHERE ug.${idColumn} = $1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [provider_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getApiTokenByHash(token_hash, query_name = "validate-api-token") {
    const query = `
      SELECT t.id, t.username, t.expires_at, t.permissions,
             u.user_id, u.is_active, u.role, u.allowed_apps as user_allowed_apps, u.full_name
      FROM mbkcore_api_tokens t
      JOIN mbkcore_users u ON t.username = u.username
      WHERE t.token_hash = $1 LIMIT 1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [token_hash] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async updateApiTokenLastUsed(token_id, query_name = "update-api-token-last-used", min_interval_minutes = 15) {
    const query = this.dialect.name === "sqlite"
      ? "UPDATE mbkcore_api_tokens SET last_used = CURRENT_TIMESTAMP WHERE id = ? AND (last_used IS NULL OR last_used < datetime('now', '-' || ? || ' minutes'))"
      : "UPDATE mbkcore_api_tokens SET last_used = NOW() WHERE id = $1 AND (last_used IS NULL OR last_used < NOW() - ($2::int * INTERVAL '1 minute'))";
    const values = [token_id, min_interval_minutes];
    return this.executeRaw(query_name ? { name: query_name, text: query, values } : { text: query, values });
  }

  async getSessionAuthData(session_id, query_name = "validate-app-session") {
    const query = "SELECT s.expires_at, u.is_active, u.role, u.allowed_apps, u.username FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1";
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionWithUserById(session_id, query_name = "restore-user-session") {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })} FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionWithUserForReload(session_id, query_name = "reload-session-user") {
    return this.getSessionWithUserById(session_id, query_name);
  }

  async getSessionValidationRow(session_id, query_name = "check-session-validity-by-id") {
    const query = "SELECT s.expires_at, u.is_active, u.username, u.role FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1";
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserFullNameByUsername(username, query_name = "get-fullname-by-username") {
    const result = await this.executeRaw({ name: query_name, text: "SELECT full_name FROM mbkcore_users WHERE username = $1 LIMIT 1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserImageByUsername(username, query_name = "get-user-profile-pic") {
    const result = await this.executeRaw({ name: query_name, text: "SELECT image FROM mbkcore_users WHERE username = $1 LIMIT 1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionValidity(session_id, session_store_sid, query_name = "check-session-validity") {
    const query = `
      SELECT s.expires_at, u.is_active,
        CASE WHEN s.expires_at IS NULL THEN (SELECT expire FROM mbkcore_session WHERE sid = $2) ELSE NULL END AS connect_expire
      FROM mbkcore_sessions s
      JOIN mbkcore_users u ON s.username = u.username
      WHERE s.id = $1 LIMIT 1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id, session_store_sid] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteAllAppSessions(query_name = "delete-all-app-sessions") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_sessions", values: [] });
  }

  async deleteActiveSessionStoreRows(query_name = "delete-active-session-store-rows") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_session WHERE expire > NOW()", values: [] });
  }
}