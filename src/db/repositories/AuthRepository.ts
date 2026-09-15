import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";

const OAUTH_PROVIDERS: Record<string, { table: string; idColumn: string; queryName: string }> = {
  github: { table: "mbkcore_user_github", idColumn: "github_id", queryName: "github-login-get-user" },
  google: { table: "mbkcore_user_google", idColumn: "google_id", queryName: "google-login-get-user" }
};

export function normalizeUserRow(row: any): AuthUser | null {
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
  buildSessionUserSelect({ includeProfile = false, includeTwoFA = false } = {}): string {
    const fields = ["s.id as sid", "s.expires_at", "u.username", "u.user_id", "u.is_active", "u.role", "u.allowed_apps"];
    if (includeProfile) fields.push("u.full_name", "u.image");
    if (includeTwoFA) fields.push("tfa.is_enabled");
    return fields.join(", ");
  }

  resolveOAuthProvider(provider: string) {
    const config = OAUTH_PROVIDERS[String(provider || "").toLowerCase()];
    if (!config) throw new Error(`Unsupported OAuth provider: ${provider}`);
    return config;
  }

  async fetchActiveSession(session_id: string): Promise<AuthUser | null> {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_sessions s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: "multi-session-fetch", text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteAppSessionById(session_id: string, query_name: string = "invalidate-app-session") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_sessions WHERE id = $1", values: [session_id] });
  }

  async deleteSessionBySid(session_id: string, query_name: string = "login-delete-old-session-before-regen") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_session WHERE sid = $1", values: [session_id] });
  }

  async getSessionsWithUsersByIds(session_ids: string[], query_name: string = "multi-session-fetch-many"): Promise<AuthUser[]> {
    if (!Array.isArray(session_ids) || session_ids.length === 0) return [];
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_sessions s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.id = ANY($1)`;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_ids] });
    return (result.rows || []).map(normalizeUserRow).filter(Boolean) as AuthUser[];
  }

  async touchTrustedDevice(device_token_hash: string, username: string): Promise<AuthUser | null> {
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

  async cleanupAndCountUserSessions(username: string, query_name: string = "cleanup-and-count-user-sessions"): Promise<number> {
    if (this.dialect.name === "sqlite") {
      await this.executeRaw({
        name: `${query_name}-delete`,
        text: "DELETE FROM mbkcore_sessions WHERE username = $1 AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP",
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

  async deleteOldestSessionsForUser(username: string, limit: number, query_name: string = "prune-oldest-user-session"): Promise<number> {
    if (!Number.isFinite(limit) || limit <= 0) return 0;
    const query = "DELETE FROM mbkcore_sessions WHERE id IN (SELECT id FROM mbkcore_sessions WHERE username = $1 ORDER BY created_at ASC LIMIT $2)";
    const result = await this.executeRaw({ name: query_name, text: query, values: [username, limit] });
    return result.rowCount || 0;
  }

  async insertAppSession(username: string, expires_at: any, meta: any) {
    const result = await this.executeRaw({
      name: "insert-app-session",
      text: "INSERT INTO mbkcore_sessions (username, expires_at, meta) VALUES ($1, $2, $3) RETURNING id",
      values: [username, expires_at, meta]
    });
    return result.rows?.[0] || null;
  }

  async createAppSessionWithPruning({ username, expiresAt, meta = null, maxSessions = 5 }: { username: string; expiresAt: any; meta?: any; maxSessions?: number }) {
    const configuredMax = Number.isInteger(maxSessions) && maxSessions > 0 ? maxSessions : 5;

    return this.withTransaction(async (txRepo) => {
      await txRepo.advisoryTransactionLock(`sessions:${username}`, "lock-user-sessions");
      const currentSessions = await txRepo.cleanupAndCountUserSessions(username);
      if (currentSessions >= configuredMax) {
        const sessionsToDelete = currentSessions - configuredMax + 1;
        await txRepo.deleteOldestSessionsForUser(username, sessionsToDelete, "prune-oldest-user-session");
      }
      await txRepo.touchUserLastLogin(username);
      const inserted = await txRepo.insertAppSession(username, expiresAt, meta);
      if (!inserted?.id) throw new Error("Failed to insert app session");
      return inserted;
    });
  }

  async countActiveSessionsForUser(username: string, query_name: string = "count-active-sessions"): Promise<number> {
    const text = this.dialect.name === "sqlite"
      ? "SELECT COUNT(*) AS count FROM mbkcore_sessions WHERE username = $1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
      : "SELECT COUNT(*)::int AS count FROM mbkcore_sessions WHERE username = $1 AND (expires_at IS NULL OR expires_at > NOW())";
    const result = await this.executeRaw({ name: query_name, text, values: [username] });
    return Number(result.rows?.[0]?.count ?? 0);
  }

  async updateLastLoginReturnProfile(username: string, query_name: string = "update-last-login-profile"): Promise<AuthUser | null> {
    const text = this.dialect.name === "sqlite"
      ? "UPDATE mbkcore_users SET last_login = CURRENT_TIMESTAMP WHERE username = $1 RETURNING full_name, image, role, allowed_apps"
      : "UPDATE mbkcore_users SET last_login = NOW() WHERE username = $1 RETURNING full_name, image, role, allowed_apps";
    const result = await this.executeRaw({ name: query_name, text, values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async touchUserLastLogin(username: string) {
    return this.executeRaw({
      name: "login-update-last-login",
      text: this.dialect.name === "sqlite" ? "UPDATE mbkcore_users SET last_login = CURRENT_TIMESTAMP WHERE username = $1" : "UPDATE mbkcore_users SET last_login = NOW() WHERE username = $1",
      values: [username]
    });
  }

  async insertTrustedDevice({ username, device_token_hash, device_name, user_agent, ip_address, expires_at }: any) {
    return this.executeRaw({
      name: "insert-trusted-device",
      text: "INSERT INTO mbkcore_trusted_devices (username, device_token, device_name, user_agent, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
      values: [username, device_token_hash, device_name, user_agent, ip_address, expires_at]
    });
  }

  async getUserWithTwoFA(username: string, query_name: string = "login-get-user"): Promise<AuthUser | null> {
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

  async getTwoFASecret(username: string): Promise<any> {
    const result = await this.executeRaw({ name: "verify-2fa-secret", text: "SELECT tfa.two_fa_secret FROM mbkcore_two_factor tfa WHERE tfa.username = $1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getOAuthUserByProviderId(provider: string, provider_id: string): Promise<AuthUser | null> {
    const { table, idColumn, queryName } = this.resolveOAuthProvider(provider);
    const query = `SELECT ug.*, u.username, u.user_id, u.role, u.is_active, u.allowed_apps, u.full_name, u.image, tfa.is_enabled
                   FROM ${table} ug
                   JOIN mbkcore_users u ON ug.username = u.username
                   LEFT JOIN mbkcore_two_factor tfa ON u.username = tfa.username
                   WHERE ug.${idColumn} = $1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [provider_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getApiTokenByHash(token_hash: string, query_name: string = "validate-api-token"): Promise<any> {
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

  async updateApiTokenLastUsed(token_id: any, query_name: string = "update-api-token-last-used", min_interval_minutes: number = 15) {
    const query = this.dialect.name === "sqlite"
      ? "UPDATE mbkcore_api_tokens SET last_used = CURRENT_TIMESTAMP WHERE id = ? AND (last_used IS NULL OR last_used < datetime('now', '-' || ? || ' minutes'))"
      : "UPDATE mbkcore_api_tokens SET last_used = NOW() WHERE id = $1 AND (last_used IS NULL OR last_used < NOW() - ($2::int * INTERVAL '1 minute'))";
    const values = [token_id, min_interval_minutes];
    return this.executeRaw(query_name ? { name: query_name, text: query, values } : { text: query, values });
  }

  async getSessionAuthData(session_id: string, query_name: string = "validate-app-session"): Promise<AuthUser | null> {
    const query = "SELECT s.expires_at, u.is_active, u.role, u.allowed_apps, u.username FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1";
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionWithUserById(session_id: string, query_name: string = "restore-user-session"): Promise<AuthUser | null> {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })} FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionWithUserForReload(session_id: string, query_name: string = "reload-session-user"): Promise<AuthUser | null> {
    return this.getSessionWithUserById(session_id, query_name);
  }

  async getUserFullNameByUsername(username: string, query_name: string = "get-fullname-by-username") {
    const result = await this.executeRaw({ name: query_name, text: "SELECT full_name FROM mbkcore_users WHERE username = $1 LIMIT 1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserImageByUsername(username: string, query_name: string = "get-user-profile-pic") {
    const result = await this.executeRaw({ name: query_name, text: "SELECT image FROM mbkcore_users WHERE username = $1 LIMIT 1", values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteSessionsByIds(session_ids: string[], query_name: string = "delete-sessions-by-ids"): Promise<number> {
    if (!Array.isArray(session_ids) || session_ids.length === 0) return 0;
    const result = await this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_sessions WHERE id = ANY($1)", values: [session_ids] });
    return result.rowCount || 0;
  }

  async getSessionValidationRow(session_id: string, query_name: string = "check-session-validity-by-id"): Promise<AuthUser | null> {
    const query = "SELECT s.expires_at, u.is_active, u.username, u.role FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1";
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionValidity(session_id: string, session_store_sid: string, query_name: string = "check-session-validity"): Promise<any> {
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

  async deleteAllAppSessions(query_name: string = "delete-all-app-sessions"): Promise<any> {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_sessions", values: [] });
  }

  async deleteActiveSessionStoreRows(query_name: string = "delete-active-session-store-rows"): Promise<any> {
    const text = this.dialect.name === "sqlite"
      ? "DELETE FROM mbkcore_session WHERE expire > CURRENT_TIMESTAMP"
      : "DELETE FROM mbkcore_session WHERE expire > NOW()";
    return this.executeRaw({ name: query_name, text, values: [] });
  }
}

export const authRepository = new AuthRepository();
export default authRepository;
