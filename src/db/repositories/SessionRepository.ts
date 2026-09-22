import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { normalizeUserRow } from "./UserRepository.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export class SessionRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  buildSessionUserSelect({ includeProfile = false, includeTwoFA = false } = {}): string {
    const fields = ["s.sid as sid", "s.expire as expires_at", "u.username", "u.user_id", "u.is_active", "u.is_local_only", "u.role", "u.allowed_apps"];
    if (includeProfile) fields.push("u.full_name", "u.image");
    if (includeTwoFA) fields.push("tfa.is_enabled");
    return fields.join(", ");
  }

  async fetchActiveSession(session_id: string): Promise<AuthUser | null> {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_session s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.sid = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: "multi-session-fetch", text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteAppSessionById(session_id: string, query_name: string = "invalidate-app-session") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_session WHERE sid = $1", values: [session_id] });
  }

  async deleteSessionBySid(session_id: string, query_name: string = "login-delete-old-session-before-regen") {
    return this.executeRaw({ name: query_name, text: "DELETE FROM mbkcore_session WHERE sid = $1", values: [session_id] });
  }

  async getSessionsWithUsersByIds(session_ids: string[], query_name: string = "multi-session-fetch-many"): Promise<AuthUser[]> {
    if (!Array.isArray(session_ids) || session_ids.length === 0) return [];
    
    if (this.dialect.name === "sqlite") {
      const placeholders = session_ids.map(() => "?").join(", ");
      const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                     FROM mbkcore_session s
                     JOIN mbkcore_users u ON s.username = u.username
                     WHERE s.sid IN (${placeholders})`;
      const result = await this.executeRaw({ name: query_name, text: query, values: session_ids });
      return (result.rows || []).map(normalizeUserRow).filter(Boolean) as AuthUser[];
    }

    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_session s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.sid = ANY($1)`;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_ids] });
    return (result.rows || []).map(normalizeUserRow).filter(Boolean) as AuthUser[];
  }

  async cleanupAndCountUserSessions(username: string, query_name: string = "cleanup-and-count-user-sessions"): Promise<number> {
    if (this.dialect.name === "sqlite") {
      await this.executeRaw({
        name: `${query_name}-delete`,
        text: "DELETE FROM mbkcore_session WHERE username = $1 AND expire IS NOT NULL AND expire <= CURRENT_TIMESTAMP",
        values: [username]
      });
      const result = await this.executeRaw({
        name: `${query_name}-count`,
        text: "SELECT COUNT(*) AS count FROM mbkcore_session WHERE username = $1",
        values: [username]
      });
      return Number(result.rows?.[0]?.count ?? 0);
    }

    const query = `
      WITH deleted AS (
        DELETE FROM mbkcore_session
        WHERE username = $1
          AND expire IS NOT NULL
          AND expire <= NOW()
      )
      SELECT COUNT(*)::int AS count
      FROM mbkcore_session
      WHERE username = $1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [username] });
    return Number(result.rows?.[0]?.count ?? 0);
  }

  async deleteOldestSessionsForUser(username: string, limit: number, query_name: string = "prune-oldest-user-session"): Promise<number> {
    if (!Number.isFinite(limit) || limit <= 0) return 0;
    const query = "DELETE FROM mbkcore_session WHERE sid IN (SELECT sid FROM mbkcore_session WHERE username = $1 ORDER BY created_at ASC LIMIT $2)";
    const result = await this.executeRaw({ name: query_name, text: query, values: [username, limit] });
    return result.rowCount || 0;
  }

  async touchUserLastLogin(username: string) {
    return this.executeRaw({
      name: "login-update-last-login",
      text: this.dialect.name === "sqlite" ? "UPDATE mbkcore_users SET last_login = CURRENT_TIMESTAMP WHERE username = $1" : "UPDATE mbkcore_users SET last_login = NOW() WHERE username = $1",
      values: [username]
    });
  }

  async insertAppSession(username: string, expires_at: any, meta: any, sid?: string, device_id?: string | null) {
    const finalSid = sid || (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
    const sess = JSON.stringify({ user: { username } });
    const result = await this.executeRaw({
      name: "insert-app-session",
      text: "INSERT INTO mbkcore_session (sid, sess, username, expire, meta, device_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING sid",
      values: [finalSid, sess, username, expires_at, meta, device_id || null]
    });
    const row = result.rows?.[0];
    return row ? { sid: row.sid, id: row.sid } : null;
  }

  async createAppSessionWithPruning({ username, expiresAt, meta = null, maxSessions = 5, sid, device_id = null }: { username: string; expiresAt: any; meta?: any; maxSessions?: number; sid?: string; device_id?: string | null }) {
    const configuredMax = Number.isInteger(maxSessions) && maxSessions > 0 ? maxSessions : 5;

    return this.withTransaction(async (txRepo: any) => {
      await txRepo.advisoryTransactionLock(`sessions:${username}`, "lock-user-sessions");
      const currentSessions = await txRepo.cleanupAndCountUserSessions(username);
      if (currentSessions >= configuredMax) {
        const sessionsToDelete = currentSessions - configuredMax + 1;
        await txRepo.deleteOldestSessionsForUser(username, sessionsToDelete, "prune-oldest-user-session");
      }
      await txRepo.touchUserLastLogin(username);
      const inserted = await txRepo.insertAppSession(username, expiresAt, meta, sid, device_id);
      if (!inserted?.id) throw new Error("Failed to insert app session");
      return inserted;
    });
  }

  async findSessionsByDeviceId(deviceId: string): Promise<any[]> {
    if (!deviceId) return [];
    const query = this.dialect.name === "sqlite"
      ? `SELECT s.sid, s.username, s.expire AS expires_at, s.last_activity, s.meta,
                u.full_name, u.image, u.role, u.is_active, u.is_local_only, u.allowed_apps
         FROM mbkcore_session s
         JOIN mbkcore_users u ON s.username = u.username
         WHERE s.device_id = $1
           AND (s.expire IS NULL OR s.expire > CURRENT_TIMESTAMP)
         ORDER BY s.last_activity DESC`
      : `SELECT s.sid, s.username, s.expire AS expires_at, s.last_activity, s.meta,
                u.full_name, u.image, u.role, u.is_active, u.is_local_only, u.allowed_apps
         FROM mbkcore_session s
         JOIN mbkcore_users u ON s.username = u.username
         WHERE s.device_id = $1
           AND (s.expire IS NULL OR s.expire > NOW())
         ORDER BY s.last_activity DESC`;
    const result = await this.executeRaw({ name: "find-sessions-by-device-id", text: query, values: [deviceId] });
    return (result.rows || []).map((row: any) => normalizeUserRow(row)).filter(Boolean);
  }

  async findDeviceSession(deviceId: string, sid: string): Promise<any | null> {
    if (!deviceId || !sid) return null;
    const query = this.dialect.name === "sqlite"
      ? `SELECT s.sid, s.username, s.expire AS expires_at, s.last_activity, s.meta,
                u.user_id, u.full_name, u.image, u.role, u.is_active, u.is_local_only, u.allowed_apps
         FROM mbkcore_session s
         JOIN mbkcore_users u ON s.username = u.username
         WHERE s.device_id = $1 AND s.sid = $2
           AND (s.expire IS NULL OR s.expire > CURRENT_TIMESTAMP)
         LIMIT 1`
      : `SELECT s.sid, s.username, s.expire AS expires_at, s.last_activity, s.meta,
                u.user_id, u.full_name, u.image, u.role, u.is_active, u.is_local_only, u.allowed_apps
         FROM mbkcore_session s
         JOIN mbkcore_users u ON s.username = u.username
         WHERE s.device_id = $1 AND s.sid = $2
           AND (s.expire IS NULL OR s.expire > NOW())
         LIMIT 1`;
    const result = await this.executeRaw({ name: "find-device-session", text: query, values: [deviceId, sid] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async deleteDeviceSession(deviceId: string, sid: string): Promise<boolean> {
    if (!deviceId || !sid) return false;
    const result = await this.executeRaw({
      name: "delete-device-session",
      text: "DELETE FROM mbkcore_session WHERE device_id = $1 AND sid = $2",
      values: [deviceId, sid]
    });
    return (result.rowCount ?? 0) > 0;
  }

  async deleteAllDeviceSessions(deviceId: string): Promise<number> {
    if (!deviceId) return 0;
    const result = await this.executeRaw({
      name: "delete-all-device-sessions",
      text: "DELETE FROM mbkcore_session WHERE device_id = $1",
      values: [deviceId]
    });
    return result.rowCount ?? 0;
  }

  async touchSessionActivity(sid: string): Promise<void> {
    if (!sid) return;
    const query = this.dialect.name === "sqlite"
      ? "UPDATE mbkcore_session SET last_activity = CURRENT_TIMESTAMP WHERE sid = $1"
      : "UPDATE mbkcore_session SET last_activity = NOW() WHERE sid = $1";
    await this.executeRaw({ name: "touch-session-activity", text: query, values: [sid] });
  }

  async getSessionAuthData(session_id: string, query_name: string = "validate-app-session"): Promise<AuthUser | null> {
    const query = `
      SELECT s.expire AS expires_at, u.username, u.is_active, u.is_local_only, u.role, u.allowed_apps
      FROM mbkcore_session s
      JOIN mbkcore_users u ON s.username = u.username
      WHERE s.sid = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionWithUserForReload(session_id: string, query_name: string = "reload-session-user"): Promise<AuthUser | null> {
    const query = `
      SELECT s.expire AS expires_at, u.username, u.user_id, u.full_name, u.role, u.allowed_apps, u.is_active, u.is_local_only
      FROM mbkcore_session s
      JOIN mbkcore_users u ON s.username = u.username
      WHERE s.sid = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }
}

export const sessionRepository = new SessionRepository();
