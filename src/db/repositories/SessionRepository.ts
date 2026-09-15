import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { normalizeUserRow } from "./UserRepository.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export class SessionRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  buildSessionUserSelect({ includeProfile = false, includeTwoFA = false } = {}): string {
    const fields = ["s.id as sid", "s.expires_at", "u.username", "u.user_id", "u.is_active", "u.role", "u.allowed_apps"];
    if (includeProfile) fields.push("u.full_name", "u.image");
    if (includeTwoFA) fields.push("tfa.is_enabled");
    return fields.join(", ");
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
    
    if (this.dialect.name === "sqlite") {
      const placeholders = session_ids.map(() => "?").join(", ");
      const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                     FROM mbkcore_sessions s
                     JOIN mbkcore_users u ON s.username = u.username
                     WHERE s.id IN (${placeholders})`;
      const result = await this.executeRaw({ name: query_name, text: query, values: session_ids });
      return (result.rows || []).map(normalizeUserRow).filter(Boolean) as AuthUser[];
    }

    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                   FROM mbkcore_sessions s
                   JOIN mbkcore_users u ON s.username = u.username
                   WHERE s.id = ANY($1)`;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_ids] });
    return (result.rows || []).map(normalizeUserRow).filter(Boolean) as AuthUser[];
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
        WHERE username = $1
          AND expires_at IS NOT NULL
          AND expires_at <= NOW()
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

  async touchUserLastLogin(username: string) {
    return this.executeRaw({
      name: "login-update-last-login",
      text: this.dialect.name === "sqlite" ? "UPDATE mbkcore_users SET last_login = CURRENT_TIMESTAMP WHERE username = $1" : "UPDATE mbkcore_users SET last_login = NOW() WHERE username = $1",
      values: [username]
    });
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

    return this.withTransaction(async (txRepo: any) => {
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

  async getSessionAuthData(session_id: string, query_name: string = "validate-app-session"): Promise<AuthUser | null> {
    const query = `
      SELECT s.expires_at, u.username, u.is_active, u.role, u.allowed_apps
      FROM mbkcore_sessions s
      JOIN mbkcore_users u ON s.username = u.username
      WHERE s.id = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getSessionWithUserForReload(session_id: string, query_name: string = "reload-session-user"): Promise<AuthUser | null> {
    const query = `
      SELECT s.expires_at, u.username, u.user_id, u.full_name, u.role, u.allowed_apps, u.is_active
      FROM mbkcore_sessions s
      JOIN mbkcore_users u ON s.username = u.username
      WHERE s.id = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: query_name, text: query, values: [session_id] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }
}

export const sessionRepository = new SessionRepository();
