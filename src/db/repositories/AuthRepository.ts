import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { UserRepository, userRepository, normalizeUserRow } from "./UserRepository.js";
import { SessionRepository, sessionRepository } from "./SessionRepository.js";
import { DeviceTrustRepository, deviceTrustRepository } from "./DeviceTrustRepository.js";
import { ApiTokenRepository, apiTokenRepository } from "./ApiTokenRepository.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export { normalizeUserRow };

export class AuthRepository extends BaseRepository {
  public users: UserRepository;
  public sessions: SessionRepository;
  public deviceTrust: DeviceTrustRepository;
  public apiTokens: ApiTokenRepository;

  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
    this.users = new UserRepository(options);
    this.sessions = new SessionRepository(options);
    this.deviceTrust = new DeviceTrustRepository(options);
    this.apiTokens = new ApiTokenRepository(options);
  }

  buildSessionUserSelect(opts?: any): string {
    return this.sessions.buildSessionUserSelect(opts);
  }

  async fetchActiveSession(session_id: string): Promise<AuthUser | null> {
    return this.sessions.fetchActiveSession(session_id);
  }

  async deleteAppSessionById(session_id: string, query_name?: string) {
    return this.sessions.deleteAppSessionById(session_id, query_name);
  }

  async deleteSessionBySid(session_id: string, query_name?: string) {
    return this.sessions.deleteSessionBySid(session_id, query_name);
  }

  async getSessionsWithUsersByIds(session_ids: string[], query_name?: string): Promise<AuthUser[]> {
    return this.sessions.getSessionsWithUsersByIds(session_ids, query_name);
  }

  async touchTrustedDevice(device_token_hash: string, username: string): Promise<AuthUser | null> {
    return this.deviceTrust.touchTrustedDevice(device_token_hash, username);
  }

  async cleanupAndCountUserSessions(username: string, query_name?: string): Promise<number> {
    return this.sessions.cleanupAndCountUserSessions(username, query_name);
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

  async createAppSessionWithPruning(params: { username: string; expiresAt: any; meta?: any; maxSessions?: number }) {
    return this.sessions.createAppSessionWithPruning(params);
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

  async insertTrustedDevice(params: any) {
    return this.deviceTrust.insertTrustedDevice(params);
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
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })} FROM mbkcore_sessions s JOIN mbkcore_users u ON s.username = u.username WHERE s.id = $1 LIMIT 1`;
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
    if (this.dialect.name === "sqlite") {
      const placeholders = session_ids.map(() => "?").join(", ");
      const result = await this.executeRaw({ name: query_name, text: `DELETE FROM mbkcore_sessions WHERE id IN (${placeholders})`, values: session_ids });
      return result.rowCount || 0;
    }
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
