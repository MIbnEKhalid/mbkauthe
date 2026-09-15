import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

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

export class UserRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  resolveOAuthProvider(provider: string) {
    const config = OAUTH_PROVIDERS[String(provider || "").toLowerCase()];
    if (!config) throw new Error(`Unsupported OAuth provider: ${provider}`);
    return config;
  }

  async getUserWithTwoFA(username: string): Promise<AuthUser | null> {
    const query = `
      SELECT u.user_id, u.username, u.password_hash, u.full_name, u.image,
             u.role, u.allowed_apps, u.is_active, tfa.is_enabled
      FROM mbkcore_users u
      LEFT JOIN mbkcore_user_two_fa tfa ON u.username = tfa.username
      WHERE u.username = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: "get-user-with-2fa", text: query, values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserById(userId: string | number): Promise<AuthUser | null> {
    const query = `
      SELECT u.user_id, u.username, u.full_name, u.image, u.role, u.allowed_apps, u.is_active
      FROM mbkcore_users u
      WHERE u.user_id = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: "get-user-by-id", text: query, values: [userId] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserByUsername(username: string): Promise<AuthUser | null> {
    const query = `
      SELECT u.user_id, u.username, u.full_name, u.image, u.role, u.allowed_apps, u.is_active
      FROM mbkcore_users u
      WHERE u.username = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: "get-user-by-username", text: query, values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserImageByUsername(username: string, query_name: string = "get-user-image-by-username"): Promise<{ image: string | null } | null> {
    const result = await this.executeRaw({ name: query_name, text: "SELECT image FROM mbkcore_users WHERE username = $1", values: [username] });
    return result.rows?.[0] || null;
  }

  async getTwoFASecret(username: string): Promise<{ secret: string; is_enabled: boolean } | null> {
    const query = `SELECT secret, is_enabled FROM mbkcore_user_two_fa WHERE username = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: "get-user-2fa-secret", text: query, values: [username] });
    return result.rows?.[0] || null;
  }

  async getOAuthUser(provider: string, profileId: string | number): Promise<AuthUser | null> {
    const config = this.resolveOAuthProvider(provider);
    const query = `
      SELECT u.user_id, u.username, u.full_name, u.image, u.role, u.allowed_apps, u.is_active, tfa.is_enabled
      FROM ${config.table} p
      JOIN mbkcore_users u ON p.username = u.username
      LEFT JOIN mbkcore_user_two_fa tfa ON u.username = tfa.username
      WHERE p.${config.idColumn} = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: config.queryName, text: query, values: [profileId] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }
}

export const userRepository = new UserRepository();
