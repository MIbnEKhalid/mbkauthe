import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";
import { defaultTokenEncryptor } from "../../oauth/crypto/tokenEncryption.js";

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
    is_local_only: row.is_local_only !== undefined ? Boolean(row.is_local_only && row.is_local_only !== "0" && row.is_local_only !== "false") : undefined,
    is_enabled: row.is_enabled !== undefined && row.is_enabled !== null ? Boolean(row.is_enabled) : null,
    permissions,
  };
}

export class UserRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  async getUserWithTwoFA(username: string): Promise<AuthUser | null> {
    const query = `
      SELECT u.user_id, u.username, u.password_hash, u.full_name, u.image,
             u.role, u.allowed_apps, u.is_active, u.is_local_only, tfa.is_enabled
      FROM mbkcore_users u
      LEFT JOIN mbkcore_two_factor tfa ON u.username = tfa.username
      WHERE (u.username = $1 OR u.user_id = $1)
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: "get-user-with-2fa", text: query, values: [username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserById(userId: string | number): Promise<AuthUser | null> {
    const query = `
      SELECT u.user_id, u.username, u.full_name, u.image, u.role, u.allowed_apps, u.is_active, u.is_local_only
      FROM mbkcore_users u
      WHERE u.user_id = $1
      LIMIT 1
    `;
    const result = await this.executeRaw({ name: "get-user-by-id", text: query, values: [userId] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async getUserByUsername(username: string): Promise<AuthUser | null> {
    const query = `
      SELECT u.user_id, u.username, u.full_name, u.image, u.role, u.allowed_apps, u.is_active, u.is_local_only
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

  /**
   * Retrieves and automatically decrypts user's TOTP 2FA secret from mbkcore_two_factor.
   */
  async getTwoFASecret(username: string): Promise<{ two_fa_secret: string | null; is_enabled: boolean } | null> {
    const query = `SELECT two_fa_secret, is_enabled FROM mbkcore_two_factor WHERE username = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: "get-user-2fa-secret", text: query, values: [username] });
    if (!result.rows?.[0]) return null;
    const rawSecret = result.rows[0].two_fa_secret;
    return {
      two_fa_secret: rawSecret ? defaultTokenEncryptor.decrypt(rawSecret) : null,
      is_enabled: Boolean(result.rows[0].is_enabled),
    };
  }

  /**
   * Saves or updates user's TOTP 2FA secret, automatically encrypting it at rest in mbkcore_two_factor.
   */
  async saveTwoFASecret(username: string, secret: string, is_enabled: boolean = false): Promise<void> {
    const encrypted = defaultTokenEncryptor.encrypt(secret) || secret;
    const query = `
      INSERT INTO mbkcore_two_factor (username, is_enabled, two_fa_secret)
      VALUES ($1, $2, $3)
      ON CONFLICT (username) DO UPDATE SET
        two_fa_secret = EXCLUDED.two_fa_secret,
        is_enabled = EXCLUDED.is_enabled
    `;
    await this.executeRaw({
      name: "save-user-2fa-secret",
      text: query,
      values: [username, is_enabled ? (this.dialect?.name === "sqlite" ? 1 : true) : (this.dialect?.name === "sqlite" ? 0 : false), encrypted],
    });
  }

  /**
   * Disables 2FA and clears secret for user.
   */
  async disableTwoFA(username: string): Promise<void> {
    const query = `UPDATE mbkcore_two_factor SET is_enabled = $1, two_fa_secret = '' WHERE username = $2`;
    await this.executeRaw({
      name: "disable-user-2fa",
      text: query,
      values: [this.dialect?.name === "sqlite" ? 0 : false, username],
    });
  }
}

export const userRepository = new UserRepository();
