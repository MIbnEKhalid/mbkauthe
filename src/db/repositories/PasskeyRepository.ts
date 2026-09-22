import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { normalizeUserRow } from "./UserRepository.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export interface PasskeyRow {
  id: number;
  username: string;
  credential_id: string;
  public_key: string;
  counter: number | string;
  device_type: string;
  backed_up: boolean | number;
  transports: string;
  name: string;
  aaguid?: string | null;
  created_at: Date | string;
  last_used_at?: Date | string | null;
}

export interface CreatePasskeyParams {
  username: string;
  credential_id: string;
  public_key: string;
  counter?: number;
  device_type?: string;
  backed_up?: boolean;
  transports?: string[];
  name?: string;
  aaguid?: string;
}

export class PasskeyRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  /**
   * Finds a passkey by credential ID and joins the active user data.
   */
  async findByCredentialId(credentialId: string): Promise<(PasskeyRow & { user: AuthUser }) | null> {
    if (this.dialect.name === "sqlite") {
      const passkeyRes = await this.executeRaw({
        name: "find-passkey-by-credential-id",
        text: `SELECT id, username, credential_id, public_key, counter, device_type, backed_up, transports, name, aaguid, created_at, last_used_at
               FROM mbkcore_passkeys
               WHERE credential_id = $1`,
        values: [credentialId],
      });
      const row = passkeyRes.rows?.[0];
      if (!row) return null;

      const userRes = await this.executeRaw({
        name: "find-user-for-passkey",
        text: `SELECT user_id, username, full_name, image, is_active, is_local_only, role, allowed_apps
               FROM mbkcore_users
               WHERE username = $1`,
        values: [row.username],
      });
      const userRow = userRes.rows?.[0];
      if (!userRow) return null;

      return {
        ...row,
        user: normalizeUserRow(userRow),
      };
    }

    const query = `
      SELECT p.id, p.username, p.credential_id, p.public_key, p.counter, p.device_type, p.backed_up, p.transports, p.name, p.aaguid, p.created_at, p.last_used_at,
             u.user_id, u.full_name, u.image, u.is_active, u.is_local_only, u.role, u.allowed_apps
      FROM mbkcore_passkeys p
      JOIN mbkcore_users u ON p.username = u.username
      WHERE p.credential_id = $1
    `;
    const result = await this.executeRaw({
      name: "find-passkey-with-user",
      text: query,
      values: [credentialId],
    });

    const row = result.rows?.[0];
    if (!row) return null;

    return {
      id: row.id,
      username: row.username,
      credential_id: row.credential_id,
      public_key: row.public_key,
      counter: row.counter,
      device_type: row.device_type,
      backed_up: Boolean(row.backed_up),
      transports: row.transports,
      name: row.name,
      aaguid: row.aaguid,
      created_at: row.created_at,
      last_used_at: row.last_used_at,
      user: normalizeUserRow(row),
    };
  }

  /**
   * Lists all passkeys registered for a given username.
   */
  async listByUsername(username: string): Promise<PasskeyRow[]> {
    const query = `
      SELECT id, username, credential_id, public_key, counter, device_type, backed_up, transports, name, aaguid, created_at, last_used_at
      FROM mbkcore_passkeys
      WHERE username = $1
      ORDER BY created_at DESC
    `;
    const result = await this.executeRaw({
      name: "list-passkeys-by-username",
      text: query,
      values: [username],
    });

    return (result.rows || []).map((row) => ({
      ...row,
      backed_up: Boolean(row.backed_up),
    }));
  }

  /**
   * Counts passkeys for a given user.
   */
  async countByUsername(username: string): Promise<number> {
    const query = `SELECT COUNT(*) as count FROM mbkcore_passkeys WHERE username = $1`;
    const result = await this.executeRaw({
      name: "count-passkeys-by-username",
      text: query,
      values: [username],
    });
    return parseInt(String(result.rows?.[0]?.count || 0), 10);
  }

  /**
   * Inserts a new passkey.
   */
  async createPasskey(data: CreatePasskeyParams): Promise<PasskeyRow> {
    const {
      username,
      credential_id,
      public_key,
      counter = 0,
      device_type = "single_device",
      backed_up = false,
      transports = [],
      name = "Passkey",
      aaguid = null,
    } = data;

    const transportsJson = JSON.stringify(transports);
    const backedUpVal = this.dialect.name === "sqlite" ? (backed_up ? 1 : 0) : backed_up;

    const query = `
      INSERT INTO mbkcore_passkeys (username, credential_id, public_key, counter, device_type, backed_up, transports, name, aaguid)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id, username, credential_id, public_key, counter, device_type, backed_up, transports, name, aaguid, created_at, last_used_at
    `;

    const result = await this.executeRaw({
      name: "insert-passkey",
      text: query,
      values: [username, credential_id, public_key, counter, device_type, backedUpVal, transportsJson, name, aaguid],
    });

    return result.rows[0];
  }

  /**
   * Updates passkey counter and touches last_used_at timestamp.
   */
  async updateCounterAndLastUsed(credentialId: string, counter: number): Promise<void> {
    const query = this.dialect.name === "sqlite"
      ? `UPDATE mbkcore_passkeys SET counter = $1, last_used_at = CURRENT_TIMESTAMP WHERE credential_id = $2`
      : `UPDATE mbkcore_passkeys SET counter = $1, last_used_at = NOW() WHERE credential_id = $2`;

    await this.executeRaw({
      name: "update-passkey-counter",
      text: query,
      values: [counter, credentialId],
    });
  }

  /**
   * Renames a passkey.
   */
  async renamePasskey(id: number | string, username: string, name: string): Promise<boolean> {
    const query = `UPDATE mbkcore_passkeys SET name = $1 WHERE id = $2 AND username = $3`;
    const result = await this.executeRaw({
      name: "rename-passkey",
      text: query,
      values: [name, id, username],
    });
    return (result.rowCount || 0) > 0;
  }

  /**
   * Deletes a passkey by ID and username.
   */
  async deleteByIdAndUsername(id: number | string, username: string): Promise<boolean> {
    const query = `DELETE FROM mbkcore_passkeys WHERE id = $1 AND username = $2`;
    const result = await this.executeRaw({
      name: "delete-passkey-by-id",
      text: query,
      values: [id, username],
    });
    return (result.rowCount || 0) > 0;
  }

  /**
   * Deletes a passkey by credential ID and username.
   */
  async deleteByCredentialIdAndUsername(credentialId: string, username: string): Promise<boolean> {
    const query = `DELETE FROM mbkcore_passkeys WHERE credential_id = $1 AND username = $2`;
    const result = await this.executeRaw({
      name: "delete-passkey-by-credential-id",
      text: query,
      values: [credentialId, username],
    });
    return (result.rowCount || 0) > 0;
  }
}

export const passkeyRepository = new PasskeyRepository();
