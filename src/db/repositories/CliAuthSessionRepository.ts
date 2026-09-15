/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { BaseRepository, BaseRepositoryOptions } from "./BaseRepository.js";
import { dblogin, dialect } from "../pool.js";
import type { CliAuthSession, ApiTokenProfile } from "../../core/types/token.types.js";

const SESSION_COLUMNS = `id, device_code_hash, user_code_hash, client_name, profile_id,
  username, token_id, pending_token, status, expires_at, created_at, approved_at`;

const PROFILE_COLUMNS = "id, profile_key, name, description, permissions, expires_in_days, is_active";

function parseJsonArray(value: unknown): string[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

const normalizeProfileRow = (row: any): ApiTokenProfile | null => (row ? {
  ...row,
  permissions: parseJsonArray(row.permissions),
  is_active: row.is_active !== undefined ? Boolean(row.is_active) : true,
} : null);

export interface CreateCliAuthSessionOptions {
  device_code_hash: string;
  user_code_hash: string;
  client_name: string;
  profile_id?: number | null;
  expires_at: Date | string;
}

export interface ApproveCliAuthOptions {
  username: string;
  token_id: string | number;
  pending_token: string;
}

export class CliAuthSessionRepository extends BaseRepository {
  constructor(options: BaseRepositoryOptions = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
  }

  async create({ device_code_hash, user_code_hash, client_name, profile_id = null, expires_at }: CreateCliAuthSessionOptions): Promise<CliAuthSession | null> {
    const { rows } = await this.executeRaw({
      name: "cli-auth-create",
      text: `INSERT INTO mbkcore_cli_auth_sessions (device_code_hash, user_code_hash, client_name, profile_id, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING ${SESSION_COLUMNS}`,
      values: [device_code_hash, user_code_hash, client_name, profile_id, expires_at],
    });
    return (rows[0] as CliAuthSession) || null;
  }

  async findByDeviceCodeHash(device_code_hash: string): Promise<CliAuthSession | null> {
    const { rows } = await this.executeRaw({
      name: "cli-auth-find-by-device",
      text: `SELECT ${SESSION_COLUMNS} FROM mbkcore_cli_auth_sessions WHERE device_code_hash = $1`,
      values: [device_code_hash],
    });
    return (rows[0] as CliAuthSession) || null;
  }

  async findByUserCodeHash(user_code_hash: string): Promise<CliAuthSession | null> {
    const { rows } = await this.executeRaw({
      name: "cli-auth-find-by-user-code",
      text: `SELECT ${SESSION_COLUMNS} FROM mbkcore_cli_auth_sessions WHERE user_code_hash = $1`,
      values: [user_code_hash],
    });
    return (rows[0] as CliAuthSession) || null;
  }

  async markApproved(id: number | string, { username, token_id, pending_token }: ApproveCliAuthOptions): Promise<boolean> {
    const isSqlite = this.dialect?.name === "sqlite";
    const nowSql = isSqlite ? "CURRENT_TIMESTAMP" : "NOW()";
    const { rows } = await this.executeRaw({
      name: "cli-auth-approve",
      text: `UPDATE mbkcore_cli_auth_sessions
             SET status = 'approved', username = $2, token_id = $3,
                  pending_token = $4, approved_at = ${nowSql}
             WHERE id = $1 AND status = 'pending'
             RETURNING id`,
      values: [id, username, token_id, pending_token],
    });
    return Boolean(rows[0]);
  }

  async markDenied(id: number | string): Promise<any> {
    return this.executeRaw({
      name: "cli-auth-deny",
      text: "UPDATE mbkcore_cli_auth_sessions SET status = 'denied' WHERE id = $1 AND status = 'pending'",
      values: [id],
    });
  }

  async markExpired(id: number | string): Promise<any> {
    return this.executeRaw({
      name: "cli-auth-expire",
      text: "UPDATE mbkcore_cli_auth_sessions SET status = 'expired' WHERE id = $1 AND status = 'pending'",
      values: [id],
    });
  }

  async expireStale(now: Date = new Date()): Promise<any> {
    return this.executeRaw({
      name: "cli-auth-expire-stale",
      text: "UPDATE mbkcore_cli_auth_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at <= $1",
      values: [now],
    });
  }

  async completeDelivery(id: number | string): Promise<boolean> {
    const { rows } = await this.executeRaw({
      name: "cli-auth-complete-delivery",
      text: "UPDATE mbkcore_cli_auth_sessions SET status = 'completed', pending_token = NULL WHERE id = $1 AND status = 'approved' RETURNING id",
      values: [id],
    });
    return Boolean(rows[0]);
  }

  async deleteById(id: number | string): Promise<any> {
    return this.executeRaw({ name: "cli-auth-delete", text: "DELETE FROM mbkcore_cli_auth_sessions WHERE id = $1", values: [id] });
  }

  async getProfileById(profile_id: number | string): Promise<ApiTokenProfile | null> {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-profile",
      text: `SELECT ${PROFILE_COLUMNS} FROM mbkcore_api_token_profiles WHERE id = $1`,
      values: [profile_id],
    });
    return normalizeProfileRow(rows[0]);
  }

  async getActiveProfileById(profile_id: number | string): Promise<ApiTokenProfile | null> {
    const isSqlite = this.dialect?.name === "sqlite";
    const trueVal = isSqlite ? "1" : "TRUE";
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile",
      text: `SELECT ${PROFILE_COLUMNS} FROM mbkcore_api_token_profiles WHERE id = $1 AND is_active = ${trueVal}`,
      values: [profile_id],
    });
    return normalizeProfileRow(rows[0]);
  }

  async getActiveProfileByKey(profile_key: string): Promise<ApiTokenProfile | null> {
    const isSqlite = this.dialect?.name === "sqlite";
    const trueVal = isSqlite ? "1" : "TRUE";
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile-by-key",
      text: `SELECT ${PROFILE_COLUMNS} FROM mbkcore_api_token_profiles WHERE profile_key = $1 AND is_active = ${trueVal}`,
      values: [profile_key],
    });
    return normalizeProfileRow(rows[0]);
  }
}

export const cliAuthSessionRepository = new CliAuthSessionRepository();
export default cliAuthSessionRepository;
