import { BaseRepository } from "./BaseRepository.js";
import { dblogin, dialect } from "#pool.js";

const SESSION_COLUMNS = `id, device_code_hash, user_code_hash, client_name, profile_id,
  username, token_id, pending_token, status, expires_at, created_at, approved_at`;

const PROFILE_COLUMNS = `id, profile_key, name, description, allowed_apps, scope, expires_in_days, is_active`;

function normalizeSessionRow(row) {
  if (!row) return row;
  return {
    ...row,
    id: row.id,
    device_code_hash: row.device_code_hash,
    user_code_hash: row.user_code_hash,
    client_name: row.client_name,
    profile_id: row.profile_id,
    username: row.username,
    token_id: row.token_id,
    pending_token: row.pending_token,
    status: row.status,
    expires_at: row.expires_at,
    created_at: row.created_at,
    approved_at: row.approved_at,
  };
}

function normalizeProfileRow(row) {
  if (!row) return row;
  return {
    ...row,
    id: row.id,
    profile_key: row.profile_key,
    name: row.name,
    description: row.description,
    allowed_apps: row.allowed_apps,
    scope: row.scope,
    expires_in_days: row.expires_in_days,
    is_active: row.is_active !== undefined ? Boolean(row.is_active) : undefined,
  };
}

export class CliAuthSessionRepository extends BaseRepository {
  constructor(options = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
  }

  async create({ device_code_hash, user_code_hash, client_name, profile_id, expires_at }) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-create",
      text: `INSERT INTO mbkcore_cli_auth_sessions (device_code_hash, user_code_hash, client_name, profile_id, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING ${SESSION_COLUMNS}`,
      values: [device_code_hash, user_code_hash, client_name, profile_id, expires_at],
    });
    return rows[0] ? normalizeSessionRow(rows[0]) : null;
  }

  async findByDeviceCodeHash(device_code_hash) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-find-by-device",
      text: `SELECT ${SESSION_COLUMNS} FROM mbkcore_cli_auth_sessions WHERE device_code_hash = $1`,
      values: [device_code_hash],
    });
    return rows[0] ? normalizeSessionRow(rows[0]) : null;
  }

  async findByUserCodeHash(user_code_hash) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-find-by-user-code",
      text: `SELECT ${SESSION_COLUMNS} FROM mbkcore_cli_auth_sessions WHERE user_code_hash = $1`,
      values: [user_code_hash],
    });
    return rows[0] ? normalizeSessionRow(rows[0]) : null;
  }

  async markApproved(id, { username, token_id, pending_token }) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-approve",
      text: `UPDATE mbkcore_cli_auth_sessions
             SET status = 'approved', username = $2, token_id = $3,
                  pending_token = $4, approved_at = NOW()
             WHERE id = $1 AND status = 'pending'
             RETURNING id`,
      values: [id, username, token_id, pending_token],
    });
    return Boolean(rows[0]);
  }

  async markDenied(id) {
    return this.executeRaw({
      name: "cli-auth-deny",
      text: `UPDATE mbkcore_cli_auth_sessions SET status = 'denied' WHERE id = $1 AND status = 'pending'`,
      values: [id],
    });
  }

  async markExpired(id) {
    return this.executeRaw({
      name: "cli-auth-expire",
      text: `UPDATE mbkcore_cli_auth_sessions SET status = 'expired' WHERE id = $1 AND status = 'pending'`,
      values: [id],
    });
  }

  async expireStale(now = new Date()) {
    return this.executeRaw({
      name: "cli-auth-expire-stale",
      text: `UPDATE mbkcore_cli_auth_sessions SET status = 'expired'
             WHERE status = 'pending' AND expires_at <= $1`,
      values: [now],
    });
  }

  async completeDelivery(id) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-complete-delivery",
      text: `UPDATE mbkcore_cli_auth_sessions SET status = 'completed', pending_token = NULL
             WHERE id = $1 AND status = 'approved'
             RETURNING id`,
      values: [id],
    });
    return Boolean(rows[0]);
  }

  async deleteById(id) {
    return this.executeRaw({
      name: "cli-auth-delete",
      text: 'DELETE FROM mbkcore_cli_auth_sessions WHERE id = $1',
      values: [id],
    });
  }

  async getProfileById(profile_id) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-profile",
      text: `SELECT ${PROFILE_COLUMNS} FROM mbkcore_api_token_profiles WHERE id = $1`,
      values: [profile_id],
    });
    return rows[0] ? normalizeProfileRow(rows[0]) : null;
  }

  async getActiveProfileById(profile_id) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile",
      text: `SELECT ${PROFILE_COLUMNS} FROM mbkcore_api_token_profiles WHERE id = $1 AND is_active = TRUE`,
      values: [profile_id],
    });
    return rows[0] ? normalizeProfileRow(rows[0]) : null;
  }

  async getActiveProfileByKey(profile_key) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile-by-key",
      text: `SELECT ${PROFILE_COLUMNS} FROM mbkcore_api_token_profiles WHERE profile_key = $1 AND is_active = TRUE`,
      values: [profile_key],
    });
    return rows[0] ? normalizeProfileRow(rows[0]) : null;
  }
}

export const cliAuthSessionRepository = new CliAuthSessionRepository();
export default cliAuthSessionRepository;
