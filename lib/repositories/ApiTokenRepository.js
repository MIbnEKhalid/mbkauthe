import { BaseRepository } from "./BaseRepository.js";
import { dblogin, dialect } from "#pool.js";

function parsePermissions(value) {
  if (value && typeof value === "object") return value;
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch {}
  }
  return {};
}

/** Normalize the token's explicit permission allow-list (`permissions.permissions`). */
function parsePermissionList(value) {
  const raw = value && typeof value === "object" ? value.permissions : undefined;
  const list = Array.isArray(raw) ? raw : [];
  return list
    .map((p) => (typeof p === "string" ? p.trim().toLowerCase() : ""))
    .filter(Boolean);
}

const normalizeToken = (row) => {
  if (!row) return row;
  const perms = parsePermissions(row.permissions);
  const name = row.name;
  const prefix = row.prefix;
  const username = row.username;
  const last_used = row.last_used;
  const created_at = row.created_at;
  const expires_at = row.expires_at;
  const role = row.role;
  const email = row.email;
  const full_name = row.full_name;

  return {
    ...row,
    id: row.id,
    name,
    prefix,
    username,
    permissions: perms,
    token_permissions: parsePermissionList(perms),
    last_used,
    created_at,
    expires_at,
    role,
    email,
    full_name,
  };
};

function formatDateTime(value) {
  if (!value) return "";
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export class ApiTokenRepository extends BaseRepository {
  constructor(options = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
  }

  async listForUser(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-for-user",
      text: `SELECT id, name, prefix, permissions, last_used, created_at, expires_at
             FROM mbkcore_api_tokens WHERE username = $1 ORDER BY created_at DESC`,
      values: [username],
    });
    return rows.map(normalizeToken);
  }

  async countForUser(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-count-for-user",
      text: 'SELECT COUNT(*) as token_count FROM mbkcore_api_tokens WHERE username = $1',
      values: [username],
    });
    return parseInt(rows[0]?.token_count ?? 0, 10);
  }

  async insert(username, name, token_hash, prefix, permissions, expires_at) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-insert",
      text: `INSERT INTO mbkcore_api_tokens (username, name, token_hash, prefix, permissions, expires_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, $6)
             RETURNING id, name, prefix, permissions, created_at, expires_at`,
      values: [username, name, token_hash, prefix, permissions, expires_at],
    });
    return normalizeToken(rows[0]);
  }

  async findByTokenHash(token_hash) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-find-by-hash",
      text: `SELECT username, permissions, expires_at, last_used
             FROM mbkcore_api_tokens WHERE token_hash = $1`,
      values: [token_hash],
    });
    return rows.map(normalizeToken);
  }

  async updateLastUsedByHash(token_hash) {
    return this.executeRaw({
      name: "api-tokens-touch-by-hash",
      text: 'UPDATE mbkcore_api_tokens SET last_used = NOW() WHERE token_hash = $1',
      values: [token_hash],
    });
  }

  async listAll() {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-all",
      text: `SELECT t.id, t.username, t.name, t.prefix, t.permissions,
                    t.last_used, t.created_at, t.expires_at,
                    u.email, u.role, u.full_name
             FROM mbkcore_api_tokens t
             LEFT JOIN mbkcore_users u ON t.username = u.username
             ORDER BY t.created_at DESC`,
      values: [],
    });
    return rows.map(normalizeToken);
  }

  async stats() {
    const { rows } = await this.executeRaw({
      name: "api-tokens-stats",
      text: `SELECT
               COUNT(*) as total_tokens,
               COUNT(DISTINCT username) as users_with_tokens,
               COUNT(CASE WHEN expires_at IS NULL THEN 1 END) as never_expire,
               COUNT(CASE WHEN expires_at < NOW() THEN 1 END) as expired,
               COUNT(CASE WHEN expires_at >= NOW() THEN 1 END) as active_with_expiry,
               COUNT(CASE WHEN last_used IS NOT NULL THEN 1 END) as used_tokens,
               COUNT(CASE WHEN last_used IS NULL THEN 1 END) as never_used
             FROM mbkcore_api_tokens`,
      values: [],
    });
    return rows[0];
  }

  async listForUserAdmin(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-admin-user",
      text: `SELECT id, name, prefix, permissions, last_used, created_at, expires_at
             FROM mbkcore_api_tokens WHERE username = $1 ORDER BY created_at DESC`,
      values: [username],
    });
    return rows.map(normalizeToken);
  }

  async findInfoById(id) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-find-info",
      text: 'SELECT username, name FROM mbkcore_api_tokens WHERE id = $1',
      values: [id],
    });
    if (!rows[0]) return null;
    return {
      username: rows[0].username,
      name: rows[0].name
    };
  }

  async _purgeDeviceCodes(whereClause, values) {
    await this.db.query("SAVEPOINT purge_device_codes");
    try {
      await this.executeRaw({
        name: "api-tokens-purge-device-codes",
        text: `DELETE FROM "DeviceCodes" WHERE ${whereClause}`,
        values,
      });
    } catch (err) {
      if (!/does not exist|no such table/i.test(String(err?.message || ""))) throw err;
      await this.db.query("ROLLBACK TO SAVEPOINT purge_device_codes").catch(() => {});
    } finally {
      await this.db.query("RELEASE SAVEPOINT purge_device_codes").catch(() => {});
    }
  }

  async deleteById(id) {
    return this.withTransaction(async (txRepo) => {
      await txRepo._purgeDeviceCodes('"apiTokenId" = $1', [id]);
      return txRepo.executeRaw({
        name: "api-tokens-delete-by-id",
        text: 'DELETE FROM mbkcore_api_tokens WHERE id = $1',
        values: [id],
      });
    });
  }

  async deleteByIds(ids) {
    const tokenIds = (Array.isArray(ids) ? ids : [])
      .map((id) => parseInt(id, 10))
      .filter((id) => Number.isInteger(id) && id > 0);
    if (tokenIds.length === 0) return { rows: [], rowCount: 0 };

    return this.withTransaction(async (txRepo) => {
      await txRepo._purgeDeviceCodes('"apiTokenId" = ANY($1)', [tokenIds]);
      return txRepo.executeRaw({
        name: "api-tokens-delete-by-ids",
        text: 'DELETE FROM mbkcore_api_tokens WHERE id = ANY($1)',
        values: [tokenIds],
      });
    });
  }

  async deleteByIdAndUsername(id, username) {
    return this.withTransaction(async (txRepo) => {
      await txRepo._purgeDeviceCodes(
        '"apiTokenId" IN (SELECT id FROM mbkcore_api_tokens WHERE id = $1 AND username = $2)',
        [id, username],
      );
      return txRepo.executeRaw({
        name: "api-tokens-delete-owned",
        text: 'DELETE FROM mbkcore_api_tokens WHERE id = $1 AND username = $2 RETURNING name',
        values: [id, username],
      });
    });
  }

  async deleteAllByUsername(username) {
    return this.withTransaction(async (txRepo) => {
      await txRepo._purgeDeviceCodes(
        '"apiTokenId" IN (SELECT id FROM mbkcore_api_tokens WHERE username = $1)',
        [username],
      );
      return txRepo.executeRaw({
        name: "api-tokens-delete-all-user",
        text: 'DELETE FROM mbkcore_api_tokens WHERE username = $1',
        values: [username],
      });
    });
  }

  async listForUserDetail(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-user-detail",
      text: `SELECT id, name, prefix, last_used, created_at, expires_at, permissions
             FROM mbkcore_api_tokens WHERE username = $1 ORDER BY created_at DESC`,
      values: [username],
    });
    const now = new Date();
    return rows.map((row) => {
      const created = row.created_at ? new Date(row.created_at) : null;
      const expires = row.expires_at ? new Date(row.expires_at) : null;
      const name = row.name;
      const prefix = row.prefix;
      const last_used = row.last_used;
      const perms = parsePermissions(row.permissions);
      return {
        id: row.id,
        name,
        prefix,
        last_used,
        formatted_created: formatDateTime(created),
        formatted_expires: formatDateTime(expires),
        is_active: !expires || expires > now,
        permissions: perms,
        token_permissions: parsePermissionList(perms),
      };
    });
  }
}

export const apiTokenRepository = new ApiTokenRepository();
export default apiTokenRepository;
