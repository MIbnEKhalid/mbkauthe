import { BaseRepository } from "./BaseRepository.js";
import { dblogin, dialect } from "#pool.js";

function parsePermissions(value) {
  if (value && typeof value === "object") return value;
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch {}
  }
  return {};
}

const withScope = (row) => {
  const perms = parsePermissions(row?.Permissions);
  return { ...row, Scope: perms.scope || "read-only", AllowedApps: perms.allowedApps ?? null };
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
      text: `SELECT "id", "Name", "Prefix", "Permissions", "LastUsed", "CreatedAt", "ExpiresAt"
             FROM "ApiTokens" WHERE "UserName" = $1 ORDER BY "CreatedAt" DESC`,
      values: [username],
    });
    return rows.map(withScope);
  }

  async countForUser(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-count-for-user",
      text: 'SELECT COUNT(*) as token_count FROM "ApiTokens" WHERE "UserName" = $1',
      values: [username],
    });
    return parseInt(rows[0]?.token_count ?? 0, 10);
  }

  async insert(username, name, tokenHash, prefix, permissions, expiresAt) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-insert",
      text: `INSERT INTO "ApiTokens" ("UserName", "Name", "TokenHash", "Prefix", "Permissions", "ExpiresAt")
             VALUES ($1, $2, $3, $4, $5::jsonb, $6)
             RETURNING "id", "Name", "Prefix", "Permissions", "CreatedAt", "ExpiresAt"`,
      values: [username, name, tokenHash, prefix, permissions, expiresAt],
    });
    return withScope(rows[0]);
  }

  async findByTokenHash(tokenHash) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-find-by-hash",
      text: `SELECT "UserName", "Permissions", "ExpiresAt", "LastUsed"
             FROM "ApiTokens" WHERE "TokenHash" = $1`,
      values: [tokenHash],
    });
    return rows.map(withScope);
  }

  async updateLastUsedByHash(tokenHash) {
    return this.executeRaw({
      name: "api-tokens-touch-by-hash",
      text: 'UPDATE "ApiTokens" SET "LastUsed" = NOW() WHERE "TokenHash" = $1',
      values: [tokenHash],
    });
  }

  async listAll() {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-all",
      text: `SELECT t."id", t."UserName", t."Name", t."Prefix", t."Permissions",
                    t."LastUsed", t."CreatedAt", t."ExpiresAt",
                    u."email", u."Role", u."FullName"
             FROM "ApiTokens" t
             LEFT JOIN "Users" u ON t."UserName" = u."UserName"
             ORDER BY t."CreatedAt" DESC`,
      values: [],
    });
    return rows.map(withScope);
  }

  async stats() {
    const { rows } = await this.executeRaw({
      name: "api-tokens-stats",
      text: `SELECT
               COUNT(*) as total_tokens,
               COUNT(DISTINCT "UserName") as users_with_tokens,
               COUNT(CASE WHEN "ExpiresAt" IS NULL THEN 1 END) as never_expire,
               COUNT(CASE WHEN "ExpiresAt" < NOW() THEN 1 END) as expired,
               COUNT(CASE WHEN "ExpiresAt" >= NOW() THEN 1 END) as active_with_expiry,
               COUNT(CASE WHEN "LastUsed" IS NOT NULL THEN 1 END) as used_tokens,
               COUNT(CASE WHEN "LastUsed" IS NULL THEN 1 END) as never_used
             FROM "ApiTokens"`,
      values: [],
    });
    return rows[0];
  }

  async listForUserAdmin(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-admin-user",
      text: `SELECT "id", "Name", "Prefix", "Permissions", "LastUsed", "CreatedAt", "ExpiresAt"
             FROM "ApiTokens" WHERE "UserName" = $1 ORDER BY "CreatedAt" DESC`,
      values: [username],
    });
    return rows.map(withScope);
  }

  async findInfoById(id) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-find-info",
      text: 'SELECT "UserName", "Name" FROM "ApiTokens" WHERE "id" = $1',
      values: [id],
    });
    return rows[0] || null;
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
        text: 'DELETE FROM "ApiTokens" WHERE "id" = $1',
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
        text: 'DELETE FROM "ApiTokens" WHERE "id" = ANY($1)',
        values: [tokenIds],
      });
    });
  }

  async deleteByIdAndUsername(id, username) {
    return this.withTransaction(async (txRepo) => {
      await txRepo._purgeDeviceCodes(
        '"apiTokenId" IN (SELECT "id" FROM "ApiTokens" WHERE "id" = $1 AND "UserName" = $2)',
        [id, username],
      );
      return txRepo.executeRaw({
        name: "api-tokens-delete-owned",
        text: 'DELETE FROM "ApiTokens" WHERE "id" = $1 AND "UserName" = $2 RETURNING "Name"',
        values: [id, username],
      });
    });
  }

  async deleteAllByUsername(username) {
    return this.withTransaction(async (txRepo) => {
      await txRepo._purgeDeviceCodes(
        '"apiTokenId" IN (SELECT "id" FROM "ApiTokens" WHERE "UserName" = $1)',
        [username],
      );
      return txRepo.executeRaw({
        name: "api-tokens-delete-all-user",
        text: 'DELETE FROM "ApiTokens" WHERE "UserName" = $1',
        values: [username],
      });
    });
  }

  async listForUserDetail(username) {
    const { rows } = await this.executeRaw({
      name: "api-tokens-list-user-detail",
      text: `SELECT "id", "Name", "Prefix", "LastUsed", "CreatedAt", "ExpiresAt", "Permissions"
             FROM "ApiTokens" WHERE "UserName" = $1 ORDER BY "CreatedAt" DESC`,
      values: [username],
    });
    const now = new Date();
    return rows.map((row) => {
      const created = row.CreatedAt ? new Date(row.CreatedAt) : null;
      const expires = row.ExpiresAt ? new Date(row.ExpiresAt) : null;
      return {
        id: row.id,
        Name: row.Name,
        Prefix: row.Prefix,
        LastUsed: row.LastUsed,
        formatted_created: formatDateTime(created),
        formatted_expires: formatDateTime(expires),
        is_active: !expires || expires > now,
        Permissions: parsePermissions(row.Permissions),
      };
    });
  }
}

export const apiTokenRepository = new ApiTokenRepository();
export default apiTokenRepository;
