import { BaseRepository } from "./BaseRepository.js";
import { dblogin, dialect } from "#pool.js";

const SESSION_COLUMNS = `"id", "DeviceCodeHash", "UserCodeHash", "ClientName", "ProfileId",
  "UserName", "TokenId", "PendingToken", "Status", "ExpiresAt", "CreatedAt", "ApprovedAt"`;

const PROFILE_COLUMNS = `"id", "ProfileKey", "Name", "Description", "AllowedApps", "Scope", "ExpiresInDays", "Active"`;

export class CliAuthSessionRepository extends BaseRepository {
  constructor(options = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || dialect });
  }

  async create({ deviceCodeHash, userCodeHash, clientName, profileId, expiresAt }) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-create",
      text: `INSERT INTO "CliAuthSessions" ("DeviceCodeHash", "UserCodeHash", "ClientName", "ProfileId", "ExpiresAt")
             VALUES ($1, $2, $3, $4, $5)
             RETURNING ${SESSION_COLUMNS}`,
      values: [deviceCodeHash, userCodeHash, clientName, profileId, expiresAt],
    });
    return rows[0] || null;
  }

  async findByDeviceCodeHash(deviceCodeHash) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-find-by-device",
      text: `SELECT ${SESSION_COLUMNS} FROM "CliAuthSessions" WHERE "DeviceCodeHash" = $1`,
      values: [deviceCodeHash],
    });
    return rows[0] || null;
  }

  async findByUserCodeHash(userCodeHash) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-find-by-user-code",
      text: `SELECT ${SESSION_COLUMNS} FROM "CliAuthSessions" WHERE "UserCodeHash" = $1`,
      values: [userCodeHash],
    });
    return rows[0] || null;
  }

  async markApproved(id, { userName, tokenId, pendingToken }) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-approve",
      text: `UPDATE "CliAuthSessions"
             SET "Status" = 'approved', "UserName" = $2, "TokenId" = $3,
                 "PendingToken" = $4, "ApprovedAt" = NOW()
             WHERE "id" = $1 AND "Status" = 'pending'
             RETURNING "id"`,
      values: [id, userName, tokenId, pendingToken],
    });
    return Boolean(rows[0]);
  }

  async markDenied(id) {
    return this.executeRaw({
      name: "cli-auth-deny",
      text: `UPDATE "CliAuthSessions" SET "Status" = 'denied' WHERE "id" = $1 AND "Status" = 'pending'`,
      values: [id],
    });
  }

  async markExpired(id) {
    return this.executeRaw({
      name: "cli-auth-expire",
      text: `UPDATE "CliAuthSessions" SET "Status" = 'expired' WHERE "id" = $1 AND "Status" = 'pending'`,
      values: [id],
    });
  }

  async expireStale(now = new Date()) {
    return this.executeRaw({
      name: "cli-auth-expire-stale",
      text: `UPDATE "CliAuthSessions" SET "Status" = 'expired'
             WHERE "Status" = 'pending' AND "ExpiresAt" <= $1`,
      values: [now],
    });
  }

  async completeDelivery(id) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-complete-delivery",
      text: `UPDATE "CliAuthSessions" SET "Status" = 'completed', "PendingToken" = NULL
             WHERE "id" = $1 AND "Status" = 'approved'
             RETURNING "id"`,
      values: [id],
    });
    return Boolean(rows[0]);
  }

  async deleteById(id) {
    return this.executeRaw({
      name: "cli-auth-delete",
      text: 'DELETE FROM "CliAuthSessions" WHERE "id" = $1',
      values: [id],
    });
  }

  async getProfileById(profileId) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-profile",
      text: `SELECT ${PROFILE_COLUMNS} FROM "ApiTokenProfiles" WHERE "id" = $1`,
      values: [profileId],
    });
    return rows[0] || null;
  }

  async getActiveProfileById(profileId) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile",
      text: `SELECT ${PROFILE_COLUMNS} FROM "ApiTokenProfiles" WHERE "id" = $1 AND "Active" = TRUE`,
      values: [profileId],
    });
    return rows[0] || null;
  }

  async getActiveProfileByKey(profileKey) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile-by-key",
      text: `SELECT ${PROFILE_COLUMNS} FROM "ApiTokenProfiles" WHERE "ProfileKey" = $1 AND "Active" = TRUE`,
      values: [profileKey],
    });
    return rows[0] || null;
  }
}

export const cliAuthSessionRepository = new CliAuthSessionRepository();
export default cliAuthSessionRepository;
