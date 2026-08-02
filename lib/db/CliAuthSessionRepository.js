// CliAuthSessionRepository — one-time device-authorization sessions backing
// the browser-based CLI login flow (RFC 8628-style device flow).
//
// MBKAuthe owns the "CliAuthSessions" table. It also performs a read-only
// lookup into the MBKCore-owned "ApiTokenProfiles" table during token
// issuance — MBKCore manages profiles, MBKAuthe only consumes them.
//
// State machine: pending -> approved -> completed
//                          \-> denied
//                          \-> expired
//   - pending   : awaiting browser approval
//   - approved  : user approved; a raw token is held in "PendingToken" awaiting
//                 delivery to exactly one poller
//   - completed : the token has been handed to the CLI (PendingToken cleared)
//   - denied    : user rejected the request
//   - expired   : the 15-minute window elapsed before approval

import { BaseRepository } from "./BaseRepository.js";
import { dblogin, dialect } from "#pool.js";

const SESSION_COLUMNS = `"id", "DeviceCodeHash", "UserCodeHash", "ClientName", "ProfileId",
  "UserName", "TokenId", "PendingToken", "Status", "ExpiresAt", "CreatedAt", "ApprovedAt"`;

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

  /**
   * Approve a pending session and stage the raw token for delivery.
   * Returns true only if this call transitioned the row (pending -> approved),
   * which guarantees a session can never be approved twice.
   */
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
    return rows[0] ? true : false;
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

  /** Opportunistically expire any stale pending sessions. */
  async expireStale(now = new Date()) {
    return this.executeRaw({
      name: "cli-auth-expire-stale",
      text: `UPDATE "CliAuthSessions" SET "Status" = 'expired'
             WHERE "Status" = 'pending' AND "ExpiresAt" <= $1`,
      values: [now],
    });
  }

  /**
   * Atomically hand delivery to exactly one poller (approved -> completed) and
   * clear the staged token. Returns true only for the poller that won the race;
   * the token itself is read from the row fetched by findByDeviceCodeHash so it
   * is never delivered twice.
   */
  async completeDelivery(id) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-complete-delivery",
      text: `UPDATE "CliAuthSessions" SET "Status" = 'completed', "PendingToken" = NULL
             WHERE "id" = $1 AND "Status" = 'approved'
             RETURNING "id"`,
      values: [id],
    });
    return rows[0] ? true : false;
  }

  async deleteById(id) {
    return this.executeRaw({
      name: "cli-auth-delete",
      text: 'DELETE FROM "CliAuthSessions" WHERE "id" = $1',
      values: [id],
    });
  }

  // --- API Token Profile lookups (MBKCore-owned table, read-only) ---

  /** Fetch any profile by id (used to render the approval page). */
  async getProfileById(profileId) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-profile",
      text: `SELECT "id", "ProfileKey", "Name", "Description", "AllowedApps", "Scope", "ExpiresInDays", "Active"
             FROM "ApiTokenProfiles" WHERE "id" = $1`,
      values: [profileId],
    });
    return rows[0] || null;
  }

  /** Fetch an active profile by id (used to issue tokens). */
  async getActiveProfileById(profileId) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile",
      text: `SELECT "id", "ProfileKey", "Name", "Description", "AllowedApps", "Scope", "ExpiresInDays", "Active"
             FROM "ApiTokenProfiles" WHERE "id" = $1 AND "Active" = TRUE`,
      values: [profileId],
    });
    return rows[0] || null;
  }

  /** Fetch an active profile by its public ProfileKey (used to issue tokens). */
  async getActiveProfileByKey(profileKey) {
    const { rows } = await this.executeRaw({
      name: "cli-auth-get-active-profile-by-key",
      text: `SELECT "id", "ProfileKey", "Name", "Description", "AllowedApps", "Scope", "ExpiresInDays", "Active"
             FROM "ApiTokenProfiles" WHERE "ProfileKey" = $1 AND "Active" = TRUE`,
      values: [profileKey],
    });
    return rows[0] || null;
  }
}

export const cliAuthSessionRepository = new CliAuthSessionRepository();
export default cliAuthSessionRepository;
