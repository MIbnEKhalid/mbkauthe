import { BaseRepository } from "./BaseRepository.js";

const OAUTH_PROVIDERS = {
  github: {
    table: "user_github",
    idColumn: "github_id",
    queryName: "github-login-get-user"
  },
  google: {
    table: "user_google",
    idColumn: "google_id",
    queryName: "google-login-get-user"
  }
};

export class AuthRepository extends BaseRepository {
  buildSessionUserSelect({ includeProfile = false, includeTwoFA = false } = {}) {
    const fields = [
      `s.id as sid`,
      `s.expires_at`,
      `u."UserName"`,
      `u."UserId"`,
      `u."Active"`,
      `u."Role"`,
      `u."AllowedApps"`
    ];

    if (includeProfile) {
      fields.push(`u."FullName"`, `u."Image"`);
    }

    if (includeTwoFA) {
      fields.push(`tfa."TwoFAStatus"`);
    }

    return fields.join(", ");
  }

  resolveOAuthProvider(provider) {
    const key = String(provider || "").toLowerCase();
    const config = OAUTH_PROVIDERS[key];
    if (!config) {
      throw new Error(`Unsupported OAuth provider: ${provider}`);
    }
    return config;
  }

  async fetchActiveSession(sessionId) {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                 FROM "Sessions" s
                 JOIN "Users" u ON s."UserName" = u."UserName"
                 WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: "multi-session-fetch", text: query, values: [sessionId] });
    return result.rows?.[0] || null;
  }

  async deleteAppSessionById(sessionId, queryName = "invalidate-app-session") {
    const query = `DELETE FROM "Sessions" WHERE id = $1`;
    return this.executeRaw({ name: queryName, text: query, values: [sessionId] });
  }

  async deleteSessionBySid(sessionId, queryName = "login-delete-old-session-before-regen") {
    const query = `DELETE FROM "session" WHERE sid = $1`;
    return this.executeRaw({ name: queryName, text: query, values: [sessionId] });
  }

  async getSessionsWithUsersByIds(sessionIds, queryName = "multi-session-fetch-many") {
    if (!Array.isArray(sessionIds) || sessionIds.length === 0) return [];

    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                 FROM "Sessions" s
                 JOIN "Users" u ON s."UserName" = u."UserName"
                 WHERE s.id = ANY($1)`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [sessionIds] });
    return result.rows || [];
  }

  async touchTrustedDevice(deviceTokenHash, username) {
    const query = `
      UPDATE "TrustedDevices" td
      SET "LastUsed" = NOW()
      FROM "Users" u
      WHERE td."DeviceToken" = $1
        AND td."UserName" = $2
        AND td."ExpiresAt" > NOW()
        AND u."UserName" = td."UserName"
        AND u."Active" = TRUE
      RETURNING td."UserName", td."ExpiresAt", u."UserId", u."Active", u."Role", u."AllowedApps"
    `;

    const result = await this.executeRaw({
      name: "check-trusted-device",
      text: query,
      values: [deviceTokenHash, username]
    });
    return result.rows?.[0] || null;
  }

  async cleanupAndCountUserSessions(username, queryName = "cleanup-and-count-user-sessions") {
    const query = `
          WITH deleted AS (
            DELETE FROM "Sessions"
            WHERE "UserName" = $1
              AND expires_at IS NOT NULL
              AND expires_at <= NOW()
          )
          SELECT COUNT(*)::int AS count
          FROM "Sessions"
          WHERE "UserName" = $1
        `;

    const result = await this.executeRaw({ name: queryName, text: query, values: [username] });
    return Number(result.rows?.[0]?.count ?? 0);
  }

  async deleteOldestSessionsForUser(username, limit, queryName = "prune-oldest-user-session") {
    if (!Number.isFinite(limit) || limit <= 0) return 0;
    const query = `DELETE FROM "Sessions" WHERE id IN (SELECT id FROM "Sessions" WHERE "UserName" = $1 ORDER BY created_at ASC LIMIT $2)`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [username, limit] });
    return result.rowCount || 0;
  }

  async deleteExpiredSessionsForUser(username) {
    const query = this.sql`
      DELETE FROM ${this.table("Sessions")}
      WHERE ${this.ident("UserName")} = ${this.value(username)}
        AND ${this.ident("expires_at")} IS NOT NULL
        AND ${this.ident("expires_at")} <= ${this.now()}
    `;

    const result = await this.execute("cleanup-expired-user-sessions", query);
    return result.rowCount || 0;
  }

  async countActiveSessionsForUser(username) {
    const columns = this.columns([`COUNT(*) AS ${this.quoteIdentifier("count")}`]);
    const query = this.sql`
      SELECT ${columns}
      FROM ${this.table("Sessions")}
      WHERE ${this.ident("UserName")} = ${this.value(username)}
    `;
    const result = await this.execute("count-user-sessions", query);
    return Number(result.rows?.[0]?.count ?? 0);
  }

  async getOldestSessionIds(username, limit) {
    if (!Number.isFinite(limit) || limit <= 0) return [];

    const query = this.sql`
      SELECT ${this.column("id")}
      FROM ${this.table("Sessions")}
      WHERE ${this.ident("UserName")} = ${this.value(username)}
      ORDER BY ${this.ident("created_at")} ASC
      ${this.limit(limit)}
    `;

    const result = await this.execute("oldest-user-sessions", query);
    return (result.rows || []).map((row) => row.id).filter(Boolean);
  }

  async insertAppSession(username, expiresAt, meta) {
    const query = `INSERT INTO "Sessions" ("UserName", expires_at, meta) VALUES ($1, $2, $3) RETURNING id`;
    const result = await this.executeRaw({
      name: "insert-app-session",
      text: query,
      values: [username, expiresAt, meta]
    });
    return result.rows?.[0] || null;
  }

  async updateLastLoginReturnProfile(username) {
    const query = `UPDATE "Users" SET "last_login" = NOW() WHERE "UserName" = $1 RETURNING "FullName", "Image"`;
    const result = await this.executeRaw({
      name: "login-update-last-login-return-profile",
      text: query,
      values: [username]
    });
    return result.rows?.[0] || null;
  }

  async getUserProfileByUsername(username, queryName = "login-get-fullname-and-image") {
    const query = `SELECT "FullName", "Image" FROM "Users" WHERE "UserName" = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [username] });
    return result.rows?.[0] || null;
  }

  async insertTrustedDevice({ username, deviceTokenHash, deviceName, userAgent, ipAddress, expiresAt }) {
    const query = `INSERT INTO "TrustedDevices" ("UserName", "DeviceToken", "DeviceName", "UserAgent", "IpAddress", "ExpiresAt") 
                   VALUES ($1, $2, $3, $4, $5, $6)`;
    return this.executeRaw({
      name: "insert-trusted-device",
      text: query,
      values: [username, deviceTokenHash, deviceName, userAgent, ipAddress, expiresAt]
    });
  }

  async getUserWithTwoFA(username, queryName = "login-get-user") {
    const query = `
      SELECT u."UserName", u."UserId", u."PasswordEnc", u."Active", u."Role", u."AllowedApps",
             tfa."TwoFAStatus", u."FullName", u."Image"
      FROM "Users" u
      LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
      WHERE u."UserName" = $1
    `;

    const result = await this.executeRaw({ name: queryName, text: query, values: [username] });
    return result.rows?.[0] || null;
  }

  async getTwoFASecret(username) {
    const query = `SELECT tfa."TwoFASecret" FROM "TwoFA" tfa WHERE tfa."UserName" = $1`;
    const result = await this.executeRaw({ name: "verify-2fa-secret", text: query, values: [username] });
    return result.rows?.[0] || null;
  }

  async deleteSessionsByIds(ids, queryName = "delete-sessions-by-ids") {
    if (!Array.isArray(ids) || ids.length === 0) return 0;
    const query = `DELETE FROM "Sessions" WHERE id = ANY($1)`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [ids] });
    return result.rowCount || 0;
  }

  async getOAuthUserByProviderId(provider, providerId) {
    const { table, idColumn, queryName } = this.resolveOAuthProvider(provider);
    const query = `SELECT ug.*, u."UserName", u."UserId", u."Role", u."Active", u."AllowedApps", tfa."TwoFAStatus"
                   FROM ${table} ug
                   JOIN "Users" u ON ug.user_name = u."UserName"
                   LEFT JOIN "TwoFA" tfa ON u."UserName" = tfa."UserName"
                   WHERE ug.${idColumn} = $1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [providerId] });
    return result.rows?.[0] || null;
  }

  async getApiTokenByHash(tokenHash, queryName = "validate-api-token") {
    const query = `
      SELECT t.id, t."UserName", t."ExpiresAt", t."Permissions",
             u."UserId", u."Active", u."Role", u."AllowedApps" as user_allowed_apps, u."FullName"
      FROM "ApiTokens" t
      JOIN "Users" u ON t."UserName" = u."UserName"
      WHERE t."TokenHash" = $1 LIMIT 1
    `;

    const result = await this.executeRaw({ name: queryName, text: query, values: [tokenHash] });
    return result.rows?.[0] || null;
  }

  async updateApiTokenLastUsed(tokenId, queryName = null, minIntervalMinutes = 15) {
    const query = `
      UPDATE "ApiTokens"
      SET "LastUsed" = NOW()
      WHERE id = $1
        AND (
          "LastUsed" IS NULL
          OR "LastUsed" < NOW() - ($2::int * INTERVAL '1 minute')
        )
    `;
    const values = [tokenId, minIntervalMinutes];
    if (queryName) {
      return this.executeRaw({ name: queryName, text: query, values });
    }
    return this.executeRaw({ text: query, values });
  }

  async getSessionAuthData(sessionId, queryName = "validate-app-session") {
    const query = `
  SELECT s.expires_at, u."Active", u."Role", u."AllowedApps", u."UserName"
  FROM "Sessions" s
  JOIN "Users" u ON s."UserName" = u."UserName"
  WHERE s.id = $1
  LIMIT 1
`;

    const result = await this.executeRaw({ name: queryName, text: query, values: [sessionId] });
    return result.rows?.[0] || null;
  }

  async getSessionWithUserById(sessionId, queryName = "restore-user-session") {
    const query = `SELECT ${this.buildSessionUserSelect({ includeProfile: true })}
                     FROM "Sessions" s
                     JOIN "Users" u ON s."UserName" = u."UserName"
                     WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [sessionId] });
    return result.rows?.[0] || null;
  }

  async getSessionWithUserForReload(sessionId, queryName = "reload-session-user") {
    return this.getSessionWithUserById(sessionId, queryName);
  }

  async getSessionValidationRow(sessionId, queryName = "check-session-validity-by-id") {
    const query = `SELECT s.expires_at, u."Active", u."UserName", u."Role" FROM "Sessions" s JOIN "Users" u ON s."UserName" = u."UserName" WHERE s.id = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [sessionId] });
    return result.rows?.[0] || null;
  }

  async getUserFullNameByUsername(username, queryName = "get-fullname-by-username") {
    const query = `SELECT "FullName" FROM "Users" WHERE "UserName" = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [username] });
    return result.rows?.[0] || null;
  }

  async getUserImageByUsername(username, queryName = "get-user-profile-pic") {
    const query = `SELECT "Image" FROM "Users" WHERE "UserName" = $1 LIMIT 1`;
    const result = await this.executeRaw({ name: queryName, text: query, values: [username] });
    return result.rows?.[0] || null;
  }

  async getSessionValidity(sessionId, sessionStoreSid, queryName = "check-session-validity") {
    const query = `
        SELECT
          s.expires_at,
          u."Active",
          CASE
            WHEN s.expires_at IS NULL THEN (SELECT expire FROM "session" WHERE sid = $2)
            ELSE NULL
          END AS connect_expire
        FROM "Sessions" s
        JOIN "Users" u ON s."UserName" = u."UserName"
        WHERE s.id = $1
        LIMIT 1
      `;

    const result = await this.executeRaw({ name: queryName, text: query, values: [sessionId, sessionStoreSid] });
    return result.rows?.[0] || null;
  }

  async deleteAllAppSessions(queryName = "delete-all-app-sessions") {
    const query = `DELETE FROM "Sessions"`;
    return this.executeRaw({ name: queryName, text: query, values: [] });
  }

  async deleteActiveSessionStoreRows(queryName = "delete-active-session-store-rows") {
    const query = `DELETE FROM "session" WHERE expire > NOW()`;
    return this.executeRaw({ name: queryName, text: query, values: [] });
  }
}