import { BaseRepository } from "./BaseRepository.js";
import { AuthUser } from "../../core/types/user.types.js";
import { normalizeUserRow } from "./UserRepository.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export class DeviceTrustRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  async touchTrustedDevice(device_token_hash: string, username: string): Promise<AuthUser | null> {
    if (this.dialect.name === "sqlite") {
      const updated = await this.executeRaw({
        name: "check-trusted-device-update",
        text: `UPDATE mbkcore_trusted_devices SET last_used = CURRENT_TIMESTAMP
               WHERE device_token = $1 AND username = $2 AND expires_at > CURRENT_TIMESTAMP
               RETURNING username, expires_at`,
        values: [device_token_hash, username]
      });
      const row = updated.rows?.[0];
      if (!row) return null;

      const userResult = await this.executeRaw({
        name: "check-trusted-device-user",
        text: "SELECT user_id, is_active, role, allowed_apps FROM mbkcore_users WHERE username = $1 AND is_active = 1",
        values: [row.username]
      });
      const userRow = userResult.rows?.[0];
      return userRow ? normalizeUserRow({ ...row, ...userRow }) : null;
    }

    const query = `
      UPDATE mbkcore_trusted_devices td
      SET last_used = NOW()
      FROM mbkcore_users u
      WHERE td.device_token = $1
        AND td.username = $2
        AND td.expires_at > NOW()
        AND u.username = td.username
        AND u.is_active = TRUE
      RETURNING td.username, td.expires_at, u.user_id, u.is_active, u.role, u.allowed_apps
    `;
    const result = await this.executeRaw({ name: "check-trusted-device", text: query, values: [device_token_hash, username] });
    return result.rows?.[0] ? normalizeUserRow(result.rows[0]) : null;
  }

  async insertTrustedDevice({
    username,
    device_token_hash,
    device_name = "Unknown Device",
    user_agent = "Unknown",
    ip_address = "Unknown",
    expires_at,
    query_name = "insert-trusted-device"
  }: {
    username: string;
    device_token_hash: string;
    device_name?: string;
    user_agent?: string;
    ip_address?: string;
    expires_at: Date;
    query_name?: string;
  }) {
    const query = `
      INSERT INTO mbkcore_trusted_devices (username, device_token, device_name, user_agent, ip_address, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `;
    return this.executeRaw({
      name: query_name,
      text: query,
      values: [username, device_token_hash, device_name, user_agent, ip_address, expires_at]
    });
  }
}

export const deviceTrustRepository = new DeviceTrustRepository();
