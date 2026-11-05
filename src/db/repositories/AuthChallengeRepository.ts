import { BaseRepository } from "./BaseRepository.js";
import { dblogin, dialect as defaultDialect } from "../pool.js";

export type ChallengeType = "reset_link" | "otp_code" | "admin_otp";

export interface AuthChallengeRow {
  id: number;
  username: string;
  challenge_type: ChallengeType;
  token_hash: string;
  expires_at: string | Date;
  attempts: number;
  max_attempts: number;
  last_attempt_at: string | Date | null;
  consumed_at: string | Date | null;
  created_at: string | Date;
}

export interface CreateChallengeParams {
  username: string;
  challenge_type: ChallengeType;
  token_hash: string;
  expires_at: Date | string;
  max_attempts?: number;
}

export class AuthChallengeRepository extends BaseRepository {
  constructor(options: any = {}) {
    super({ db: options.db || dblogin, dialect: options.dialect || defaultDialect });
  }

  async createChallenge(params: CreateChallengeParams): Promise<AuthChallengeRow> {
    const { username, challenge_type, token_hash, expires_at, max_attempts = 5 } = params;
    const expiresFormatted = expires_at instanceof Date ? expires_at.toISOString() : expires_at;

    // Invalidate existing active unconsumed challenges of same type for user
    await this.clearChallengesForUser(username, challenge_type);

    const query = `
      INSERT INTO mbkcore_auth_challenges (username, challenge_type, token_hash, expires_at, attempts, max_attempts)
      VALUES ($1, $2, $3, $4, 0, $5)
    `;
    await this.executeRaw({
      name: "create-auth-challenge",
      text: query,
      values: [username, challenge_type, token_hash, expiresFormatted, max_attempts],
    });

    const active = await this.findActiveChallenge(username, challenge_type);
    if (!active) {
      throw new Error("Failed to create auth challenge record");
    }
    return active;
  }

  async findActiveChallenge(username: string, challenge_type?: string): Promise<AuthChallengeRow | null> {
    const query = challenge_type
      ? `SELECT * FROM mbkcore_auth_challenges
         WHERE username = $1 AND challenge_type = $2 AND consumed_at IS NULL
         ORDER BY id DESC LIMIT 1`
      : `SELECT * FROM mbkcore_auth_challenges
         WHERE username = $1 AND consumed_at IS NULL
         ORDER BY id DESC LIMIT 1`;

    const values = challenge_type ? [username, challenge_type] : [username];
    const result = await this.executeRaw({
      name: "find-active-challenge",
      text: query,
      values,
    });
    return (result.rows?.[0] as AuthChallengeRow) || null;
  }

  async findChallengeByHash(token_hash: string): Promise<AuthChallengeRow | null> {
    const query = `
      SELECT * FROM mbkcore_auth_challenges
      WHERE token_hash = $1 AND consumed_at IS NULL
      ORDER BY id DESC LIMIT 1
    `;
    const result = await this.executeRaw({
      name: "find-challenge-by-hash",
      text: query,
      values: [token_hash],
    });
    return (result.rows?.[0] as AuthChallengeRow) || null;
  }

  async incrementAttempts(id: number): Promise<void> {
    const query = this.dialect.name === "sqlite"
      ? `UPDATE mbkcore_auth_challenges
         SET attempts = attempts + 1, last_attempt_at = CURRENT_TIMESTAMP
         WHERE id = $1`
      : `UPDATE mbkcore_auth_challenges
         SET attempts = attempts + 1, last_attempt_at = NOW()
         WHERE id = $1`;

    await this.executeRaw({
      name: "increment-challenge-attempts",
      text: query,
      values: [id],
    });
  }

  async markConsumed(id: number): Promise<void> {
    const query = this.dialect.name === "sqlite"
      ? `UPDATE mbkcore_auth_challenges SET consumed_at = CURRENT_TIMESTAMP WHERE id = $1`
      : `UPDATE mbkcore_auth_challenges SET consumed_at = NOW() WHERE id = $1`;

    await this.executeRaw({
      name: "mark-challenge-consumed",
      text: query,
      values: [id],
    });
  }

  async clearChallengesForUser(username: string, challenge_type?: string): Promise<void> {
    const query = challenge_type
      ? `DELETE FROM mbkcore_auth_challenges WHERE username = $1 AND challenge_type = $2`
      : `DELETE FROM mbkcore_auth_challenges WHERE username = $1`;

    const values = challenge_type ? [username, challenge_type] : [username];
    await this.executeRaw({
      name: "clear-user-challenges",
      text: query,
      values,
    });
  }

  async getRecentAttemptCount(username: string, windowMinutes: number = 60): Promise<number> {
    const cutoff = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();
    const query = `
      SELECT COUNT(*) as count FROM mbkcore_auth_challenges
      WHERE username = $1 AND created_at >= $2
    `;
    const result = await this.executeRaw({
      name: "get-recent-challenge-count",
      text: query,
      values: [username, cutoff],
    });
    return Number(result.rows?.[0]?.count || 0);
  }
}

export const authChallengeRepository = new AuthChallengeRepository();

