/**
 * OAuth Accounts Database Repository for MBKAuthe
 * Supports both PostgreSQL and SQLite via BaseRepository.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { BaseRepository, type BaseRepositoryOptions } from "./BaseRepository.js";
import type { OAuthAccountRecord } from "../../oauth/types.js";
import type { OAuthAccountRepository as IOAuthAccountRepository } from "../../oauth/ports.js";
import { dblogin, dialect } from "../pool.js";

const OAUTH_ACCOUNT_COLUMNS = `id, user_id, provider_id, provider_user_id, profile,
  access_token, refresh_token, id_token, token_expires_at, scope, created_at, updated_at`;

export class OAuthAccountRepository
  extends BaseRepository<OAuthAccountRecord>
  implements IOAuthAccountRepository
{
  public static readonly TABLE_NAME = "mbkcore_oauth_accounts";

  constructor(options: BaseRepositoryOptions = {}) {
    super({
      ...options,
      db: options.db || dblogin,
      dialect: options.dialect || dialect,
      defaultTable: OAuthAccountRepository.TABLE_NAME,
    });
  }

  private mapRow(row: any): OAuthAccountRecord | null {
    if (!row) return null;

    let profile = row.profile;
    if (typeof profile === "string") {
      try {
        profile = JSON.parse(profile);
      } catch {
        profile = {};
      }
    }

    return {
      id: row.id,
      userId: row.user_id,
      providerId: row.provider_id,
      providerUserId: row.provider_user_id,
      profile: profile || {},
      encryptedAccessToken: row.access_token || null,
      encryptedRefreshToken: row.refresh_token || null,
      encryptedIdToken: row.id_token || null,
      tokenExpiresAt: row.token_expires_at ? new Date(row.token_expires_at) : null,
      scope: row.scope || null,
      createdAt: row.created_at ? new Date(row.created_at) : new Date(),
      updatedAt: row.updated_at ? new Date(row.updated_at) : new Date(),
    };
  }

  /**
   * Finds an OAuth account by provider and provider's unique user ID.
   */
  async findByProvider(providerId: string, providerUserId: string): Promise<OAuthAccountRecord | null> {
    const text = `
      SELECT ${OAUTH_ACCOUNT_COLUMNS} FROM mbkcore_oauth_accounts
      WHERE provider_id = $1 AND provider_user_id = $2
      LIMIT 1
    `;
    const res = await this.executeRaw({
      name: "oauth-account-find-by-provider",
      text,
      values: [providerId.toLowerCase(), String(providerUserId)],
    });
    return this.mapRow(res.rows?.[0]);
  }

  /**
   * Finds all OAuth accounts linked to a user ID.
   */
  async findByUserId(userId: string | number): Promise<OAuthAccountRecord[]> {
    const text = `
      SELECT ${OAUTH_ACCOUNT_COLUMNS} FROM mbkcore_oauth_accounts
      WHERE user_id = $1
      ORDER BY created_at ASC
    `;
    const res = await this.executeRaw({
      name: "oauth-account-find-by-user",
      text,
      values: [String(userId)],
    });
    return (res.rows || []).map((row: any) => this.mapRow(row)!).filter(Boolean);
  }

  /**
   * Finds an OAuth account linked to a specific user and provider.
   */
  async findByUserAndProvider(userId: string | number, providerId: string): Promise<OAuthAccountRecord | null> {
    const text = `
      SELECT ${OAUTH_ACCOUNT_COLUMNS} FROM mbkcore_oauth_accounts
      WHERE user_id = $1 AND provider_id = $2
      LIMIT 1
    `;
    const res = await this.executeRaw({
      name: "oauth-account-find-by-user-provider",
      text,
      values: [String(userId), providerId.toLowerCase()],
    });
    return this.mapRow(res.rows?.[0]);
  }

  /**
   * Creates a new OAuth account record.
   */
  async create(account: Omit<OAuthAccountRecord, "id" | "createdAt" | "updatedAt">): Promise<OAuthAccountRecord> {
    const profileJson = typeof account.profile === "object" ? JSON.stringify(account.profile) : account.profile || "{}";

    const text = `
      INSERT INTO mbkcore_oauth_accounts (
        user_id, provider_id, provider_user_id, profile,
        access_token, refresh_token, id_token, token_expires_at, scope
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING ${OAUTH_ACCOUNT_COLUMNS}
    `;

    const values = [
      String(account.userId),
      account.providerId.toLowerCase(),
      String(account.providerUserId),
      profileJson,
      account.encryptedAccessToken || null,
      account.encryptedRefreshToken || null,
      account.encryptedIdToken || null,
      account.tokenExpiresAt ? account.tokenExpiresAt.toISOString() : null,
      account.scope || null,
    ];

    const res = await this.executeRaw({
      name: "oauth-account-create",
      text,
      values,
    });

    return this.mapRow(res.rows?.[0])!;
  }

  /**
   * Updates an existing OAuth account record.
   */
  async update(id: string | number, account: Partial<OAuthAccountRecord>): Promise<OAuthAccountRecord> {
    const sets: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (account.profile !== undefined) {
      sets.push(`profile = $${paramIndex++}`);
      values.push(typeof account.profile === "object" ? JSON.stringify(account.profile) : account.profile);
    }
    if (account.encryptedAccessToken !== undefined) {
      sets.push(`access_token = $${paramIndex++}`);
      values.push(account.encryptedAccessToken);
    }
    if (account.encryptedRefreshToken !== undefined) {
      sets.push(`refresh_token = $${paramIndex++}`);
      values.push(account.encryptedRefreshToken);
    }
    if (account.encryptedIdToken !== undefined) {
      sets.push(`id_token = $${paramIndex++}`);
      values.push(account.encryptedIdToken);
    }
    if (account.tokenExpiresAt !== undefined) {
      sets.push(`token_expires_at = $${paramIndex++}`);
      values.push(account.tokenExpiresAt ? account.tokenExpiresAt.toISOString() : null);
    }
    if (account.scope !== undefined) {
      sets.push(`scope = $${paramIndex++}`);
      values.push(account.scope);
    }

    sets.push(`updated_at = CURRENT_TIMESTAMP`);

    values.push(id);
    const idParam = `$${paramIndex}`;

    const text = `
      UPDATE mbkcore_oauth_accounts
      SET ${sets.join(", ")}
      WHERE id = ${idParam}
      RETURNING ${OAUTH_ACCOUNT_COLUMNS}
    `;

    const res = await this.executeRaw({
      name: "oauth-account-update",
      text,
      values,
    });

    return this.mapRow(res.rows?.[0])!;
  }

  /**
   * Deletes an OAuth account record by its ID.
   */
  async delete(id: string | number): Promise<boolean> {
    const text = `DELETE FROM mbkcore_oauth_accounts WHERE id = $1`;
    const res = await this.executeRaw({
      name: "oauth-account-delete",
      text,
      values: [id],
    });
    return (res.rowCount || 0) > 0;
  }

  /**
   * Deletes an OAuth account by user ID and provider.
   */
  async deleteByUserAndProvider(userId: string | number, providerId: string): Promise<boolean> {
    const text = `DELETE FROM mbkcore_oauth_accounts WHERE user_id = $1 AND provider_id = $2`;
    const res = await this.executeRaw({
      name: "oauth-account-delete-by-user-provider",
      text,
      values: [String(userId), providerId.toLowerCase()],
    });
    return (res.rowCount || 0) > 0;
  }
}

export const oAuthAccountRepository = new OAuthAccountRepository({ db: dblogin });
