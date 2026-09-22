import { ApiTokenRepository, apiTokenRepository } from "../db/repositories/ApiTokenRepository.js";
import { AuthRepository, authRepository } from "../db/repositories/AuthRepository.js";
import { TokenEngine } from "../core/tokens/TokenEngine.js";
import { emitAuthEvent } from "../core/events/index.js";
import { validateCreateApiTokenDto, CreateApiTokenDto } from "../core/validation/authDto.js";
import { ApiTokenRecord, ApiTokenStats } from "../core/types/token.types.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { createLogger } from "../utils/logger.js";

const debug = createLogger("mbkauthe:api-token-service");

export interface CreateTokenResult {
  token: string;
  tokenRecord: ApiTokenRecord;
}

export interface CreateTokenOptions {
  userRole?: string;
  maxTokensPerUser?: number;
}

export interface VerifyTokenResult {
  valid: boolean;
  username: string;
  permissions: string[];
}

export class ApiTokenService {
  constructor(
    private tokenRepo: ApiTokenRepository = apiTokenRepository,
    private authRepo: AuthRepository = authRepository
  ) {}

  /**
   * Generates and stores a new API Personal Access Token
   */
  async createToken(
    username: string,
    dto: CreateApiTokenDto,
    options?: CreateTokenOptions
  ): Promise<CreateTokenResult> {
    const validated = validateCreateApiTokenDto(dto);
    const { name, scopes, expiresInDays } = validated;

    if (!username) {
      throw new MbkAuthError(ErrorCodes.SESSION_NOT_FOUND, 401, "User is required to create API token");
    }

    if (options?.userRole !== "superadmin") {
      const limit = options?.maxTokensPerUser ?? 10;
      const tokenCount = await this.tokenRepo.countForUser(username);
      if (tokenCount >= limit) {
        throw new MbkAuthError(ErrorCodes.INSUFFICIENT_PERMISSIONS, 403, `Token limit reached (max ${limit}).`);
      }
    }

    const rawToken = TokenEngine.createApiToken();
    const tokenHash = TokenEngine.hashToken(rawToken);
    if (!tokenHash) {
      throw new MbkAuthError(ErrorCodes.INTERNAL_SERVER_ERROR, 500, "Failed to hash token");
    }

    const prefix = "mbk_pat_";
    const expiresAt = expiresInDays && expiresInDays > 0 ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) : null;

    const permissions = { permissions: scopes };

    const tokenRecord = await this.tokenRepo.insert(
      username,
      name,
      tokenHash,
      prefix,
      permissions,
      expiresAt
    );

    if (!tokenRecord) {
      throw new MbkAuthError(ErrorCodes.DATABASE_ERROR, 500, "Failed to persist API token");
    }

    debug("Created API token %s for user %s", tokenRecord.id, username);

    emitAuthEvent("auth:token:created", {
      tokenId: tokenRecord.id,
      userId: username,
      name,
      scopes,
      expiresAt,
    });

    return {
      token: rawToken,
      tokenRecord,
    };
  }

  /**
   * Validates a raw API token and updates its last_used timestamp.
   * Returns token user & permissions or throws MbkAuthError.
   */
  async verifyToken(rawToken: string): Promise<VerifyTokenResult> {
    if (!rawToken || typeof rawToken !== "string") {
      throw new MbkAuthError(ErrorCodes.INVALID_TOKEN_FORMAT, 401, "No token provided");
    }

    const tokenHash = TokenEngine.hashToken(rawToken);
    if (!tokenHash) {
      throw new MbkAuthError(ErrorCodes.INVALID_TOKEN_FORMAT, 401, "Invalid token");
    }

    const rows = await this.tokenRepo.findByTokenHash(tokenHash);
    if (!rows || rows.length === 0) {
      throw new MbkAuthError(ErrorCodes.INVALID_AUTH_TOKEN, 401, "Invalid token");
    }

    const tokenData = rows[0];
    if (tokenData.expires_at && new Date(tokenData.expires_at) < new Date()) {
      throw new MbkAuthError(ErrorCodes.API_TOKEN_EXPIRED, 401, "Token expired");
    }

    // Touch last used asynchronously
    this.tokenRepo.updateLastUsedByHash(tokenHash).catch((err) => {
      debug("Failed to touch token last_used: %s", err?.message || err);
    });

    const permissions = Array.isArray(tokenData.permissions)
      ? tokenData.permissions
      : (tokenData.permissions as any)?.permissions || [];

    return {
      valid: true,
      username: tokenData.username,
      permissions,
    };
  }

  /**
   * Lists all tokens for a user with display details
   */
  async listUserTokens(username: string): Promise<ApiTokenRecord[]> {
    if (!username) return [];
    return this.tokenRepo.listForUserDetail(username);
  }

  /**
   * Revokes a single token owned by a user
   */
  async revokeToken(id: string | number, username: string): Promise<boolean> {
    const result = await this.tokenRepo.deleteByIdAndUsername(id, username);
    const deleted = (result.rowCount || 0) > 0 || (Array.isArray(result.rows) && result.rows.length > 0);
    if (deleted) {
      debug("Revoked API token %s for user %s", id, username);
      emitAuthEvent("auth:token:revoked", {
        tokenId: id,
        userId: username,
      });
    }
    return Boolean(deleted);
  }

  /**
   * Revokes all tokens owned by a user
   */
  async revokeAllUserTokens(username: string): Promise<number> {
    const result = await this.tokenRepo.deleteAllByUsername(username);
    const count = result.rowCount || 0;
    debug("Revoked all %d API tokens for user %s", count, username);
    return count;
  }

  /**
   * Authenticates a raw API token and updates its last_used timestamp
   */
  async authenticateRawToken(rawToken: string): Promise<any | null> {
    if (!rawToken) return null;
    const tokenHash = TokenEngine.hashToken(rawToken);
    if (!tokenHash) return null;

    const tokenUser = await this.authRepo.getApiTokenByHash(tokenHash);
    if (!tokenUser) return null;

    if (tokenUser.expires_at) {
      const expires = new Date(tokenUser.expires_at);
      if (expires <= new Date()) {
        debug("API token expired at %s", tokenUser.expires_at);
        return null;
      }
    }

    if (tokenUser.is_active === false) {
      debug("API token user %s is inactive", tokenUser.username);
      return null;
    }

    // Touch last used asynchronously
    this.authRepo.updateApiTokenLastUsed(tokenUser.id).catch((err) => {
      debug("Failed to update token last_used: %s", err?.message || err);
    });

    return tokenUser;
  }

  /**
   * Admin: List all tokens
   */
  async listAllTokens(): Promise<ApiTokenRecord[]> {
    return this.tokenRepo.listAll();
  }

  /**
   * Admin: List tokens for a specific user
   */
  async listTokensForUserAdmin(username: string): Promise<ApiTokenRecord[]> {
    if (!username) return [];
    return this.tokenRepo.listForUserAdmin(username);
  }

  /**
   * Admin: Bulk revoke tokens by ID and emit revocation audit events
   */
  async bulkRevokeTokens(ids: Array<string | number>): Promise<number> {
    const validIds = (Array.isArray(ids) ? ids : [])
      .map((id) => parseInt(String(id), 10))
      .filter((id) => Number.isInteger(id) && id > 0);

    if (validIds.length === 0) return 0;

    // Retrieve usernames for audit before deletion
    const usernames = await Promise.all(
      validIds.map(async (id) => {
        const info = await this.tokenRepo.findInfoById(id);
        return { id, username: info?.username };
      })
    );

    const result = await this.tokenRepo.deleteByIds(validIds);
    const count = result.rowCount || 0;

    for (const { id, username } of usernames) {
      if (username) {
        emitAuthEvent("auth:token:revoked", {
          tokenId: id,
          userId: username,
        });
      }
    }

    return count;
  }

  /**
   * Admin: Token statistics
   */
  async getTokenStats(): Promise<ApiTokenStats> {
    return this.tokenRepo.stats();
  }

  /**
   * Admin: Delete token by ID
   */
  async adminDeleteToken(id: string | number): Promise<boolean> {
    const info = await this.tokenRepo.findInfoById(id);
    const result = await this.tokenRepo.deleteById(id);
    const deleted = (result.rowCount || 0) > 0 || (Array.isArray(result.rows) && result.rows.length > 0);
    if (deleted && info) {
      emitAuthEvent("auth:token:revoked", {
        tokenId: id,
        userId: info.username,
      });
    }
    return Boolean(deleted);
  }
}

export const apiTokenService = new ApiTokenService();
