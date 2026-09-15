import { AuthRepository, authRepository } from "../db/repositories/AuthRepository.js";
import { OAuthAccountRepository, oAuthAccountRepository } from "../db/repositories/OAuthAccountRepository.js";
import { UserRepository, userRepository } from "../db/repositories/UserRepository.js";
import { mbkautheVar } from "../config/index.js";
import { isUserAuthorizedForApp } from "../http/utils/appAccess.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { createLogger } from "../utils/logger.js";
import { emitAuthEvent } from "../core/events/index.js";
import { loadOAuthProvidersFromConfig } from "../oauth/providers/loader.js";
import type { OAuthTokens, OAuthUserProfile, OAuthAccountRecord } from "../oauth/types.js";

const debug = createLogger("mbkauthe:oauth-service");

export interface OAuthUserData {
  user_id?: number | string;
  username: string;
  role: string;
  allowed_apps?: any;
  is_enabled?: boolean;
  full_name?: string;
  image?: string;
  [key: string]: any;
}

export class OAuthService {
  constructor(
    private authRepo: AuthRepository = authRepository,
    private oauthAccountRepo: OAuthAccountRepository = oAuthAccountRepository,
    private userRepo: UserRepository = userRepository
  ) {}

  /**
   * Validates OAuth user against system database.
   * Strictly checks if an account link exists in mbkcore_oauth_accounts.
   * If not linked, throws a descriptive NOT_LINKED error.
   */
  async validateOAuthProfile(provider: string, profileId: string, emailOrUser?: string): Promise<OAuthUserData> {
    const providerId = provider.toLowerCase().trim();
    debug("Validating OAuth profile for provider %s, id: %s", providerId, profileId);

    const account = await this.oauthAccountRepo.findByProvider(providerId, profileId);

    if (!account) {
      debug("OAuth profile not linked for %s (id: %s)", providerId, profileId);
      const error: any = new Error(`Your ${provider} account is not linked to any user in our system.`);
      error.code = `${providerId.toUpperCase()}_NOT_LINKED`;
      error.statusCode = 403;
      throw error;
    }

    const user = await this.userRepo.getUserWithTwoFA(String(account.userId));

    if (!user) {
      debug("Linked user %s not found in system", account.userId);
      const error: any = new Error(`User account linked to this ${provider} profile was not found.`);
      error.code = "USER_NOT_FOUND";
      error.statusCode = 403;
      throw error;
    }

    if (user.is_active === false) {
      debug("OAuth user %s is inactive", user.username);
      const error: any = new Error("Account is inactive");
      error.code = "ACCOUNT_INACTIVE";
      error.statusCode = 403;
      throw error;
    }

    if (!isUserAuthorizedForApp(user, mbkautheVar.APP_NAME)) {
      debug("OAuth user %s is not authorized for app %s", user.username, mbkautheVar.APP_NAME);
      const error: any = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
      error.code = "NOT_AUTHORIZED";
      error.statusCode = 403;
      throw error;
    }

    return {
      user_id: user.user_id,
      username: user.username,
      role: user.role,
      allowed_apps: user.allowed_apps,
      is_enabled: Boolean(user.is_enabled),
      full_name: user.full_name,
      image: user.image,
      provider: providerId,
      provider_user_id: profileId,
    };
  }

  /**
   * Returns list of enabled OAuth providers based on environment configuration
   */
  getEnabledProviders(): string[] {
    const providers = loadOAuthProvidersFromConfig(mbkautheVar.OAUTH_PROVIDERS || mbkautheVar.oauth_providers);
    return providers.map((p) => p.name || p.id);
  }

  /**
   * Retrieves all linked OAuth accounts for a user.
   */
  async getLinkedAccounts(userId: string | number): Promise<OAuthAccountRecord[]> {
    return this.oauthAccountRepo.findByUserId(userId);
  }

  /**
   * Checks if a user has a specific provider linked.
   */
  async isProviderLinked(userId: string | number, providerId: string): Promise<boolean> {
    const account = await this.oauthAccountRepo.findByUserAndProvider(userId, providerId.toLowerCase());
    return Boolean(account);
  }

  /**
   * Gets linked account details for a user and provider.
   */
  async getLinkedAccount(userId: string | number, providerId: string): Promise<OAuthAccountRecord | null> {
    return this.oauthAccountRepo.findByUserAndProvider(userId, providerId.toLowerCase());
  }

  /**
   * Unlinks an OAuth provider from a user.
   */
  async unlinkAccount(userId: string | number, providerId: string): Promise<boolean> {
    return this.oauthAccountRepo.deleteByUserAndProvider(userId, providerId.toLowerCase());
  }
}

export const oAuthService = new OAuthService();
