import { AuthRepository, authRepository } from "../db/repositories/AuthRepository.js";
import { mbkautheVar } from "../config/index.js";
import { isUserAuthorizedForApp } from "../http/utils/appAccess.js";
import { MbkAuthError } from "../core/errors/MbkAuthError.js";
import { ErrorCodes } from "../core/errors/catalog.js";
import { createLogger } from "../utils/logger.js";
import { emitAuthEvent } from "../core/events/index.js";

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
  constructor(private authRepo: AuthRepository = authRepository) {}

  /**
   * Validates OAuth user against system database
   */
  async validateOAuthProfile(provider: string, profileId: string, emailOrUser?: string): Promise<OAuthUserData> {
    debug("Validating OAuth profile for provider %s, id: %s", provider, profileId);

    const user = await this.authRepo.getOAuthUserByProviderId(provider.toLowerCase(), profileId);

    if (!user) {
      debug("OAuth profile not linked for %s (id: %s)", provider, profileId);
      const error: any = new Error(`${provider} account not linked to any user`);
      error.code = `${provider.toUpperCase()}_NOT_LINKED`;
      throw error;
    }

    if (user.is_active === false) {
      debug("OAuth user %s is inactive", user.username);
      const error: any = new Error("Account is inactive");
      error.code = "ACCOUNT_INACTIVE";
      throw error;
    }

    if (!isUserAuthorizedForApp(user, mbkautheVar.APP_NAME)) {
      debug("OAuth user %s is not authorized for app %s", user.username, mbkautheVar.APP_NAME);
      const error: any = new Error(`Not authorized to use ${mbkautheVar.APP_NAME}`);
      error.code = "NOT_AUTHORIZED";
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
      ...(provider.toLowerCase() === "github"
        ? { github_id: user.github_id, github_username: user.github_username }
        : { google_id: user.google_id, google_email: user.google_email }),
    };
  }

  /**
   * Returns list of enabled OAuth providers based on environment configuration
   */
  getEnabledProviders(): string[] {
    const providers: string[] = [];
    const githubClientId = mbkautheVar.GITHUB_APP_CLIENT_ID || mbkautheVar.GITHUB_CLIENT_ID;
    const githubClientSecret = mbkautheVar.GITHUB_APP_CLIENT_SECRET || mbkautheVar.GITHUB_CLIENT_SECRET;

    if (String(mbkautheVar.GITHUB_LOGIN_ENABLED || "").toLowerCase() === "true" && githubClientId && githubClientSecret) {
      providers.push("GitHub App");
    }

    if (String(mbkautheVar.GOOGLE_LOGIN_ENABLED || "").toLowerCase() === "true" && mbkautheVar.GOOGLE_CLIENT_ID && mbkautheVar.GOOGLE_CLIENT_SECRET) {
      providers.push("Google");
    }

    return providers;
  }
}

export const oAuthService = new OAuthService();
