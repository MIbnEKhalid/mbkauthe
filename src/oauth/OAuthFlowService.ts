/**
 * Provider-Neutral OAuth & OIDC Flow Service for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type {
  OAuthFlowBeginOptions,
  OAuthFlowBeginResult,
  OAuthFlowCompleteOptions,
  OAuthFlowCompleteResult,
  OAuthTokens,
  OAuthUserProfile,
  OAuthAccountRecord,
} from "./types.js";
import type {
  OAuthProvider,
  OAuthStateStore,
  OAuthAccountRepository,
  OAuthTokenEncryptor,
} from "./ports.js";
import { defaultOAuthStateStore } from "./state/OAuthStateStore.js";
import { defaultTokenEncryptor } from "./crypto/tokenEncryption.js";
import { oAuthAccountRepository } from "../db/repositories/OAuthAccountRepository.js";
import { authRepository, type AuthRepository } from "../db/repositories/AuthRepository.js";
import { userRepository, type UserRepository } from "../db/repositories/UserRepository.js";
import { emitAuthEvent } from "../core/events/index.js";
import { isUserAuthorizedForApp } from "../http/utils/appAccess.js";

import { loadOAuthProvidersFromConfig } from "./providers/loader.js";

export class OAuthFlowError extends Error {
  public statusCode: number;
  public code: string;
  public profile?: OAuthUserProfile;
  public details?: any;

  constructor(message: string, code: string = "OAUTH_ERROR", statusCode: number = 400, details?: any) {
    super(message);
    this.name = "OAuthFlowError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, OAuthFlowError.prototype);
  }
}

export interface OAuthFlowServiceOptions {
  providers?: OAuthProvider[];
  stateStore?: OAuthStateStore;
  accountRepo?: OAuthAccountRepository;
  userRepo?: UserRepository;
  authRepo?: AuthRepository;
  encryptor?: OAuthTokenEncryptor;
  emitEvent?: typeof emitAuthEvent;
  stateTtlSeconds?: number;
  allowAutoLinkByEmail?: boolean;
  appName?: string;
}

export class OAuthFlowService {
  private providers = new Map<string, OAuthProvider>();
  private stateStore: OAuthStateStore;
  private accountRepo: OAuthAccountRepository;
  private userRepo: UserRepository;
  private authRepo: AuthRepository;
  private encryptor: OAuthTokenEncryptor;
  private emitEvent: typeof emitAuthEvent;
  private stateTtlSeconds: number;
  private allowAutoLinkByEmail: boolean;
  private appName: string;

  constructor(options: OAuthFlowServiceOptions = {}) {
    this.stateStore = options.stateStore || defaultOAuthStateStore;
    this.accountRepo = options.accountRepo || oAuthAccountRepository;
    this.userRepo = options.userRepo || userRepository;
    this.authRepo = options.authRepo || authRepository;
    this.encryptor = options.encryptor || defaultTokenEncryptor;
    this.emitEvent = options.emitEvent || emitAuthEvent;
    this.stateTtlSeconds = options.stateTtlSeconds || 600;
    this.allowAutoLinkByEmail = Boolean(options.allowAutoLinkByEmail);
    this.appName = options.appName || "mbkauthe";

    if (options.providers && options.providers.length > 0) {
      for (const provider of options.providers) {
        this.registerProvider(provider);
      }
    } else {
      const defaultProviders = loadOAuthProvidersFromConfig();
      for (const provider of defaultProviders) {
        this.registerProvider(provider);
      }
    }
  }

  /**
   * Registers a provider instance.
   */
  registerProvider(provider: OAuthProvider): void {
    this.providers.set(provider.id.toLowerCase(), provider);
  }

  /**
   * Checks if a provider is registered.
   */
  hasProvider(providerId: string): boolean {
    const id = providerId.toLowerCase();
    if (!this.providers.has(id)) {
      const freshlyLoaded = loadOAuthProvidersFromConfig();
      for (const p of freshlyLoaded) {
        this.registerProvider(p);
      }
    }
    return this.providers.has(id);
  }

  /**
   * Retrieves a registered provider by its ID.
   */
  getProvider(providerId: string): OAuthProvider {
    const id = providerId.toLowerCase();
    let provider = this.providers.get(id);
    if (!provider) {
      const freshlyLoaded = loadOAuthProvidersFromConfig();
      for (const p of freshlyLoaded) {
        this.registerProvider(p);
      }
      provider = this.providers.get(id);
    }
    if (!provider) {
      throw new OAuthFlowError(
        `OAuth provider '${providerId}' is not configured or enabled.`,
        "PROVIDER_NOT_CONFIGURED",
        400
      );
    }
    return provider;
  }

  /**
   * Returns metadata for all registered providers.
   */
  listProviders(): Array<{ id: string; name: string; isOidc: boolean }> {
    if (this.providers.size === 0) {
      const freshlyLoaded = loadOAuthProvidersFromConfig();
      for (const p of freshlyLoaded) {
        this.registerProvider(p);
      }
    }
    return Array.from(this.providers.values()).map((p) => ({
      id: p.id,
      name: p.name,
      isOidc: p.isOidc,
    }));
  }

  /**
   * Initiates an OAuth authorization flow.
   */
  async begin(providerId: string, options: OAuthFlowBeginOptions): Promise<OAuthFlowBeginResult> {
    const provider = this.getProvider(providerId);

    const pkce = this.stateStore.generatePkce();
    const nonce = provider.isOidc ? this.stateStore.generateNonce() : undefined;

    const state = await this.stateStore.generateState(
      {
        providerId: provider.id,
        redirectUri: options.redirectUri,
        codeVerifier: pkce.codeVerifier,
        nonce,
        returnTo: options.returnTo,
        action: options.action || "login",
        userId: options.userId,
        extra: options.extraParams,
      },
      this.stateTtlSeconds
    );

    const authorizationUrl = await provider.getAuthorizationUrl({
      state,
      redirectUri: options.redirectUri,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: pkce.codeChallengeMethod,
      nonce,
      scopes: options.scopes,
      prompt: options.prompt,
      extraParams: options.extraParams,
    });

    this.emitEvent("oauth.begin", {
      provider: provider.id,
      action: options.action || "login",
      userId: options.userId,
      timestamp: new Date(),
    });

    return {
      authorizationUrl,
      state,
      providerId: provider.id,
    };
  }

  /**
   * Completes an OAuth authorization callback flow.
   */
  async complete(providerId: string, options: OAuthFlowCompleteOptions): Promise<OAuthFlowCompleteResult> {
    const provider = this.getProvider(providerId);

    // 1. Consume and verify state
    const stateData = await this.stateStore.verifyAndConsumeState(options.state);
    if (!stateData) {
      this.emitEvent("oauth.suspicious", {
        provider: provider.id,
        reason: "Invalid, expired, or reused OAuth state parameter",
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      this.emitEvent("oauth.callback.failure", {
        provider: provider.id,
        reason: "Invalid or expired state parameter",
        code: "INVALID_STATE",
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      throw new OAuthFlowError(
        "OAuth security validation failed (state mismatch or expired). Please try again.",
        "INVALID_STATE",
        403
      );
    }

    if (stateData.providerId.toLowerCase() !== provider.id.toLowerCase()) {
      this.emitEvent("oauth.suspicious", {
        provider: provider.id,
        reason: `OAuth state provider mismatch: expected ${stateData.providerId}, got ${provider.id}`,
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      throw new OAuthFlowError(
        "OAuth state mismatch. Please start login again.",
        "STATE_MISMATCH",
        403
      );
    }

    // 2. Exchange authorization code for tokens
    let tokens: OAuthTokens;
    try {
      tokens = await provider.exchangeCode({
        code: options.code,
        redirectUri: stateData.redirectUri || options.redirectUri,
        codeVerifier: stateData.codeVerifier,
        nonce: stateData.nonce,
      });
    } catch (err: any) {
      this.emitEvent("oauth.callback.failure", {
        provider: provider.id,
        reason: `Token exchange failed: ${err.message}`,
        code: "TOKEN_EXCHANGE_ERROR",
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      throw new OAuthFlowError(
        `Failed to exchange authorization code with ${provider.name}: ${err.message}`,
        "TOKEN_EXCHANGE_ERROR",
        400,
        err
      );
    }

    // 3. Fetch normalized user profile
    let profile: OAuthUserProfile;
    try {
      profile = await provider.getUserInfo(tokens);
    } catch (err: any) {
      this.emitEvent("oauth.callback.failure", {
        provider: provider.id,
        reason: `User info retrieval failed: ${err.message}`,
        code: "USERINFO_ERROR",
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      throw new OAuthFlowError(
        `Failed to retrieve user profile from ${provider.name}: ${err.message}`,
        "USERINFO_ERROR",
        400,
        err
      );
    }

    // 4. Handle Account Linking vs Login
    if (stateData.action === "link") {
      if (!stateData.userId) {
        throw new OAuthFlowError("Cannot link OAuth account: missing user ID in session state.", "MISSING_USER_ID", 400);
      }

      const account = await this.link(stateData.userId, provider.id, tokens, profile);
      const user = await this.userRepo.getUserWithTwoFA(String(stateData.userId));

      return {
        success: true,
        action: "link",
        user,
        account,
        profile,
        tokens,
        returnTo: stateData.returnTo,
        isNewUser: false,
      };
    }

    // 5. Login Flow
    let account = await this.accountRepo.findByProvider(provider.id, profile.id);
    let user: any = null;

    if (account) {
      // Existing linked account in new table
      user = await this.userRepo.getUserWithTwoFA(String(account.userId));
      // Update tokens & profile
      await this.accountRepo.update(account.id!, {
        profile,
        encryptedAccessToken: this.encryptor.encrypt(tokens.accessToken),
        encryptedRefreshToken: this.encryptor.encrypt(tokens.refreshToken),
        encryptedIdToken: this.encryptor.encrypt(tokens.idToken),
        tokenExpiresAt: tokens.expiresAt,
        scope: Array.isArray(tokens.scope) ? tokens.scope.join(" ") : tokens.scope,
      });
    } else {
      // Check auto-link by verified email if enabled
      if (this.allowAutoLinkByEmail && profile.email && profile.emailVerified) {
        // Check if a user with this username or email prefix exists
        const usernameCandidate = profile.username || profile.email.split("@")[0];
        const existingUser = await this.userRepo.getUserByUsername(usernameCandidate);
        if (existingUser) {
          user = existingUser;
          account = await this.link(existingUser.username, provider.id, tokens, profile);
        }
      }
    }

    if (!user || !account) {
      this.emitEvent("oauth.callback.failure", {
        provider: provider.id,
        reason: `OAuth account ${profile.id} is not linked to any user in the system`,
        code: `${provider.id.toUpperCase()}_NOT_LINKED`,
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });

      const err = new OAuthFlowError(
        `Your ${provider.name} account is not linked to any user in our system.`,
        `${provider.id.toUpperCase()}_NOT_LINKED`,
        403
      );
      err.profile = profile;
      throw err;
    }

    // 6. Check if user is active
    if (user.is_active === false) {
      this.emitEvent("oauth.callback.failure", {
        provider: provider.id,
        reason: `User ${user.username} is inactive`,
        code: "ACCOUNT_INACTIVE",
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      throw new OAuthFlowError("Your account has been deactivated.", "ACCOUNT_INACTIVE", 403);
    }

    // 7. Check allowed apps
    if (!isUserAuthorizedForApp(user, this.appName)) {
      this.emitEvent("oauth.callback.failure", {
        provider: provider.id,
        reason: `User ${user.username} is not authorized for app ${this.appName}`,
        code: "NOT_AUTHORIZED",
        ip: options.ip,
        userAgent: options.userAgent,
        timestamp: new Date(),
      });
      throw new OAuthFlowError(`You are not authorized to access ${this.appName}.`, "NOT_AUTHORIZED", 403);
    }

    this.emitEvent("oauth.callback.success", {
      provider: provider.id,
      providerUserId: profile.id,
      userId: user.user_id || user.username,
      username: user.username,
      action: "login",
      ip: options.ip,
      userAgent: options.userAgent,
      timestamp: new Date(),
    });

    return {
      success: true,
      action: "login",
      user,
      account,
      profile,
      tokens,
      returnTo: stateData.returnTo,
      isNewUser: false,
    };
  }

  /**
   * Links an OAuth provider account to a user.
   */
  async link(
    userId: string | number,
    providerId: string,
    tokens: OAuthTokens,
    profile: OAuthUserProfile
  ): Promise<OAuthAccountRecord> {
    const provider = this.getProvider(providerId);

    // Check if this provider account is already linked to another user
    const existing = await this.accountRepo.findByProvider(provider.id, profile.id);
    if (existing && String(existing.userId) !== String(userId)) {
      throw new OAuthFlowError(
        `This ${provider.name} account is already linked to another user account.`,
        "ACCOUNT_ALREADY_LINKED",
        409
      );
    }

    let accountRecord: OAuthAccountRecord;

    if (existing) {
      accountRecord = await this.accountRepo.update(existing.id!, {
        profile,
        encryptedAccessToken: this.encryptor.encrypt(tokens.accessToken),
        encryptedRefreshToken: this.encryptor.encrypt(tokens.refreshToken),
        encryptedIdToken: this.encryptor.encrypt(tokens.idToken),
        tokenExpiresAt: tokens.expiresAt,
        scope: Array.isArray(tokens.scope) ? tokens.scope.join(" ") : tokens.scope,
      });
    } else {
      // Check if the user already has a link with this provider
      const userExisting = await this.accountRepo.findByUserAndProvider(userId, provider.id);
      if (userExisting) {
        accountRecord = await this.accountRepo.update(userExisting.id!, {
          providerUserId: profile.id,
          profile,
          encryptedAccessToken: this.encryptor.encrypt(tokens.accessToken),
          encryptedRefreshToken: this.encryptor.encrypt(tokens.refreshToken),
          encryptedIdToken: this.encryptor.encrypt(tokens.idToken),
          tokenExpiresAt: tokens.expiresAt,
          scope: Array.isArray(tokens.scope) ? tokens.scope.join(" ") : tokens.scope,
        });
      } else {
        accountRecord = await this.accountRepo.create({
          userId,
          providerId: provider.id,
          providerUserId: profile.id,
          profile,
          encryptedAccessToken: this.encryptor.encrypt(tokens.accessToken),
          encryptedRefreshToken: this.encryptor.encrypt(tokens.refreshToken),
          encryptedIdToken: this.encryptor.encrypt(tokens.idToken),
          tokenExpiresAt: tokens.expiresAt,
          scope: Array.isArray(tokens.scope) ? tokens.scope.join(" ") : tokens.scope,
        });
      }
    }

    this.emitEvent("oauth.account.linked", {
      provider: provider.id,
      providerUserId: profile.id,
      userId,
      timestamp: new Date(),
    });

    return accountRecord;
  }

  /**
   * Unlinks an OAuth provider from a user.
   */
  async unlink(userId: string | number, providerId: string): Promise<boolean> {
    const provider = this.getProvider(providerId);
    const unlinked = await this.accountRepo.deleteByUserAndProvider(userId, provider.id);

    if (unlinked) {
      this.emitEvent("oauth.account.unlinked", {
        provider: provider.id,
        userId,
        timestamp: new Date(),
      });
    }

    return unlinked;
  }

  /**
   * Lists all linked OAuth accounts for a user.
   */
  async listAccounts(userId: string | number): Promise<OAuthAccountRecord[]> {
    const accounts = await this.accountRepo.findByUserId(userId);
    // Sanitize sensitive tokens before returning to client/caller
    return accounts.map((acc) => ({
      ...acc,
      encryptedAccessToken: undefined,
      encryptedRefreshToken: undefined,
      encryptedIdToken: undefined,
    }));
  }
}

export const oAuthFlowService = new OAuthFlowService();
