/**
 * MBKAuthe Dependency Injection Entry Point: createAuth
 * Configures authentication, OAuth providers, and repositories cleanly with zero global state.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OAuthFlowService, type OAuthFlowServiceOptions } from "../oauth/OAuthFlowService.js";
import type { OAuthProvider, OAuthStateStore, OAuthAccountRepository as IOAuthAccountRepository, OAuthTokenEncryptor } from "../oauth/ports.js";
import { MemoryOAuthStateStore } from "../oauth/state/OAuthStateStore.js";
import { AesGcmTokenEncryptor } from "../oauth/crypto/tokenEncryption.js";
import { loadOAuthProvidersFromConfig } from "../oauth/providers/loader.js";
import { OAuthAccountRepository } from "../db/repositories/OAuthAccountRepository.js";
import { UserRepository } from "../db/repositories/UserRepository.js";
import { AuthRepository } from "../db/repositories/AuthRepository.js";
import { SessionRepository } from "../db/repositories/SessionRepository.js";
import { PasskeyRepository } from "../db/repositories/PasskeyRepository.js";
import { ApiTokenRepository } from "../db/repositories/ApiTokenRepository.js";
import { PermissionRepository } from "../db/repositories/PermissionRepository.js";
import { CliAuthSessionRepository } from "../db/repositories/CliAuthSessionRepository.js";
import { createOAuthRouter, type OAuthRouterOptions } from "../express/oauth.router.js";
import type { OAuthProvidersConfig } from "../config/types.js";
import { mbkautheVar } from "../config/index.js";
import type { Router } from "express";

export interface OAuthConfig {
  providers?: OAuthProvider[];
  providersConfig?: OAuthProvidersConfig;
  stateTtlSeconds?: number;
  allowAutoLinkByEmail?: boolean;
  encryptionKey?: string;
  stateStore?: OAuthStateStore;
  accountRepo?: IOAuthAccountRepository;
  tokenEncryptor?: OAuthTokenEncryptor;
}

export interface AuthRepositoriesConfig {
  user?: UserRepository;
  auth?: AuthRepository;
  oauthAccount?: OAuthAccountRepository;
  session?: SessionRepository;
  passkeys?: PasskeyRepository;
  apiToken?: ApiTokenRepository;
  permission?: PermissionRepository;
  cliAuth?: CliAuthSessionRepository;
}

export interface AuthConfig {
  oauth?: OAuthConfig;
  repositories?: AuthRepositoriesConfig;
  appName?: string;
  isDeployed?: boolean;
}

export class MbkAuthInstance {
  public readonly oauth: OAuthFlowService;
  public readonly repositories: {
    user: UserRepository;
    auth: AuthRepository;
    oauthAccount: OAuthAccountRepository;
    session: SessionRepository;
    passkeys: PasskeyRepository;
    apiToken: ApiTokenRepository;
    permission: PermissionRepository;
    cliAuth: CliAuthSessionRepository;
  };
  public readonly appName: string;

  constructor(config: AuthConfig = {}) {
    this.appName = config.appName || "mbkauthe";

    // Setup Repositories
    const repos = config.repositories || {};
    const userRepo = repos.user || new UserRepository();
    const authRepo = repos.auth || new AuthRepository();
    const oauthAccountRepo = repos.oauthAccount || new OAuthAccountRepository();
    const sessionRepo = repos.session || new SessionRepository();
    const passkeyRepo = repos.passkeys || new PasskeyRepository();
    const apiTokenRepo = repos.apiToken || new ApiTokenRepository();
    const permissionRepo = repos.permission || new PermissionRepository();
    const cliAuthRepo = repos.cliAuth || new CliAuthSessionRepository();

    this.repositories = {
      user: userRepo,
      auth: authRepo,
      oauthAccount: oauthAccountRepo,
      session: sessionRepo,
      passkeys: passkeyRepo,
      apiToken: apiTokenRepo,
      permission: permissionRepo,
      cliAuth: cliAuthRepo,
    };

    // Setup OAuth
    const oauthConfig = config.oauth || {};
    const stateStore = oauthConfig.stateStore || new MemoryOAuthStateStore({ defaultTtlSeconds: oauthConfig.stateTtlSeconds || 600 });
    const tokenEncryptor = oauthConfig.tokenEncryptor || (oauthConfig.encryptionKey ? new AesGcmTokenEncryptor(oauthConfig.encryptionKey) : undefined);

    let providers = oauthConfig.providers;
    if (!providers || providers.length === 0) {
      const providersSource = oauthConfig.providersConfig || mbkautheVar.OAUTH_PROVIDERS || mbkautheVar.oauth_providers;
      providers = loadOAuthProvidersFromConfig(providersSource);
    }

    this.oauth = new OAuthFlowService({
      providers: providers || [],
      stateStore,
      accountRepo: (oauthConfig.accountRepo as any) || oauthAccountRepo,
      userRepo,
      authRepo,
      encryptor: tokenEncryptor,
      stateTtlSeconds: oauthConfig.stateTtlSeconds || 600,
      allowAutoLinkByEmail: oauthConfig.allowAutoLinkByEmail,
      appName: this.appName,
    });
  }

  /**
   * Creates an Express router configured with this auth instance's OAuth flow service.
   */
  createOAuthRouter(options: OAuthRouterOptions = {}): Router {
    return createOAuthRouter(this.oauth, options);
  }
}

/**
 * Factory function to create an authentication instance.
 */
export function createAuth(config: AuthConfig = {}): MbkAuthInstance {
  return new MbkAuthInstance(config);
}
