/**
 * Provider-Neutral OAuth & OIDC Ports / Interfaces for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type {
  OAuthAuthorizationUrlOptions,
  OAuthTokenExchangeOptions,
  OAuthTokens,
  OAuthUserProfile,
  OAuthStateData,
  OAuthAccountRecord,
} from "./types.js";

/**
 * Interface implemented by all OAuth 2.0 and OIDC providers.
 * Completely framework-agnostic with no Express or Passport dependencies.
 */
export interface OAuthProvider {
  /** Unique provider identifier (e.g., "google", "github", "microsoft", "discord", "apple", "custom-oidc") */
  readonly id: string;
  /** Human-readable provider name (e.g., "Google", "GitHub") */
  readonly name: string;
  /** Indicates whether this provider is OpenID Connect compliant */
  readonly isOidc: boolean;

  /**
   * Generates the authorization URL to redirect the user to.
   */
  getAuthorizationUrl(options: OAuthAuthorizationUrlOptions): Promise<string> | string;

  /**
   * Exchanges an authorization code for access tokens (and ID token if OIDC).
   */
  exchangeCode(options: OAuthTokenExchangeOptions): Promise<OAuthTokens>;

  /**
   * Fetches and normalizes the user profile from the provider.
   */
  getUserInfo(tokens: OAuthTokens): Promise<OAuthUserProfile>;

  /**
   * Optional: Refreshes an expired access token using a refresh token.
   */
  refreshToken?(refreshToken: string): Promise<OAuthTokens>;

  /**
   * Optional: Revokes a given access or refresh token.
   */
  revokeToken?(token: string, tokenTypeHint?: "access_token" | "refresh_token"): Promise<void>;
}

/**
 * State and PKCE store interface for securing the OAuth lifecycle.
 */
export interface OAuthStateStore {
  /**
   * Generates a secure random state, stores the state data, and returns the state string.
   */
  generateState(data: Omit<OAuthStateData, "state" | "createdAt" | "expiresAt">, ttlSeconds?: number): Promise<string>;

  /**
   * Retrieves and consumes (one-time use) the state data. Returns null if expired or invalid.
   */
  verifyAndConsumeState(state: string): Promise<OAuthStateData | null>;

  /**
   * Generates PKCE code_verifier and S256 code_challenge.
   */
  generatePkce(): { codeVerifier: string; codeChallenge: string; codeChallengeMethod: "S256" };

  /**
   * Generates a cryptographic nonce for OIDC.
   */
  generateNonce(): string;
}

/**
 * Repository interface for OAuth account persistence.
 */
export interface OAuthAccountRepository {
  /**
   * Finds an OAuth account by provider ID and the provider's unique user ID.
   */
  findByProvider(providerId: string, providerUserId: string): Promise<OAuthAccountRecord | null>;

  /**
   * Finds all OAuth accounts linked to a specific user.
   */
  findByUserId(userId: string | number): Promise<OAuthAccountRecord[]>;

  /**
   * Finds an OAuth account linked to a specific user and provider.
   */
  findByUserAndProvider(userId: string | number, providerId: string): Promise<OAuthAccountRecord | null>;

  /**
   * Creates a new OAuth account record.
   */
  create(account: Omit<OAuthAccountRecord, "id" | "createdAt" | "updatedAt">): Promise<OAuthAccountRecord>;

  /**
   * Updates an existing OAuth account record.
   */
  update(id: string | number, account: Partial<OAuthAccountRecord>): Promise<OAuthAccountRecord>;

  /**
   * Deletes an OAuth account record by its primary key ID.
   */
  delete(id: string | number): Promise<boolean>;

  /**
   * Deletes an OAuth account linked to a specific user and provider.
   */
  deleteByUserAndProvider(userId: string | number, providerId: string): Promise<boolean>;
}

/**
 * Encryptor for securing sensitive tokens (access_token, refresh_token) at rest.
 */
export interface OAuthTokenEncryptor {
  encrypt(plainText?: string | null): string | null;
  decrypt(cipherText?: string | null): string | null;
}
