/**
 * Provider-Neutral OAuth & OIDC Types for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

export interface OAuthUserProfile {
  /** The provider identifier (e.g. "google", "github", "microsoft", "discord", "apple", "custom-oidc") */
  provider: string;
  /** Unique user identifier within the provider (e.g. "sub" or "id") */
  id: string;
  /** Normalized email address if available */
  email: string | null;
  /** Whether the email was verified by the provider */
  emailVerified: boolean;
  /** Full display name if available */
  name: string | null;
  /** Preferred username or handle if available */
  username: string | null;
  /** Profile picture or avatar URL if available */
  avatarUrl: string | null;
  /** Full raw claims or profile object returned by the provider */
  raw: Record<string, any>;
}

export interface OAuthTokens {
  accessToken: string;
  tokenType?: string;
  idToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt?: Date;
  scope?: string | string[];
  raw?: Record<string, any>;
}

export interface OAuthAuthorizationUrlOptions {
  state: string;
  redirectUri: string;
  codeChallenge?: string;
  codeChallengeMethod?: "S256" | "plain";
  nonce?: string;
  scopes?: string[];
  prompt?: string;
  extraParams?: Record<string, string>;
}

export interface OAuthTokenExchangeOptions {
  code: string;
  redirectUri: string;
  codeVerifier?: string;
  nonce?: string;
  extraParams?: Record<string, string>;
}

export interface OAuthStateData {
  state: string;
  providerId: string;
  redirectUri: string;
  codeVerifier?: string;
  nonce?: string;
  returnTo?: string;
  action?: "login" | "link";
  userId?: string | number;
  createdAt: number;
  expiresAt: number;
  extra?: Record<string, any>;
}

export interface OAuthAccountRecord {
  id?: number | string;
  userId: string | number;
  providerId: string;
  providerUserId: string;
  profile: OAuthUserProfile;
  encryptedAccessToken?: string | null;
  encryptedRefreshToken?: string | null;
  encryptedIdToken?: string | null;
  tokenExpiresAt?: Date | null;
  scope?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface OAuthFlowBeginOptions {
  redirectUri: string;
  returnTo?: string;
  action?: "login" | "link";
  userId?: string | number;
  scopes?: string[];
  prompt?: string;
  extraParams?: Record<string, string>;
}

export interface OAuthFlowBeginResult {
  authorizationUrl: string;
  state: string;
  providerId: string;
}

export interface OAuthFlowCompleteOptions {
  code: string;
  state: string;
  redirectUri: string;
  ip?: string;
  userAgent?: string;
}

export interface OAuthFlowCompleteResult {
  success: boolean;
  action: "login" | "link";
  user: any;
  account: OAuthAccountRecord;
  profile: OAuthUserProfile;
  tokens: OAuthTokens;
  returnTo?: string;
  isNewUser?: boolean;
}
