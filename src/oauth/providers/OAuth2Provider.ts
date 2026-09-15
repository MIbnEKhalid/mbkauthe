/**
 * Framework-Agnostic OAuth 2.0 Base Provider for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type {
  OAuthAuthorizationUrlOptions,
  OAuthTokenExchangeOptions,
  OAuthTokens,
  OAuthUserProfile,
} from "../types.js";
import type { OAuthProvider } from "../ports.js";
import { OAuthHttpClient, defaultOAuthHttpClient } from "../http/OAuthHttpClient.js";

export interface OAuth2ProviderConfig {
  id: string;
  name: string;
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
  defaultScopes?: string[];
  tokenAuthMethod?: "client_secret_post" | "client_secret_basic";
  usePkce?: boolean;
  httpClient?: OAuthHttpClient;
  profileParser?: (raw: any, tokens: OAuthTokens) => Promise<OAuthUserProfile> | OAuthUserProfile;
  headers?: Record<string, string>;
}

export class OAuth2Provider implements OAuthProvider {
  public readonly id: string;
  public readonly name: string;
  public readonly isOidc: boolean = false;

  protected clientId: string;
  protected clientSecret: string;
  protected authorizationEndpoint: string;
  protected tokenEndpoint: string;
  protected userinfoEndpoint?: string;
  protected defaultScopes: string[];
  protected tokenAuthMethod: "client_secret_post" | "client_secret_basic";
  protected usePkce: boolean;
  protected httpClient: OAuthHttpClient;
  protected profileParser?: (raw: any, tokens: OAuthTokens) => Promise<OAuthUserProfile> | OAuthUserProfile;
  protected customHeaders: Record<string, string>;

  constructor(config: OAuth2ProviderConfig) {
    this.id = config.id.toLowerCase();
    this.name = config.name;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.authorizationEndpoint = config.authorizationEndpoint;
    this.tokenEndpoint = config.tokenEndpoint;
    this.userinfoEndpoint = config.userinfoEndpoint;
    this.defaultScopes = config.defaultScopes || [];
    this.tokenAuthMethod = config.tokenAuthMethod || "client_secret_post";
    this.usePkce = config.usePkce !== undefined ? config.usePkce : true;
    this.httpClient = config.httpClient || defaultOAuthHttpClient;
    this.profileParser = config.profileParser;
    this.customHeaders = config.headers || {};
  }

  /**
   * Builds the authorization URL for initiating the OAuth flow.
   */
  getAuthorizationUrl(options: OAuthAuthorizationUrlOptions): Promise<string> | string {
    const url = new URL(this.authorizationEndpoint);

    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", options.redirectUri);
    url.searchParams.set("state", options.state);

    const scopes = options.scopes || this.defaultScopes;
    if (scopes.length > 0) {
      url.searchParams.set("scope", scopes.join(" "));
    }

    if (this.usePkce && options.codeChallenge) {
      url.searchParams.set("code_challenge", options.codeChallenge);
      url.searchParams.set("code_challenge_method", options.codeChallengeMethod || "S256");
    }

    if (options.nonce) {
      url.searchParams.set("nonce", options.nonce);
    }

    if (options.prompt) {
      url.searchParams.set("prompt", options.prompt);
    }

    if (options.extraParams) {
      for (const [key, value] of Object.entries(options.extraParams)) {
        url.searchParams.set(key, value);
      }
    }

    return url.toString();
  }

  /**
   * Exchanges an authorization code for access tokens.
   */
  async exchangeCode(options: OAuthTokenExchangeOptions): Promise<OAuthTokens> {
    const form: Record<string, string | undefined> = {
      grant_type: "authorization_code",
      code: options.code,
      redirect_uri: options.redirectUri,
    };

    if (options.codeVerifier) {
      form.code_verifier = options.codeVerifier;
    }

    if (options.extraParams) {
      Object.assign(form, options.extraParams);
    }

    const headers: Record<string, string> = {
      ...this.customHeaders,
    };

    if (this.tokenAuthMethod === "client_secret_basic") {
      const credentials = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      headers["Authorization"] = `Basic ${credentials}`;
    } else {
      form.client_id = this.clientId;
      form.client_secret = this.clientSecret;
    }

    const data = await this.httpClient.post(this.tokenEndpoint, {
      form,
      headers,
    });

    const expiresIn = data.expires_in ? Number(data.expires_in) : undefined;
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : undefined;

    return {
      accessToken: data.access_token,
      tokenType: data.token_type || "Bearer",
      idToken: data.id_token,
      refreshToken: data.refresh_token,
      expiresIn,
      expiresAt,
      scope: data.scope,
      raw: data,
    };
  }

  /**
   * Retrieves and normalizes user profile from userinfo endpoint.
   */
  async getUserInfo(tokens: OAuthTokens): Promise<OAuthUserProfile> {
    if (!this.userinfoEndpoint) {
      throw new Error(`Provider '${this.name}' does not have a configured userinfo endpoint.`);
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${tokens.accessToken}`,
      ...this.customHeaders,
    };

    const raw = await this.httpClient.get(this.userinfoEndpoint, { headers });

    if (this.profileParser) {
      return this.profileParser(raw, tokens);
    }

    return {
      provider: this.id,
      id: String(raw.id || raw.sub || raw.user_id || ""),
      email: raw.email || null,
      emailVerified: Boolean(raw.email_verified ?? raw.verified ?? false),
      name: raw.name || raw.display_name || null,
      username: raw.login || raw.username || raw.preferred_username || null,
      avatarUrl: raw.avatar_url || raw.picture || null,
      raw,
    };
  }

  /**
   * Refreshes an expired access token using a refresh token.
   */
  async refreshToken(refreshToken: string): Promise<OAuthTokens> {
    const form: Record<string, string | undefined> = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    };

    const headers: Record<string, string> = {
      ...this.customHeaders,
    };

    if (this.tokenAuthMethod === "client_secret_basic") {
      const credentials = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      headers["Authorization"] = `Basic ${credentials}`;
    } else {
      form.client_id = this.clientId;
      form.client_secret = this.clientSecret;
    }

    const data = await this.httpClient.post(this.tokenEndpoint, {
      form,
      headers,
    });

    const expiresIn = data.expires_in ? Number(data.expires_in) : undefined;
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : undefined;

    return {
      accessToken: data.access_token,
      tokenType: data.token_type || "Bearer",
      idToken: data.id_token,
      refreshToken: data.refresh_token || refreshToken,
      expiresIn,
      expiresAt,
      scope: data.scope,
      raw: data,
    };
  }
}
