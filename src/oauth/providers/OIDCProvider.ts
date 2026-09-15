/**
 * Discovery-Driven OpenID Connect (OIDC) Provider for MBKAuthe
 * Uses `jose` for JWKS fetching and cryptographic ID token validation.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import * as jose from "jose";
import type {
  OAuthAuthorizationUrlOptions,
  OAuthTokenExchangeOptions,
  OAuthTokens,
  OAuthUserProfile,
} from "../types.js";
import { OAuth2Provider, type OAuth2ProviderConfig } from "./OAuth2Provider.js";
import { OAuthHttpClient, defaultOAuthHttpClient } from "../http/OAuthHttpClient.js";

export interface OIDCProviderConfig {
  id: string;
  name: string;
  clientId: string;
  clientSecret: string;
  /** Issuer URL (e.g. "https://accounts.google.com" or "https://login.microsoftonline.com/{tenant}/v2.0") */
  issuer?: string;
  /** Explicit authorization endpoint if not using discovery */
  authorizationEndpoint?: string;
  /** Explicit token endpoint if not using discovery */
  tokenEndpoint?: string;
  /** Explicit userinfo endpoint if not using discovery */
  userinfoEndpoint?: string;
  /** Explicit jwks_uri if not using discovery */
  jwksUri?: string;
  defaultScopes?: string[];
  tokenAuthMethod?: "client_secret_post" | "client_secret_basic";
  usePkce?: boolean;
  httpClient?: OAuthHttpClient;
  profileParser?: (raw: any, tokens: OAuthTokens) => Promise<OAuthUserProfile> | OAuthUserProfile;
  headers?: Record<string, string>;
  /** Optional custom JWKS key store or mock resolver for testing */
  jwksKeySet?: jose.JWTVerifyGetKey;
}

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  response_types_supported?: string[];
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  [key: string]: any;
}

export class OIDCProvider extends OAuth2Provider {
  public override readonly isOidc: boolean = true;
  protected issuer?: string;
  protected jwksUri?: string;
  protected jwksKeySet?: jose.JWTVerifyGetKey;
  protected discoveryPromise: Promise<OIDCDiscoveryDocument> | null = null;
  protected discoveryData: OIDCDiscoveryDocument | null = null;

  constructor(config: OIDCProviderConfig) {
    super({
      id: config.id,
      name: config.name,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      authorizationEndpoint: config.authorizationEndpoint || "",
      tokenEndpoint: config.tokenEndpoint || "",
      userinfoEndpoint: config.userinfoEndpoint,
      defaultScopes: config.defaultScopes && config.defaultScopes.length > 0 ? config.defaultScopes : ["openid", "profile", "email"],
      tokenAuthMethod: config.tokenAuthMethod || "client_secret_post",
      usePkce: config.usePkce !== undefined ? config.usePkce : true,
      httpClient: config.httpClient || defaultOAuthHttpClient,
      profileParser: config.profileParser,
      headers: config.headers,
    });

    this.issuer = config.issuer ? config.issuer.replace(/\/+$/, "") : undefined;
    this.jwksUri = config.jwksUri;
    this.jwksKeySet = config.jwksKeySet;

    // Ensure openid scope is present
    if (!this.defaultScopes.includes("openid")) {
      this.defaultScopes.unshift("openid");
    }
  }

  /**
   * Fetches and caches the OIDC discovery document (/.well-known/openid-configuration).
   */
  async discover(): Promise<OIDCDiscoveryDocument> {
    if (this.discoveryData) {
      return this.discoveryData;
    }

    if (this.discoveryPromise) {
      return this.discoveryPromise;
    }

    if (!this.issuer) {
      if (this.authorizationEndpoint && this.tokenEndpoint && this.jwksUri) {
        this.discoveryData = {
          issuer: "",
          authorization_endpoint: this.authorizationEndpoint,
          token_endpoint: this.tokenEndpoint,
          userinfo_endpoint: this.userinfoEndpoint,
          jwks_uri: this.jwksUri,
        };
        return this.discoveryData;
      }
      throw new Error(`OIDC Provider '${this.name}' requires either an 'issuer' or explicit endpoints.`);
    }

    const discoveryUrl = `${this.issuer}/.well-known/openid-configuration`;

    this.discoveryPromise = (async () => {
      try {
        const doc = await this.httpClient.get<OIDCDiscoveryDocument>(discoveryUrl);
        this.discoveryData = doc;
        if (!this.authorizationEndpoint) this.authorizationEndpoint = doc.authorization_endpoint;
        if (!this.tokenEndpoint) this.tokenEndpoint = doc.token_endpoint;
        if (!this.userinfoEndpoint) this.userinfoEndpoint = doc.userinfo_endpoint;
        if (!this.jwksUri) this.jwksUri = doc.jwks_uri;
        return doc;
      } catch (err: any) {
        this.discoveryPromise = null;
        throw new Error(`Failed to load OIDC discovery document for '${this.name}' at ${discoveryUrl}: ${err.message}`);
      }
    })();

    return this.discoveryPromise;
  }

  /**
   * Initializes endpoints before generating authorization URL.
   */
  override async getAuthorizationUrl(options: OAuthAuthorizationUrlOptions): Promise<string> {
    if (!this.authorizationEndpoint) {
      await this.discover();
    }
    return super.getAuthorizationUrl(options);
  }

  /**
   * Exchanges code for tokens and cryptographically validates the ID token using `jose`.
   */
  override async exchangeCode(options: OAuthTokenExchangeOptions): Promise<OAuthTokens> {
    if (!this.tokenEndpoint || !this.jwksUri) {
      await this.discover();
    }

    const tokens = await super.exchangeCode(options);

    if (tokens.idToken) {
      const claims = await this.verifyIdToken(tokens.idToken, options.nonce);
      tokens.raw = { ...tokens.raw, idTokenClaims: claims };
    }

    return tokens;
  }

  /**
   * Cryptographically verifies the OIDC ID Token using JWKS.
   * Checks signature, issuer, audience, expiration, and nonce.
   */
  async verifyIdToken(idToken: string, expectedNonce?: string): Promise<jose.JWTPayload> {
    if (!this.jwksUri && !this.jwksKeySet) {
      await this.discover();
    }

    let keySet = this.jwksKeySet;
    if (!keySet) {
      if (!this.jwksUri) {
        throw new Error(`Cannot verify ID token: jwks_uri is missing for provider '${this.name}'`);
      }
      keySet = jose.createRemoteJWKSet(new URL(this.jwksUri));
      this.jwksKeySet = keySet;
    }

    const verifyOptions: jose.JWTVerifyOptions = {
      audience: this.clientId,
    };

    if (this.issuer) {
      verifyOptions.issuer = [this.issuer, `${this.issuer}/`];
    }

    try {
      const { payload } = await jose.jwtVerify(idToken, keySet, verifyOptions);

      if (expectedNonce && payload.nonce !== expectedNonce) {
        throw new Error(`ID token nonce mismatch. Expected '${expectedNonce}', received '${payload.nonce}'`);
      }

      return payload;
    } catch (err: any) {
      throw new Error(`ID Token validation failed for '${this.name}': ${err.message}`);
    }
  }

  /**
   * Normalized user profile from ID token claims or userinfo.
   */
  override async getUserInfo(tokens: OAuthTokens): Promise<OAuthUserProfile> {
    const claims = tokens.raw?.idTokenClaims;

    let profileData: any = claims;

    // If claims are incomplete or userinfo is available, fetch userinfo
    if (this.userinfoEndpoint && (!claims || !claims.email || !claims.name)) {
      try {
        const userinfo = await super.getUserInfo(tokens);
        profileData = { ...claims, ...userinfo.raw };
      } catch {
        // Fall back to claims
      }
    }

    if (!profileData) {
      if (this.userinfoEndpoint) {
        const userinfo = await super.getUserInfo(tokens);
        profileData = userinfo.raw;
      } else {
        throw new Error(`Unable to determine user profile: No ID token claims or userinfo for '${this.name}'`);
      }
    }

    if (this.profileParser) {
      return this.profileParser(profileData, tokens);
    }

    return {
      provider: this.id,
      id: String(profileData.sub || profileData.id || profileData.user_id || ""),
      email: profileData.email || null,
      emailVerified: Boolean(profileData.email_verified ?? false),
      name: profileData.name || profileData.given_name || null,
      username: profileData.preferred_username || profileData.nickname || profileData.name || null,
      avatarUrl: profileData.picture || profileData.avatar_url || null,
      raw: profileData,
    };
  }
}
