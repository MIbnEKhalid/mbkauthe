/**
 * Sign in with Apple OAuth / OIDC Provider Preset for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OIDCProvider, type OIDCProviderConfig } from "../OIDCProvider.js";
import type { OAuthTokens, OAuthUserProfile } from "../../types.js";

export interface AppleProviderOptions extends Partial<OIDCProviderConfig> {
  clientId: string;
  clientSecret: string;
}

export function appleProvider(options: AppleProviderOptions): OIDCProvider {
  return new OIDCProvider({
    id: "apple",
    name: "Apple",
    issuer: "https://appleid.apple.com",
    authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
    tokenEndpoint: "https://appleid.apple.com/auth/token",
    jwksUri: "https://appleid.apple.com/auth/keys",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    defaultScopes: options.defaultScopes || ["openid", "name", "email"],
    profileParser: (raw: any, tokens: OAuthTokens): OAuthUserProfile => {
      return {
        provider: "apple",
        id: String(raw.sub || raw.id || ""),
        email: raw.email || null,
        emailVerified: Boolean(raw.email_verified ?? true),
        name: raw.name ? `${raw.name.firstName || ""} ${raw.name.lastName || ""}`.trim() : null,
        username: raw.email ? raw.email.split("@")[0] : null,
        avatarUrl: null,
        raw,
      };
    },
    ...options,
  });
}
