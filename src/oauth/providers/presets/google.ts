/**
 * Google OAuth / OIDC Provider Preset for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OIDCProvider, type OIDCProviderConfig } from "../OIDCProvider.js";
import type { OAuthTokens, OAuthUserProfile } from "../../types.js";

export interface GoogleProviderOptions extends Partial<OIDCProviderConfig> {
  clientId: string;
  clientSecret: string;
  accessType?: "online" | "offline";
  prompt?: string;
}

export function googleProvider(options: GoogleProviderOptions): OIDCProvider {
  return new OIDCProvider({
    id: "google",
    name: "Google",
    issuer: "https://accounts.google.com",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    defaultScopes: options.defaultScopes || ["openid", "profile", "email"],
    profileParser: (raw: any, tokens: OAuthTokens): OAuthUserProfile => {
      return {
        provider: "google",
        id: String(raw.sub || raw.id || ""),
        email: raw.email || null,
        emailVerified: Boolean(raw.email_verified),
        name: raw.name || `${raw.given_name || ""} ${raw.family_name || ""}`.trim() || null,
        username: raw.email ? raw.email.split("@")[0] : null,
        avatarUrl: raw.picture || null,
        raw,
      };
    },
    ...options,
  });
}
