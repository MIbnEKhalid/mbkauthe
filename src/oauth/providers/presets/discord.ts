/**
 * Discord OAuth Provider Preset for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OAuth2Provider, type OAuth2ProviderConfig } from "../OAuth2Provider.js";
import type { OAuthTokens, OAuthUserProfile } from "../../types.js";

export interface DiscordProviderOptions extends Partial<OAuth2ProviderConfig> {
  clientId: string;
  clientSecret: string;
}

export function discordProvider(options: DiscordProviderOptions): OAuth2Provider {
  return new OAuth2Provider({
    id: "discord",
    name: "Discord",
    authorizationEndpoint: "https://discord.com/api/oauth2/authorize",
    tokenEndpoint: "https://discord.com/api/oauth2/token",
    userinfoEndpoint: "https://discord.com/api/users/@me",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    defaultScopes: options.defaultScopes || ["identify", "email"],
    tokenAuthMethod: "client_secret_post",
    profileParser: (raw: any, tokens: OAuthTokens): OAuthUserProfile => {
      const avatarUrl = raw.avatar
        ? `https://cdn.discordapp.com/avatars/${raw.id}/${raw.avatar}.png`
        : null;

      return {
        provider: "discord",
        id: String(raw.id),
        email: raw.email || null,
        emailVerified: Boolean(raw.verified),
        name: raw.global_name || raw.username || null,
        username: raw.username || null,
        avatarUrl,
        raw,
      };
    },
    ...options,
  });
}
