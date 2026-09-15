/**
 * GitHub OAuth Provider Preset for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OAuth2Provider, type OAuth2ProviderConfig } from "../OAuth2Provider.js";
import type { OAuthTokens, OAuthUserProfile } from "../../types.js";
import { defaultOAuthHttpClient } from "../../http/OAuthHttpClient.js";

export interface GitHubProviderOptions extends Partial<OAuth2ProviderConfig> {
  clientId: string;
  clientSecret: string;
  allowSignup?: boolean;
}

export function githubProvider(options: GitHubProviderOptions): OAuth2Provider {
  const httpClient = options.httpClient || defaultOAuthHttpClient;

  return new OAuth2Provider({
    id: "github",
    name: "GitHub",
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userinfoEndpoint: "https://api.github.com/user",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    defaultScopes: options.defaultScopes || ["read:user", "user:email"],
    tokenAuthMethod: "client_secret_post",
    headers: {
      "User-Agent": "MBKAuthe-OAuth",
      Accept: "application/vnd.github+json",
      ...(options.headers || {}),
    },
    profileParser: async (raw: any, tokens: OAuthTokens): Promise<OAuthUserProfile> => {
      let email = raw.email || null;
      let emailVerified = false;

      // If email is private or not present in /user, fetch from /user/emails
      if (!email && tokens.accessToken) {
        try {
          const emails = await httpClient.get<Array<{ email: string; primary: boolean; verified: boolean }>>(
            "https://api.github.com/user/emails",
            {
              headers: {
                Authorization: `Bearer ${tokens.accessToken}`,
                "User-Agent": "MBKAuthe-OAuth",
                Accept: "application/vnd.github+json",
              },
            }
          );

          if (Array.isArray(emails)) {
            const primary = emails.find((e) => e.primary) || emails[0];
            if (primary) {
              email = primary.email;
              emailVerified = Boolean(primary.verified);
            }
          }
        } catch {
          // Gracefully fallback
        }
      } else if (email) {
        emailVerified = true;
      }

      return {
        provider: "github",
        id: String(raw.id),
        email,
        emailVerified,
        name: raw.name || raw.login || null,
        username: raw.login || null,
        avatarUrl: raw.avatar_url || null,
        raw,
      };
    },
    ...options,
  });
}
