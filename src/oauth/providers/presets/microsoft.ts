/**
 * Microsoft OAuth / Entra ID Provider Preset for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OIDCProvider, type OIDCProviderConfig } from "../OIDCProvider.js";
import type { OAuthTokens, OAuthUserProfile } from "../../types.js";

export interface MicrosoftProviderOptions extends Partial<OIDCProviderConfig> {
  clientId: string;
  clientSecret: string;
  /** Azure Tenant ID (defaults to "common") */
  tenantId?: string;
  prompt?: string;
}

export function microsoftProvider(options: MicrosoftProviderOptions): OIDCProvider {
  const tenant = options.tenantId || "common";
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;

  return new OIDCProvider({
    id: "microsoft",
    name: "Microsoft",
    issuer,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    defaultScopes: options.defaultScopes || ["openid", "profile", "email", "User.Read"],
    profileParser: (raw: any, tokens: OAuthTokens): OAuthUserProfile => {
      return {
        provider: "microsoft",
        id: String(raw.sub || raw.oid || raw.id || ""),
        email: raw.email || raw.preferred_username || raw.userPrincipalName || null,
        emailVerified: Boolean(raw.email || raw.preferred_username),
        name: raw.name || `${raw.given_name || ""} ${raw.family_name || ""}`.trim() || null,
        username: (raw.preferred_username || raw.email || "").split("@")[0] || null,
        avatarUrl: raw.picture || null,
        raw,
      };
    },
    ...options,
  });
}
