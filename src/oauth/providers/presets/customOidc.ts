/**
 * Custom OpenID Connect (OIDC) Provider Preset for MBKAuthe
 * Allows connecting any standard OIDC identity provider (Keycloak, Auth0, Okta, Authentik, etc.)
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import { OIDCProvider, type OIDCProviderConfig } from "../OIDCProvider.js";

export interface CustomOIDCProviderOptions extends OIDCProviderConfig {}

export function customOIDCProvider(options: CustomOIDCProviderOptions): OIDCProvider {
  return new OIDCProvider(options);
}
