/**
 * OAuth & OIDC Providers and Presets Exports for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

export { OAuth2Provider, type OAuth2ProviderConfig } from "./OAuth2Provider.js";
export { OIDCProvider, type OIDCProviderConfig, type OIDCDiscoveryDocument } from "./OIDCProvider.js";

// Presets
export { googleProvider, type GoogleProviderOptions } from "./presets/google.js";
export { githubProvider, type GitHubProviderOptions } from "./presets/github.js";
export { microsoftProvider, type MicrosoftProviderOptions } from "./presets/microsoft.js";
export { discordProvider, type DiscordProviderOptions } from "./presets/discord.js";
export { appleProvider, type AppleProviderOptions } from "./presets/apple.js";
export { customOIDCProvider, type CustomOIDCProviderOptions } from "./presets/customOidc.js";

// Loader
export { loadOAuthProvidersFromConfig, isOAuthProviderConfigured } from "./loader.js";
