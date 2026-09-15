/**
 * OAuth Provider Loader from Environment Configuration
 * Automatically discovers, validates, and initializes OAuth & OIDC providers
 * from structured environment configuration objects (e.g. OAUTH_PROVIDERS or mbkautheVar).
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import type { OAuthProvider } from "../ports.js";
import type { OAuthProviderConfig, OAuthProvidersConfig } from "../../config/types.js";
import { githubProvider } from "./presets/github.js";
import { googleProvider } from "./presets/google.js";
import { microsoftProvider } from "./presets/microsoft.js";
import { discordProvider } from "./presets/discord.js";
import { appleProvider } from "./presets/apple.js";
import { customOIDCProvider } from "./presets/customOidc.js";
import { createLogger } from "../../utils/logger.js";

import { mbkautheVar } from "../../config/env.js";

const debug = createLogger("mbkauthe:oauth-loader");

/**
 * Resolves configuration source from arguments, mbkautheVar, or process.env.
 */
export function resolveConfigSource(configSource?: OAuthProvidersConfig | Record<string, any> | string): Record<string, any> | undefined {
  let source = configSource !== undefined ? configSource : (mbkautheVar?.OAUTH_PROVIDERS || mbkautheVar?.oauth_providers || process.env.OAUTH_PROVIDERS || process.env.oauth_providers);
  if (typeof source === "string") {
    try {
      source = JSON.parse(source);
    } catch {
      return undefined;
    }
  }
  if (source && typeof source === "object" && !Array.isArray(source)) {
    return source as Record<string, any>;
  }
  return undefined;
}

/**
 * Normalizes boolean flag from string or boolean.
 */
function isTruthy(val: any, defaultVal = true): boolean {
  if (val === undefined || val === null) return defaultVal;
  if (typeof val === "boolean") return val;
  const str = String(val).trim().toLowerCase();
  if (str === "false" || str === "f" || str === "0" || str === "no" || str === "off") return false;
  if (str === "true" || str === "t" || str === "1" || str === "yes" || str === "on") return true;
  return defaultVal;
}

/**
 * Normalizes property lookup on provider config object (case-insensitive & snake_case/camelCase).
 */
function getProp(cfg: Record<string, any>, ...keys: string[]): any {
  if (!cfg || typeof cfg !== "object") return undefined;
  for (const key of keys) {
    if (cfg[key] !== undefined) return cfg[key];
    const lowerKey = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    for (const [k, v] of Object.entries(cfg)) {
      if (k.toLowerCase().replace(/[^a-z0-9]/g, "") === lowerKey && v !== undefined) {
        return v;
      }
    }
  }
  return undefined;
}

export interface OAuthProviderUIItem {
  id: string;
  name: string;
  displayName: string;
  loginUrl: string;
  iconClass: string;
  btnClass: string;
  mobileBtnClass: string;
  isLastUsed: boolean;
}

/**
 * Checks if a specific OAuth provider is enabled in the configuration.
 */
export function isOAuthProviderConfigured(providerId: string, configSource?: OAuthProvidersConfig | Record<string, any> | string): boolean {
  const resolvedSource = resolveConfigSource(configSource);
  if (!resolvedSource) return false;
  const targetId = providerId.toLowerCase().trim();

  for (const [key, rawCfg] of Object.entries(resolvedSource)) {
    if (key.toLowerCase().trim() === targetId && rawCfg && typeof rawCfg === "object") {
      const enabled = isTruthy(getProp(rawCfg, "login_enabled", "loginEnabled", "enabled"), true);
      const clientId = getProp(rawCfg, "client_id", "clientId", "app_client_id", "appClientId", "id");
      return Boolean(enabled && clientId);
    }
  }
  return false;
}

/**
 * Returns metadata for all configured and enabled OAuth providers for rendering in the login UI.
 */
export function getEnabledOAuthProvidersUI(
  configSource?: OAuthProvidersConfig | Record<string, any> | string,
  lastLoginMethod?: string | null
): OAuthProviderUIItem[] {
  const resolvedSource = resolveConfigSource(configSource);
  if (!resolvedSource) return [];
  const items: OAuthProviderUIItem[] = [];

  for (const [providerKey, rawConfig] of Object.entries(resolvedSource)) {
    if (!rawConfig || typeof rawConfig !== "object" || Array.isArray(rawConfig)) continue;
    const normKey = providerKey.toLowerCase().trim();
    const cfg = rawConfig as Record<string, any>;
    const enabled = isTruthy(getProp(cfg, "login_enabled", "loginEnabled", "enabled"), true);
    const clientId = getProp(cfg, "client_id", "clientId", "app_client_id", "appClientId", "id");
    if (!enabled || !clientId) continue;

    let name = "OAuth";
    let iconClass = "fas fa-shield-alt";
    let btnClass = `btn-social btn-${normKey}-side`;
    let mobileBtnClass = `mobile-${normKey}-btn`;

    if (normKey === "github") {
      name = "GitHub";
      iconClass = "fab fa-github";
    } else if (normKey === "google") {
      name = "Google";
      iconClass = "fab fa-google";
    } else if (normKey === "microsoft" || normKey === "azure" || normKey === "entra") {
      name = "Microsoft";
      iconClass = "fab fa-microsoft";
    } else if (normKey === "discord") {
      name = "Discord";
      iconClass = "fab fa-discord";
    } else if (normKey === "apple") {
      name = "Apple";
      iconClass = "fab fa-apple";
    } else {
      name = getProp(cfg, "name", "display_name") || normKey.charAt(0).toUpperCase() + normKey.slice(1);
      iconClass = "fas fa-shield-alt";
    }

    items.push({
      id: normKey,
      name,
      displayName: `Login with ${name}`,
      loginUrl: `/mbkauthe/oauth/${normKey}/begin`,
      iconClass,
      btnClass,
      mobileBtnClass,
      isLastUsed: lastLoginMethod?.toLowerCase() === normKey,
    });
  }

  return items;
}

/**
 * Instantiates OAuth providers from a structured configuration object.
 *
 * Supported formats:
 * - Nested OAUTH_PROVIDERS: `{ "github": { "login_enabled": "true", "client_id": "...", "client_secret": "..." } }`
 * - Uppercase keys: `{ "GITHUB": { "LOGIN_ENABLED": "true", "CLIENT_ID": "...", "CLIENT_SECRET": "..." } }`
 * - Microsoft with tenant: `{ "microsoft": { "client_id": "...", "client_secret": "...", "tenant": "common" } }`
 * - Custom OIDC: `{ "okta": { "type": "oidc", "issuer": "https://company.okta.com", "client_id": "...", "client_secret": "..." } }`
 */
export function loadOAuthProvidersFromConfig(configSource?: OAuthProvidersConfig | Record<string, any> | string): OAuthProvider[] {
  const resolvedSource = resolveConfigSource(configSource);
  if (!resolvedSource) {
    return [];
  }

  const providers: OAuthProvider[] = [];

  for (const [providerKey, rawConfig] of Object.entries(resolvedSource)) {
    if (!rawConfig || typeof rawConfig !== "object" || Array.isArray(rawConfig)) {
      continue;
    }

    const normKey = providerKey.toLowerCase().trim();
    const cfg = rawConfig as Record<string, any>;

    const enabled = isTruthy(getProp(cfg, "login_enabled", "loginEnabled", "enabled"), true);
    if (!enabled) {
      debug("Provider %s is disabled in configuration, skipping", providerKey);
      continue;
    }

    const clientId = getProp(cfg, "client_id", "clientId", "app_client_id", "appClientId", "id");
    const clientSecret = getProp(cfg, "client_secret", "clientSecret", "app_client_secret", "appClientSecret", "secret") || "";

    if (!clientId) {
      debug("Provider %s missing client_id, skipping", providerKey);
      continue;
    }

    const type = String(getProp(cfg, "type", "provider_type") || normKey).toLowerCase().trim();
    const scopesRaw = getProp(cfg, "scopes", "default_scopes", "defaultScopes");
    const scopes = Array.isArray(scopesRaw)
      ? scopesRaw
      : typeof scopesRaw === "string" && scopesRaw.trim()
        ? scopesRaw.split(/[\s,]+/).filter(Boolean)
        : undefined;

    try {
      if (normKey === "github" || type === "github") {
        providers.push(
          githubProvider({
            clientId,
            clientSecret,
            defaultScopes: scopes,
          })
        );
        debug("Loaded GitHub provider from config");
      } else if (normKey === "google" || type === "google") {
        providers.push(
          googleProvider({
            clientId,
            clientSecret,
            defaultScopes: scopes,
          })
        );
        debug("Loaded Google provider from config");
      } else if (normKey === "microsoft" || type === "microsoft" || type === "azure" || type === "entra") {
        const tenantId = getProp(cfg, "tenant", "tenant_id", "tenantId") || "common";
        providers.push(
          microsoftProvider({
            clientId,
            clientSecret,
            tenantId,
            defaultScopes: scopes,
          })
        );
        debug("Loaded Microsoft provider from config (tenant: %s)", tenantId);
      } else if (normKey === "discord" || type === "discord") {
        providers.push(
          discordProvider({
            clientId,
            clientSecret,
            defaultScopes: scopes,
          })
        );
        debug("Loaded Discord provider from config");
      } else if (normKey === "apple" || type === "apple") {
        providers.push(
          appleProvider({
            clientId,
            clientSecret,
            defaultScopes: scopes,
          })
        );
        debug("Loaded Apple provider from config");
      } else {
        // Custom OIDC or generic provider
        const issuer = getProp(cfg, "issuer", "issuer_url", "issuerUrl");
        if (issuer || type === "oidc") {
          const providerName = getProp(cfg, "name", "display_name") || normKey.charAt(0).toUpperCase() + normKey.slice(1);
          providers.push(
            customOIDCProvider({
              id: normKey,
              name: providerName,
              issuer: issuer || "",
              clientId,
              clientSecret,
              defaultScopes: scopes,
              authorizationEndpoint: getProp(cfg, "authorization_endpoint", "authorizationEndpoint"),
              tokenEndpoint: getProp(cfg, "token_endpoint", "tokenEndpoint"),
              userinfoEndpoint: getProp(cfg, "userinfo_endpoint", "userinfoEndpoint"),
              jwksUri: getProp(cfg, "jwks_uri", "jwksUri"),
            })
          );
          debug("Loaded Custom OIDC provider %s (issuer: %s)", normKey, issuer);
        } else {
          console.warn(`[mbkauthe] Unknown OAuth provider type '${normKey}' without an OIDC issuer; skipping.`);
        }
      }
    } catch (err: any) {
      console.error(`[mbkauthe] Failed to instantiate OAuth provider '${providerKey}':`, err.message);
    }
  }

  return providers;
}
