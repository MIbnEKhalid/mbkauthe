import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MBKAuthConfig, OAuthProvidersConfig } from "./types.js";
import { setPasswordPepper } from "../core/security/password.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Read package.json dynamically without hardcoded versions
function findPackageJson(): { version: string; name: string; [key: string]: any } {
  let currentDir = __dirname;
  while (currentDir) {
    const candidate = path.join(currentDir, "package.json");
    try {
      if (fs.existsSync(candidate)) {
        const parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
        if (parsed?.name === "mbkauthe" && typeof parsed?.version === "string") {
          return parsed;
        }
      }
    } catch {}
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }
  return { version: "", name: "mbkauthe" };
}

export const packageJson = findPackageJson();
export const appVersion = packageJson.version;

export function normalizeKey(key: string): string {
  return typeof key === "string" ? key.toLowerCase().replace(/[^a-z0-9]/g, "") : "";
}

const CANONICAL_KEYS = [
  "app_name", "main_secret_token", "session_secret_key",
  "is_deployed", "db_type", "login_db", "sqlite_path", "mbkauth_two_fa_enable",
  "cookie_expire_time", "domain", "login_redirect_url", "oauth_providers",
  "max_sessions_per_user", "cli_auth_base_url", "cli_auth_enabled"
].map((k) => ({ lower: k, upper: k.toUpperCase() }));

const DEFAULT_CONFIG: Record<string, any> = {
  app_name: "mbkapp",
  domain: "localhost",
  is_deployed: "false",
  db_type: "postgres",
  sqlite_path: "./mbkauthe.sqlite",
  mbkauth_two_fa_enable: "false",
  cookie_expire_time: 2,
  login_redirect_url: "/dashboard",
  oauth_providers: {},
  max_sessions_per_user: 5,
  cli_auth_enabled: "false",
};

const BOOLEAN_KEYS = new Set(["mbkauth_two_fa_enable", "is_deployed", "cli_auth_enabled"]);
const STRING_KEYS = new Set([
  "app_name", "main_secret_token", "session_secret_key", "db_type", "login_db", "sqlite_path",
  "domain", "login_redirect_url", "cli_auth_base_url"
]);
const REQUIRED_KEYS = ["app_name", "main_secret_token", "session_secret_key", "is_deployed", "mbkauth_two_fa_enable", "domain"];

const isPlainObject = (val: any) => Boolean(val && typeof val === "object" && !Array.isArray(val));
const isBlank = (val: any) => val === undefined || val === null || (typeof val === "string" && val.trim() === "");
const hasValue = (val: any) => !isBlank(val);

export function parseJsonEnv(name: string, { required = false } = {}): Record<string, any> | null {
  const directKey = Object.keys(process.env).find((k) => k.toLowerCase() === name.toLowerCase());
  const raw = directKey ? process.env[directKey] : undefined;
  if (isBlank(raw)) {
    if (required) throw new Error(`[mbkauthe] Configuration Error:\n  - process.env.${name} is not defined`);
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!isPlainObject(parsed)) throw new Error(`${name} must be a valid object`);
    return parsed;
  } catch (error: any) {
    const message = error.message === `${name} must be a valid object` ? error.message : `Invalid JSON in process.env.${name}`;
    if (required) throw new Error(`[mbkauthe] Configuration Error:\n  - ${message}`);
    console.warn(`[mbkauthe] ${message}, ignoring it`);
    return null;
  }
}

export function getPrefixedEnvVars(prefix: string): Record<string, any> {
  const result: Record<string, any> = {};
  const lowerPrefix = prefix.toLowerCase();
  for (const [key, value] of Object.entries(process.env)) {
    const lowerKey = key.toLowerCase();
    if ((lowerKey.startsWith(`${lowerPrefix}.`) || lowerKey.startsWith(`${lowerPrefix}_`)) && hasValue(value)) {
      result[key.slice(prefix.length + 1)] = value;
    }
  }
  return result;
}

export function getSimpleEnvValue(key: string): any {
  const target = normalizeKey(key);
  for (const [envKey, envVal] of Object.entries(process.env)) {
    const lower = envKey.toLowerCase();
    if (lower === "mbkauthevar" || lower === "mbkauthshared" || lower.startsWith("mbkauthevar.") || lower.startsWith("mbkauthevar_") || lower.startsWith("mbkauthshared.") || lower.startsWith("mbkauthshared_")) {
      continue;
    }
    if (normalizeKey(envKey) === target && hasValue(envVal)) return envVal;
  }
  return undefined;
}

export function findValue(source: Record<string, any>, key: string): any {
  if (!source || typeof source !== "object") return undefined;
  if (source[key] !== undefined) return source[key];
  const target = normalizeKey(key);
  const matchKey = Object.keys(source).find((k) => normalizeKey(k) === target);
  return matchKey !== undefined ? source[matchKey] : undefined;
}

const setBoth = (config: Record<string, any>, lowerKey: string, upperKey: string, val: any) => {
  config[lowerKey] = val;
  config[upperKey] = val;
};

function normalizeBooleanFlag(config: Record<string, any>, lowerKey: string, upperKey: string, errors: string[]) {
  const value = config[lowerKey];
  if (typeof value === "boolean") {
    setBoth(config, lowerKey, upperKey, value ? "true" : "false");
    return;
  }
  const norm = String(value ?? "").trim().toLowerCase();
  if (norm === "f" || norm === "false") setBoth(config, lowerKey, upperKey, "false");
  else if (norm === "true") setBoth(config, lowerKey, upperKey, "true");
  else if (!isBlank(value)) errors.push(`${upperKey} must be either 'true' or 'false' or 'f'`);
}

function normalizePositiveNumber(config: Record<string, any>, lowerKey: string, upperKey: string, errors: string[], integerOnly = false) {
  const num = Number(config[lowerKey]);
  if (!Number.isFinite(num) || num <= 0 || (integerOnly && !Number.isInteger(num))) {
    errors.push(`${upperKey} must be a valid positive ${integerOnly ? "integer" : "number"}`);
  } else {
    setBoth(config, lowerKey, upperKey, num);
  }
}

function normalizeAndValidateConfig(config: Record<string, any>, errors: string[]) {
  for (const { lower, upper } of CANONICAL_KEYS) {
    if (STRING_KEYS.has(lower) && hasValue(config[lower])) {
      setBoth(config, lower, upper, String(config[lower]).trim());
    }
  }

  if (hasValue(config.app_name)) {
    setBoth(config, "app_name", "APP_NAME", config.app_name.toLowerCase());
  }

  if (hasValue(config.db_type)) {
    const db_type = config.db_type.toLowerCase();
    setBoth(config, "db_type", "DB_TYPE", db_type);
    if (!["postgres", "sqlite"].includes(db_type)) {
      errors.push("DB_TYPE must be either 'postgres' or 'sqlite'");
    }
  }

  if (hasValue(config.domain)) {
    const domain = config.domain.toLowerCase().replace(/^\.+/, "");
    setBoth(config, "domain", "DOMAIN", domain);
    if (domain.includes("://") || domain.includes("/") || domain.includes(":")) {
      errors.push("DOMAIN must be a hostname only, without protocol, path, or port");
    }
  }

  if (hasValue(config.login_redirect_url)) {
    const redirectUrl = String(config.login_redirect_url).trim();
    setBoth(config, "login_redirect_url", "LOGIN_REDIRECT_URL", redirectUrl);
    if (!redirectUrl.startsWith("/") || redirectUrl.startsWith("//")) {
      errors.push("LOGIN_REDIRECT_URL must be a relative path starting with '/'");
    }
  }

  for (const { lower, upper } of CANONICAL_KEYS) {
    if (BOOLEAN_KEYS.has(lower)) normalizeBooleanFlag(config, lower, upper, errors);
  }

  normalizePositiveNumber(config, "cookie_expire_time", "COOKIE_EXPIRE_TIME", errors);
  normalizePositiveNumber(config, "max_sessions_per_user", "MAX_SESSIONS_PER_USER", errors, true);
}

function createConfigProxy(target: any): MBKAuthConfig {
  return new Proxy(target, {
    get(t, prop, receiver) {
      if (typeof prop !== "string") return Reflect.get(t, prop, receiver);
      if (prop in t) return t[prop];
      const lower = prop.toLowerCase();
      if (lower in t) return t[lower];
      const upper = prop.toUpperCase();
      if (upper in t) return t[upper];
      const norm = normalizeKey(prop);
      const match = Object.keys(t).find((k) => normalizeKey(k) === norm);
      return match ? t[match] : undefined;
    },
    has(t, prop) {
      if (typeof prop !== "string") return Reflect.has(t, prop);
      return prop in t || prop.toLowerCase() in t || Object.keys(t).some((k) => normalizeKey(k) === normalizeKey(prop));
    }
  });
}

const KNOWN_OAUTH_PROVIDERS = new Set(["github", "google", "microsoft", "azure", "discord", "apple", "oidc"]);

/**
 * Extracts and consolidates OAuth providers from JSON env, top-level objects, or legacy env keys.
 */
function extractOAuthProviders(
  mbkautheVarSource: Record<string, any>,
  mbkauthSharedSource: Record<string, any>
): OAuthProvidersConfig {
  const result: Record<string, any> = {};

  // 1. Direct env variable OAUTH_PROVIDERS
  const directJson = parseJsonEnv("OAUTH_PROVIDERS") || parseJsonEnv("oauth_providers");
  if (directJson && typeof directJson === "object") {
    Object.assign(result, directJson);
  }

  // 2. Nested in mbkauthShared
  const sharedProviders = findValue(mbkauthSharedSource, "oauth_providers") || findValue(mbkauthSharedSource, "oauth");
  if (sharedProviders && typeof sharedProviders === "object") {
    Object.assign(result, sharedProviders);
  }

  // 3. Nested in mbkautheVar
  const varProviders = findValue(mbkautheVarSource, "oauth_providers") || findValue(mbkautheVarSource, "oauth");
  if (varProviders && typeof varProviders === "object") {
    Object.assign(result, varProviders);
  }

  // 4. Top-level provider objects in mbkauthShared & mbkautheVar
  // e.g. { "GITHUB": { "LOGIN_ENABLED": "true", "CLIENT_ID": "...", "CLIENT_SECRET": "..." } }
  const scanTopLevel = (source: Record<string, any>) => {
    for (const [key, val] of Object.entries(source)) {
      if (!val || typeof val !== "object" || Array.isArray(val)) continue;
      const lowerKey = key.toLowerCase();
      const hasClientDetails = val.client_id !== undefined || val.clientId !== undefined || val.CLIENT_ID !== undefined;
      const hasLoginEnabled = val.login_enabled !== undefined || val.loginEnabled !== undefined || val.LOGIN_ENABLED !== undefined;
      if (KNOWN_OAUTH_PROVIDERS.has(lowerKey) || hasClientDetails || hasLoginEnabled) {
        result[lowerKey] = { ...(result[lowerKey] || {}), ...val };
      }
    }
  };

  scanTopLevel(mbkauthSharedSource);
  scanTopLevel(mbkautheVarSource);

  // 5. Legacy flat fallback if still present
  const legacyGithubId = getSimpleEnvValue("github_app_client_id") || getSimpleEnvValue("github_client_id");
  const legacyGithubSecret = getSimpleEnvValue("github_app_client_secret") || getSimpleEnvValue("github_client_secret");
  const legacyGithubEnabled = getSimpleEnvValue("github_login_enabled");
  if (legacyGithubId && !result.github) {
    result.github = {
      client_id: legacyGithubId,
      client_secret: legacyGithubSecret || "",
      login_enabled: legacyGithubEnabled !== undefined ? legacyGithubEnabled : "true",
    };
  }

  const legacyGoogleId = getSimpleEnvValue("google_client_id");
  const legacyGoogleSecret = getSimpleEnvValue("google_client_secret");
  const legacyGoogleEnabled = getSimpleEnvValue("google_login_enabled");
  if (legacyGoogleId && !result.google) {
    result.google = {
      client_id: legacyGoogleId,
      client_secret: legacyGoogleSecret || "",
      login_enabled: legacyGoogleEnabled !== undefined ? legacyGoogleEnabled : "true",
    };
  }

  return result;
}

function extractAndResolveConfig({ strict = false } = {}): { resolved: Record<string, any>; errors: string[] } {
  const errors: string[] = [];
  const mbkautheVarSource = { ...(parseJsonEnv("mbkautheVar") || {}), ...getPrefixedEnvVars("mbkautheVar") };
  const mbkauthSharedSource = { ...(parseJsonEnv("mbkauthShared") || {}), ...getPrefixedEnvVars("mbkauthShared") };
  const resolved: Record<string, any> = {};

  for (const { lower, upper } of CANONICAL_KEYS) {
    if (lower === "oauth_providers") continue; // handled specially below

    const simpleVal = getSimpleEnvValue(lower);
    if (hasValue(simpleVal)) {
      setBoth(resolved, lower, upper, simpleVal);
      continue;
    }
    const varVal = findValue(mbkautheVarSource, lower);
    if (hasValue(varVal)) {
      setBoth(resolved, lower, upper, varVal);
      continue;
    }
    const sharedVal = findValue(mbkauthSharedSource, lower);
    if (hasValue(sharedVal)) {
      setBoth(resolved, lower, upper, sharedVal);
      continue;
    }
    const defVal = findValue(DEFAULT_CONFIG, lower);
    if (defVal !== undefined) {
      setBoth(resolved, lower, upper, defVal);
    }
  }

  // Extract unified OAuth providers
  const oauthProviders = extractOAuthProviders(mbkautheVarSource, mbkauthSharedSource);
  setBoth(resolved, "oauth_providers", "OAUTH_PROVIDERS", oauthProviders);

  const knownNorms = new Set(CANONICAL_KEYS.map((k) => normalizeKey(k.lower)));
  const resolveCustomKey = (k: string) => {
    if (knownNorms.has(normalizeKey(k))) return;
    const simpleVal = getSimpleEnvValue(k);
    if (hasValue(simpleVal)) {
      setBoth(resolved, k.toLowerCase(), k.toUpperCase(), simpleVal);
      return;
    }
    const varVal = findValue(mbkautheVarSource, k);
    if (hasValue(varVal)) {
      setBoth(resolved, k.toLowerCase(), k.toUpperCase(), varVal);
      return;
    }
    const sharedVal = findValue(mbkauthSharedSource, k);
    if (hasValue(sharedVal)) {
      setBoth(resolved, k.toLowerCase(), k.toUpperCase(), sharedVal);
    }
  };

  Object.keys(mbkautheVarSource).forEach(resolveCustomKey);
  Object.keys(mbkauthSharedSource).forEach(resolveCustomKey);

  if (strict) {
    for (const key of REQUIRED_KEYS) {
      if (isBlank(resolved[key])) {
        errors.push(`Missing required configuration: ${key.toUpperCase()}`);
      }
    }
  }

  normalizeAndValidateConfig(resolved, errors);
  return { resolved, errors };
}

export function resolveRawConfig(): MBKAuthConfig {
  const { resolved } = extractAndResolveConfig({ strict: false });
  setPasswordPepper(resolved.SESSION_SECRET_KEY || resolved.session_secret_key || "");
  return createConfigProxy(resolved);
}

export function checkConfigurationStatus(): { valid: boolean; missingRequired: string[]; warnings: string[]; resolved: Record<string, any> } {
  const { resolved, errors } = extractAndResolveConfig({ strict: true });
  const missingRequired = errors.filter((e) => e.startsWith("Missing required configuration:")).map((e) => e.replace("Missing required configuration: ", ""));
  const warnings = errors.filter((e) => !e.startsWith("Missing required configuration:"));
  return {
    valid: errors.length === 0,
    missingRequired,
    warnings,
    resolved,
  };
}

export function validateConfiguration(): MBKAuthConfig {
  const { resolved, errors } = extractAndResolveConfig({ strict: true });
  if (errors.length > 0) {
    throw new Error(`[mbkauthe] Configuration Validation Failed:\n  - ${errors.join("\n  - ")}`);
  }
  setPasswordPepper(resolved.SESSION_SECRET_KEY || resolved.session_secret_key || "");
  return createConfigProxy(resolved);
}

export const mbkautheVar = resolveRawConfig();
export default mbkautheVar;
