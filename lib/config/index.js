/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import dotenv from "dotenv";
import { createRequire } from "node:module";
import { createLogger } from "../utils/logger.js";
import { setPasswordPepper } from "./security.js";

dotenv.config();
const logConfig = createLogger("config");

export function normalizeKey(key) {
  return typeof key === "string" ? key.toLowerCase().replace(/[^a-z0-9]/g, "") : "";
}

const CANONICAL_KEYS = [
  "app_name", "device_trust_duration_days", "main_secret_token", "session_secret_key",
  "is_deployed", "db_type", "login_db", "sqlite_path", "mbkauth_two_fa_enable",
  "cookie_expire_time", "domain", "login_redirect_url", "github_login_enabled",
  "github_app_client_id", "github_app_client_secret", "github_client_id",
  "github_client_secret", "google_login_enabled", "google_client_id",
  "google_client_secret", "max_sessions_per_user", "cli_auth_base_url", "cli_auth_enabled"
].map((k) => ({ lower: k, upper: k.toUpperCase() }));

const DEFAULT_CONFIG = {
  device_trust_duration_days: 7,
  is_deployed: "false",
  db_type: "postgres",
  sqlite_path: "./mbkauthe.sqlite",
  mbkauth_two_fa_enable: "false",
  cookie_expire_time: 2,
  login_redirect_url: "/dashboard",
  github_login_enabled: "false",
  google_login_enabled: "false",
  max_sessions_per_user: 5,
  cli_auth_enabled: "false",
};

const BOOLEAN_KEYS = new Set(["github_login_enabled", "google_login_enabled", "mbkauth_two_fa_enable", "is_deployed", "cli_auth_enabled"]);
const STRING_KEYS = new Set([
  "app_name", "main_secret_token", "session_secret_key", "db_type", "login_db", "sqlite_path",
  "domain", "login_redirect_url", "github_app_client_id", "github_app_client_secret",
  "github_client_id", "github_client_secret", "google_client_id", "google_client_secret", "cli_auth_base_url"
]);
const REQUIRED_KEYS = ["app_name", "main_secret_token", "session_secret_key", "is_deployed", "mbkauth_two_fa_enable", "domain"];

const isPlainObject = (val) => Boolean(val && typeof val === "object" && !Array.isArray(val));
const isBlank = (val) => val === undefined || val === null || (typeof val === "string" && val.trim() === "");
const hasValue = (val) => !isBlank(val);

function parseJsonEnv(name, { required = false } = {}) {
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
  } catch (error) {
    const message = error.message === `${name} must be a valid object` ? error.message : `Invalid JSON in process.env.${name}`;
    if (required) throw new Error(`[mbkauthe] Configuration Error:\n  - ${message}`);
    console.warn(`[mbkauthe] ${message}, ignoring it`);
    return null;
  }
}

function getPrefixedEnvVars(prefix) {
  const result = {};
  const lowerPrefix = prefix.toLowerCase();
  for (const [key, value] of Object.entries(process.env)) {
    const lowerKey = key.toLowerCase();
    if ((lowerKey.startsWith(`${lowerPrefix}.`) || lowerKey.startsWith(`${lowerPrefix}_`)) && hasValue(value)) {
      result[key.slice(prefix.length + 1)] = value;
    }
  }
  return result;
}

function getSimpleEnvValue(key) {
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

function findValue(source, key) {
  if (!source || typeof source !== "object") return undefined;
  if (source[key] !== undefined) return source[key];
  const target = normalizeKey(key);
  const matchKey = Object.keys(source).find((k) => normalizeKey(k) === target);
  return matchKey !== undefined ? source[matchKey] : undefined;
}

const setBoth = (config, lowerKey, upperKey, val) => {
  config[lowerKey] = val;
  config[upperKey] = val;
};

function normalizeBooleanFlag(config, lowerKey, upperKey, errors) {
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

function normalizePositiveNumber(config, lowerKey, upperKey, errors, integerOnly = false) {
  const num = Number(config[lowerKey]);
  if (!Number.isFinite(num) || num <= 0 || (integerOnly && !Number.isInteger(num))) {
    errors.push(`${upperKey} must be a valid positive ${integerOnly ? "integer" : "number"}`);
  } else {
    setBoth(config, lowerKey, upperKey, num);
  }
}

function normalizeAndValidateConfig(config, errors) {
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
  normalizePositiveNumber(config, "device_trust_duration_days", "DEVICE_TRUST_DURATION_DAYS", errors);
  normalizePositiveNumber(config, "max_sessions_per_user", "MAX_SESSIONS_PER_USER", errors, true);
}

function createConfigProxy(target) {
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

function resolveRawConfig() {
  const errors = [];
  const usedFromEnv = new Set();
  const usedFromVar = new Set();
  const usedFromShared = new Set();
  const usedDefaults = new Set();

  const mbkautheVarSource = { ...(parseJsonEnv("mbkautheVar") || {}), ...getPrefixedEnvVars("mbkautheVar") };
  const mbkauthSharedSource = { ...(parseJsonEnv("mbkauthShared") || {}), ...getPrefixedEnvVars("mbkauthShared") };
  const resolved = {};

  for (const { lower, upper } of CANONICAL_KEYS) {
    const simpleVal = getSimpleEnvValue(lower);
    if (hasValue(simpleVal)) {
      setBoth(resolved, lower, upper, simpleVal);
      usedFromEnv.add(upper);
      continue;
    }
    const varVal = findValue(mbkautheVarSource, lower);
    if (hasValue(varVal)) {
      setBoth(resolved, lower, upper, varVal);
      usedFromVar.add(upper);
      continue;
    }
    const sharedVal = findValue(mbkauthSharedSource, lower);
    if (hasValue(sharedVal)) {
      setBoth(resolved, lower, upper, sharedVal);
      usedFromShared.add(upper);
      continue;
    }
    const defVal = findValue(DEFAULT_CONFIG, lower);
    if (defVal !== undefined) {
      setBoth(resolved, lower, upper, defVal);
      usedDefaults.add(upper);
    }
  }

  const knownNorms = new Set(CANONICAL_KEYS.map((k) => normalizeKey(k.lower)));
  const resolveCustomKey = (k) => {
    if (knownNorms.has(normalizeKey(k))) return;
    const simpleVal = getSimpleEnvValue(k);
    if (hasValue(simpleVal)) {
      setBoth(resolved, k.toLowerCase(), k.toUpperCase(), simpleVal);
      usedFromEnv.add(k.toUpperCase());
      return;
    }
    const varVal = findValue(mbkautheVarSource, k);
    if (hasValue(varVal)) {
      setBoth(resolved, k.toLowerCase(), k.toUpperCase(), varVal);
      usedFromVar.add(k.toUpperCase());
      return;
    }
    const sharedVal = findValue(mbkauthSharedSource, k);
    if (hasValue(sharedVal)) {
      setBoth(resolved, k.toLowerCase(), k.toUpperCase(), sharedVal);
      usedFromShared.add(k.toUpperCase());
    }
  };

  Object.keys(mbkauthSharedSource).forEach(resolveCustomKey);
  Object.keys(mbkautheVarSource).forEach(resolveCustomKey);

  normalizeAndValidateConfig(resolved, errors);
  return { resolved, errors, usedFromEnv, usedFromVar, usedFromShared, usedDefaults };
}

function validateConfiguration(options = {}) {
  const throwOnError = typeof options === "boolean" ? options : (options?.throwOnError ?? true);
  const logSummary = typeof options === "object" && options?.logSummary !== undefined ? options.logSummary : true;
  const { resolved, errors, usedFromEnv, usedFromVar, usedFromShared, usedDefaults } = resolveRawConfig();

  for (const key of REQUIRED_KEYS) {
    if (isBlank(resolved[key])) errors.push(`${key.toUpperCase()} is required and cannot be empty`);
  }

  if (resolved.github_login_enabled === "true") {
    if (!(resolved.github_app_client_id || resolved.github_client_id)) {
      errors.push("GITHUB_APP_CLIENT_ID (or GITHUB_CLIENT_ID) is required when GITHUB_LOGIN_ENABLED is 'true'");
    }
    if (!(resolved.github_app_client_secret || resolved.github_client_secret)) {
      errors.push("GITHUB_APP_CLIENT_SECRET (or GITHUB_CLIENT_SECRET) is required when GITHUB_LOGIN_ENABLED is 'true'");
    }
  }

  if (resolved.google_login_enabled === "true") {
    if (isBlank(resolved.google_client_id)) errors.push("GOOGLE_CLIENT_ID is required when GOOGLE_LOGIN_ENABLED is 'true'");
    if (isBlank(resolved.google_client_secret)) errors.push("GOOGLE_CLIENT_SECRET is required when GOOGLE_LOGIN_ENABLED is 'true'");
  }

  if (resolved.db_type === "sqlite") {
    if (isBlank(resolved.sqlite_path)) errors.push("SQLITE_PATH is required and cannot be empty when DB_TYPE is 'sqlite'");
  } else {
    if (isBlank(resolved.login_db)) {
      errors.push("LOGIN_DB is required and cannot be empty when DB_TYPE is 'postgres'");
    } else if (!resolved.login_db.startsWith("postgresql://") && !resolved.login_db.startsWith("postgres://")) {
      errors.push("LOGIN_DB must be a valid PostgreSQL connection string");
    }
  }

  if (errors.length > 0) {
    if (throwOnError) throw new Error(`[mbkauthe] Configuration Validation Failed:\n  - ${errors.join("\n  - ")}`);
  } else if (logSummary) {
    const parts = [
      usedFromEnv.size && `process.env: ${usedFromEnv.size} keys`,
      usedFromVar.size && `mbkautheVar: ${usedFromVar.size} keys`,
      usedFromShared.size && `mbkauthShared: ${usedFromShared.size} keys`,
      usedDefaults.size && `defaults: ${usedDefaults.size} keys`,
    ].filter(Boolean);
    logConfig(`Configuration loaded${parts.length ? ` (${parts.join(", ")})` : ""}`);
  }

  return Object.freeze(createConfigProxy(resolved));
}

const mbkautheVar = new Proxy({}, {
  get(t, prop, receiver) {
    if (typeof prop !== "string") return Reflect.get(t, prop, receiver);
    return createConfigProxy(resolveRawConfig().resolved)[prop];
  },
  has(t, prop) {
    if (typeof prop !== "string") return Reflect.has(t, prop);
    return prop in createConfigProxy(resolveRawConfig().resolved);
  },
  ownKeys() {
    return Reflect.ownKeys(resolveRawConfig().resolved);
  },
  getOwnPropertyDescriptor(t, prop) {
    const { resolved } = resolveRawConfig();
    return prop in resolved ? { value: resolved[prop], writable: false, enumerable: true, configurable: true } : undefined;
  }
});

const require = createRequire(import.meta.url);
let packageJson;
try {
  packageJson = require("mbkauthe/package.json");
} catch {
  packageJson = require("../../package.json");
}

let appVersion;
try {
  appVersion = require("../../../../package.json")?.version || require(process.cwd() + "/package.json")?.version || "unknown";
} catch {
  appVersion = "unknown";
}

if (mbkautheVar.SESSION_SECRET_KEY) {
  setPasswordPepper(mbkautheVar.SESSION_SECRET_KEY);
}

export { packageJson, appVersion, mbkautheVar, validateConfiguration, findValue, resolveRawConfig };
export { hashPassword, hashApiToken, verifyPassword } from "./security.js";