// Type definitions for mbkauthe
// Project: https://github.com/MIbnEKhalid/mbkauthe
// Definitions by: Muhammad Bin Khalid <https://github.com/MIbnEKhalid>

/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import { Request, Response, NextFunction, Router, Express as ExpressApp } from 'express';
import { SessionOptions } from 'express-session';
import { Pool } from 'pg';

// Global augmentations for Express Request and Session
declare global {
  namespace Express {
    interface Request {
      user?: {
        user_id?: string | number;
        username: string;
        role: 'superadmin' | 'normaluser' | 'guest' | string;
        full_name?: string;
      };
      userRole?: 'superadmin' | 'normaluser' | 'guest' | string;
    }

    interface Session {
      user?: {
        user_id?: string | number;
        username: string;
        full_name?: string;
        role: 'superadmin' | 'normaluser' | 'guest' | string;
        session_id?: string;
        allowed_apps?: string[];
        permissions?: SessionPermissions | string[];
      };
      pre_auth_user?: {
        user_id?: string | number;
        username: string;
        role: 'superadmin' | 'normaluser' | 'guest' | string;
        login_method?: 'password' | 'github' | 'google';
        redirect_url?: string | null;
        allowed_apps?: string[];
      };
      oauth_redirect?: string;
      oauth_csrf_token?: string;
      [key: string]: any;
    }
  }
}

// Configuration Types
export interface MBKAuthConfig {
  // Lowercase normalized
  app_name?: string;
  session_secret_key?: string;
  main_secret_token?: string;
  is_deployed?: 'true' | 'false' | 'f';
  domain?: string;
  db_type?: 'postgres' | 'sqlite';
  login_db?: string;
  sqlite_path?: string;
  mbkauth_two_fa_enable?: 'true' | 'false' | 'f';
  cookie_expire_time?: number;
  device_trust_duration_days?: number;
  github_login_enabled?: 'true' | 'false' | 'f';
  github_app_client_id?: string;
  github_app_client_secret?: string;
  github_client_id?: string;
  github_client_secret?: string;
  google_login_enabled?: 'true' | 'false' | 'f';
  google_client_id?: string;
  google_client_secret?: string;
  login_redirect_url?: string;
  max_sessions_per_user?: number;
  cli_auth_base_url?: string;
  cli_auth_enabled?: 'true' | 'false' | 'f';

  // Uppercase canonical
  APP_NAME: string;
  SESSION_SECRET_KEY: string;
  MAIN_SECRET_TOKEN: string;
  IS_DEPLOYED: 'true' | 'false' | 'f';
  DOMAIN: string;
  DB_TYPE?: 'postgres' | 'sqlite';
  LOGIN_DB?: string;
  SQLITE_PATH?: string;
  MBKAUTH_TWO_FA_ENABLE: 'true' | 'false' | 'f';
  COOKIE_EXPIRE_TIME?: number;
  DEVICE_TRUST_DURATION_DAYS?: number;
  GITHUB_LOGIN_ENABLED?: 'true' | 'false' | 'f';
  GITHUB_APP_CLIENT_ID?: string;
  GITHUB_APP_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GOOGLE_LOGIN_ENABLED?: 'true' | 'false' | 'f';
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  LOGIN_REDIRECT_URL?: string;
  MAX_SESSIONS_PER_USER?: number;
  CLI_AUTH_BASE_URL?: string;
  CLI_AUTH_ENABLED?: 'true' | 'false' | 'f';
  [key: string]: any;
}

export interface OAuthConfig {
  GITHUB_LOGIN_ENABLED?: 'true' | 'false' | 'f';
  GITHUB_APP_CLIENT_ID?: string;
  GITHUB_APP_CLIENT_SECRET?: string;
  GOOGLE_LOGIN_ENABLED?: 'true' | 'false' | 'f';
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
}

// User Types
export type UserRole = 'superadmin' | 'normaluser' | 'guest' | string;

export interface SessionUser {
  user_id?: string | number;
  username: string;
  full_name?: string;
  role: UserRole;
  session_id?: string;
  allowed_apps?: string[];
  permissions?: SessionPermissions | string[];
}

export interface PreAuthUser {
  user_id?: string | number;
  username: string;
  role: UserRole;
  allowed_apps?: string[];
  login_method?: 'password' | 'github' | 'google';
  redirect_url?: string | null;
}

// Database Schema Types
export interface DBUser {
  id: number;
  username: string;
  user_id?: string;
  password_hash?: string;
  role: UserRole;
  is_active: boolean;
  allowed_apps: string[];
  created_at?: Date;
  updated_at?: Date;
  last_login?: Date;
}

export interface TwoFARecord {
  username: string;
  is_enabled: boolean;
  two_fa_secret?: string;
}

export interface TrustedDevice {
  id: number;
  username: string;
  device_token: string;
  device_name?: string;
  user_agent?: string;
  ip_address?: string;
  created_at: Date;
  expires_at: Date;
  last_used: Date;
}

export interface GitHubUser {
  id: number;
  username: string;
  github_id: string;
  github_username: string;
  installation_id?: number;
  installation_target_type?: string;
  access_token: string;
  created_at: Date;
  updated_at: Date;
}

export interface GoogleUser {
  id: number;
  username: string;
  google_id: string;
  google_email: string;
  access_token: string;
  created_at: Date;
  updated_at: Date;
}

// API Token Types
export interface TokenPermissions {
  /** Explicit permission allow-list granted to the token (`app:service:action`). */
  permissions: string[];
}

export interface ApiToken {
  id: number;
  username: string;
  name: string;
  token_hash: string;
  prefix: string;
  permissions: TokenPermissions;
  last_used?: Date;
  created_at: Date;
  expires_at?: Date;
}

/** A token row as returned by list/admin repository methods */
export interface ApiTokenRow {
  id: number;
  name: string;
  prefix: string;
  permissions?: TokenPermissions;
  /** Flattened token permission allow-list. */
  token_permissions?: string[];
  last_used?: Date;
  created_at?: Date;
  expires_at?: Date;
  username?: string;
  email?: string;
  role?: string;
  full_name?: string;
}

/** A token row as returned by listForUserDetail */
export interface ApiTokenDetailRow {
  id: number;
  name: string;
  prefix: string;
  last_used?: Date;
  formatted_created: string;
  formatted_expires: string;
  is_active: boolean;
  permissions: TokenPermissions;
}

// CLI / Device-flow auth types
export type CliAuthStatus = 'pending' | 'approved' | 'completed' | 'denied' | 'expired';

export interface ApiTokenProfile {
  id: number;
  /** Public random key (>= 6 chars) that CLIs use instead of the serial id. */
  profile_key?: string | null;
  name: string;
  description?: string | null;
  permissions?: string[];
  expires_in_days?: number | null;
  active?: boolean;
  created_at?: Date;
  updated_at?: Date;
}

export interface CliAuthSession {
  id: number;
  device_code_hash: string;
  user_code_hash: string;
  client_name: string;
  profile_id: number;
  username?: string | null;
  token_id?: number | null;
  pending_token?: string | null;
  status: CliAuthStatus;
  expires_at: Date;
  created_at: Date;
  approved_at?: Date | null;
}

// Auth Repository
export class AuthRepository {
  constructor(options?: { db?: any; dialect?: typeof dialect });
  fetchActiveSession(session_id: string): Promise<any>;
  deleteAppSessionById(session_id: string, query_name?: string): Promise<any>;
  deleteSessionBySid(session_id: string, query_name?: string): Promise<any>;
  getSessionsWithUsersByIds(session_ids: string[], query_name?: string): Promise<any[]>;
  touchTrustedDevice(device_token_hash: string, username: string): Promise<any>;
  cleanupAndCountUserSessions(username: string, query_name?: string): Promise<number>;
  deleteOldestSessionsForUser(username: string, limit: number, query_name?: string): Promise<number>;
  deleteExpiredSessionsForUser(username: string): Promise<number>;
  countActiveSessionsForUser(username: string): Promise<number>;
  getOldestSessionIds(username: string, limit: number): Promise<string[]>;
  insertAppSession(username: string, expires_at: Date | string | null, meta?: any): Promise<any>;
  updateLastLoginReturnProfile(username: string): Promise<any>;
  getUserProfileByUsername(username: string, query_name?: string): Promise<any>;
  insertTrustedDevice(input: { username: string; device_token_hash: string; device_name?: string; user_agent?: string; ip_address?: string; expires_at: Date }): Promise<any>;
  getUserWithTwoFA(username: string, query_name?: string): Promise<any>;
  getTwoFASecret(username: string): Promise<any>;
  deleteSessionsByIds(session_ids: string[], query_name?: string): Promise<number>;
  getOAuthUserByProviderId(provider: string, provider_id: string): Promise<any>;
  getApiTokenByHash(token_hash: string, query_name?: string): Promise<any>;
  updateApiTokenLastUsed(token_id: number, query_name?: string | null, min_interval_minutes?: number): Promise<any>;
  getSessionAuthData(session_id: string, query_name?: string): Promise<any>;
  getSessionWithUserById(session_id: string, query_name?: string): Promise<any>;
  getSessionWithUserForReload(session_id: string, query_name?: string): Promise<any>;
  getSessionValidationRow(session_id: string, query_name?: string): Promise<any>;
  getUserFullNameByUsername(username: string, query_name?: string): Promise<string | null | any>;
  getUserImageByUsername(username: string, query_name?: string): Promise<any>;
  getSessionValidity(session_id: string, session_store_sid: string, query_name?: string): Promise<any>;
  deleteAllAppSessions(query_name?: string): Promise<any>;
  deleteActiveSessionStoreRows(query_name?: string): Promise<any>;
}

export const authRepository: AuthRepository;

// API Token Repository
export class ApiTokenRepository {
  constructor(options?: { db?: any; dialect?: typeof dialect });
  listForUser(username: string): Promise<ApiTokenRow[]>;
  countForUser(username: string): Promise<number>;
  insert(
    username: string,
    name: string,
    token_hash: string,
    prefix: string,
    permissions: string | TokenPermissions,
    expires_at?: Date | string | null
  ): Promise<ApiTokenRow>;
  deleteByIdAndUsername(id: number, username: string): Promise<{ rows: { name: string }[]; rowCount: number }>;
  findByTokenHash(token_hash: string): Promise<ApiTokenRow[]>;
  updateLastUsedByHash(token_hash: string): Promise<{ rowCount: number }>;
  listAll(): Promise<ApiTokenRow[]>;
  stats(): Promise<Record<string, number | string>>;
  listForUserAdmin(username: string): Promise<ApiTokenRow[]>;
  findInfoById(id: number): Promise<{ username: string; name: string } | null>;
  deleteById(id: number): Promise<{ rowCount: number }>;
  deleteByIds(ids: number[]): Promise<{ rowCount: number }>;
  deleteAllByUsername(username: string): Promise<{ rowCount: number }>;
  listForUserDetail(username: string): Promise<ApiTokenDetailRow[]>;
}

export const apiTokenRepository: ApiTokenRepository;

// CLI Auth Session Repository
export class CliAuthSessionRepository {
  constructor(options?: { db?: any; dialect?: typeof dialect });
  create(input: {
    device_code_hash: string;
    user_code_hash: string;
    client_name: string;
    profile_id: number;
    expires_at: Date;
  }): Promise<CliAuthSession | null>;
  findByDeviceCodeHash(device_code_hash: string): Promise<CliAuthSession | null>;
  findByUserCodeHash(user_code_hash: string): Promise<CliAuthSession | null>;
  markApproved(id: number, input: { username: string; token_id: number; pending_token: string }): Promise<boolean>;
  markDenied(id: number): Promise<{ rowCount: number }>;
  markExpired(id: number): Promise<{ rowCount: number }>;
  expireStale(now?: Date): Promise<{ rowCount: number }>;
  completeDelivery(id: number): Promise<boolean>;
  deleteById(id: number): Promise<{ rowCount: number }>;
  getProfileById(profile_id: number): Promise<ApiTokenProfile | null>;
  getActiveProfileById(profile_id: number): Promise<ApiTokenProfile | null>;
  getActiveProfileByKey(profile_key: string): Promise<ApiTokenProfile | null>;
}

export const cliAuthSessionRepository: CliAuthSessionRepository;

// --------------------------------------------------------------------------
// Dynamic Permission System
// --------------------------------------------------------------------------

/** Session-cached effective permissions (`req.session.user.permissions`). */
export interface SessionPermissions {
  /** Effective allowed permissions (union of templates + allow overrides, minus denies). */
  allows: string[];
  /** Explicit per-user deny overrides (deny always wins). */
  denies: string[];
}

/** A single permission string: `app:service:action` (segments may be `*`). */
export type PermissionString = string;

export interface CatalogPermissionEntry {
  id: number;
  app_key: string;
  service_key: string;
  action_key: string;
  label?: string;
  is_active: boolean;
  updated_at?: any;
  permission: string;
}

export interface PermissionTemplate {
  id: number;
  name: string;
  permissions: string[];
  created_at?: any;
  updated_at?: any;
}

export interface PermissionOverride {
  permission: string;
  effect: 'allow' | 'deny';
  granted_by?: string | null;
  created_at?: any;
}

/**
 * Define an application's permission manifest. Each action resolves to
 * `appKey:service:action`. App key resolution: `appKey` option >
 * `mbkautheVar.APP_NAME` > `fallbackAppKey`.
 */
export function definePermissions(
  manifest: Record<string, Record<string, string>>,
  options?: { appKey?: string; fallbackAppKey?: string }
): Record<string, Record<string, string>> & {
  __manifest: Record<string, Record<string, string>>;
  __appKey: string;
  __permissions: string[];
};

/** Define permissions shared by every application under the `global` app key. */
export function defineGlobalPermissions(
  manifest: Record<string, Record<string, string>>
): Record<string, Record<string, string>> & {
  __manifest: Record<string, Record<string, string>>;
  __appKey: 'global';
  __permissions: string[];
};

/** Reserved app key used by global permissions. */
export const GLOBAL_APP_KEY: 'global';

/** Built-in catalog permissions shared by every application. */
export const GlobalPermissions: {
  basic: { access: 'global:basic:access' };
};

/** Resolve `service.action` shorthand to `global:service:action`. */
export function resolvePermission(value: any): string;

/** Resolve + normalize the permission app key (see definePermissions). */
export function resolveAppKey(appKey?: string | null, fallbackAppKey?: string | null): string;

/** In-memory (pure, no DB) authorization decision. */
export function hasPermission(
  user: { role?: string; permissions?: SessionPermissions | string[] } | null | undefined,
  required: string
): boolean;

export function permissionMatches(stored: string, required: string): boolean;

export function normalizePermissions(permissions: any): { allows: string[]; denies: string[] };

export function buildEffectivePermissions(input: {
  templates?: Array<string | string[]>;
  allows?: string[];
  denies?: string[];
}): { allows: string[]; denies: string[] };

/**
 * Cap a requested permission set to the permissions held by the owner
 * (used to scope API tokens; a token can never exceed its owner).
 */
export function intersectPermissions(
  held: SessionPermissions | string[] | string | null | undefined,
  requested: string[] | string
): { allows: string[]; denies: string[] };export function collectPermissions(
  permissions: any,
  appKeyOverride?: string | null
): Array<{
  appKey: string;
  serviceKey: string;
  actionKey: string;
  label: string;
  permission: string;
}>;

/** Sync an app manifest into `mbkcore_permission_catalog` (idempotent). */
export function syncAppPermissions(
  Permissions: any,
  options?: { appKey?: string; fallbackAppKey?: string; repository?: any }
): Promise<{ appKey: string; synced: number; deactivated: number }>;

/** Compute + cache a user's effective permissions on the session user object. */
export function attachSessionPermissions(
  sessionUser: { permissions?: any } | null | undefined,
  username: string
): Promise<{ allows: string[]; denies: string[] }>;

export class PermissionRepository extends BaseRepository {
  constructor(options?: { db?: any; dialect?: typeof dialect });
  upsertCatalogPermission(input: { appKey: string; serviceKey: string; actionKey: string; label?: string | null }): Promise<any>;
  deactivateAllCatalogPermissionsForApp(appKey: string): Promise<any>;
  syncCatalogForApp(appKey: string, declared?: Array<{ serviceKey: string; actionKey: string; label?: string }>): Promise<void>;
  listCatalog(): Promise<CatalogPermissionEntry[]>;
  listActiveCatalog(): Promise<CatalogPermissionEntry[]>;
  listCatalogByApp(appKey: string): Promise<CatalogPermissionEntry[]>;
  lookupCatalogPermission(permission: string): Promise<{ permission: string; is_active: boolean } | null>;
  isCatalogPermissionActive(permission: string): Promise<boolean>;
  listTemplates(): Promise<PermissionTemplate[]>;
  getTemplateByName(name: string): Promise<PermissionTemplate | null>;
  createTemplate(name: string, permissions?: string[]): Promise<any>;
  updateTemplatePermissions(name: string, permissions?: string[]): Promise<any>;
  deleteTemplate(name: string): Promise<any>;
  listOverridesForUser(username: string): Promise<PermissionOverride[]>;
  setOverride(username: string, permission: string, effect: 'allow' | 'deny', grantedBy?: string | null): Promise<any>;
  removeOverride(username: string, permission: string): Promise<any>;
  clearOverridesForUser(username: string): Promise<any>;
  getUserPermissionTemplates(username: string): Promise<{ templates: string[]; perm_version: number }>;
  setUserPermissionTemplates(username: string, templateNames?: string[]): Promise<any>;
  bumpPermissionVersion(username: string): Promise<any>;
  computeEffectiveForUser(username: string): Promise<{ templates: string[]; allows: string[]; denies: string[]; perm_version: number }>;
  getTemplatePermissionsByName(names?: string[]): Promise<Array<{ name: string; permissions: string[] }>>;
}

export const permissionRepository: PermissionRepository;

// API Response Types
export interface LoginResponse {
  success: boolean;
  message: string;
  session_id?: string;
  two_factor_required?: boolean;
  redirect_url?: string;
  error_code?: number;
}

export interface LogoutResponse {
  success: boolean;
  message: string;
}

export interface TwoFAVerifyResponse {
  success: boolean;
  message: string;
  session_id?: string;
  redirect_url?: string;
}

export interface ErrorResponse {
  success: false;
  message: string;
  error_code?: number;
}

// Error Render Options
export interface ErrorRenderOptions {
  layout?: boolean;
  code: number | string;
  error: string;
  message: string;
  page?: string;
  pagename?: string;
  details?: string;
  app?: string;
  version?: string;
}

// Middleware Types
export type AuthMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => void | Promise<void>;

// Middleware Functions
export function validateSession(
  req: Request,
  res: Response,
  next: NextFunction,
  strictTokenValidation?: boolean
): void | Promise<void>;

export function validateApiSession(
  req: Request,
  res: Response,
  next: NextFunction
): void | Promise<void>;

export function checkRolePermission(
  requiredRole: UserRole | 'any' | '*' | UserRole[],
  notAllowed?: UserRole
): AuthMiddleware;

export function validateSessionAndRole(
  requiredRole: UserRole | 'any' | '*' | UserRole[],
  notAllowed?: UserRole,
  strictTokenValidation?: boolean
): AuthMiddleware;

// Permission middleware. `service.action` resolves to the global namespace;
// omitting the argument uses global basic access.
export function checkPermission(requiredPermission?: string): AuthMiddleware;
export function validateSessionAndPermission(
  requiredPermission?: string,
  strictTokenValidation?: boolean
): AuthMiddleware;
export const permChk: typeof checkPermission;
export const sessPerm: typeof validateSessionAndPermission;

export const sessVal: typeof validateSession;
export const sessRole: typeof validateSessionAndRole;
export const roleChk: typeof checkRolePermission;

export const strictValidateSession: AuthMiddleware;
export const strictSessVal: typeof strictValidateSession;

export function strictValidateSessionAndRole(
  requiredRole: UserRole | 'any' | '*' | UserRole[],
  notAllowed?: UserRole
): AuthMiddleware;
export const strictSessRole: typeof strictValidateSessionAndRole;

export function authenticate(token: string): AuthMiddleware;

// Reload session user values from DB and refresh cookies.
// Returns true when session is refreshed and valid, false if session invalidated.
export function reloadSessionUser(req: Request, res: Response): Promise<boolean>;

// Session & Security Middlewares
export const sessionConfig: SessionOptions;
export function corsMiddleware(req: Request, res: Response, next: NextFunction): void;
export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void;
export function sessionRestorationMiddleware(req: Request, res: Response, next: NextFunction): void | Promise<void>;
export function sessionCookieSyncMiddleware(req: Request, res: Response, next: NextFunction): void;
export function requestContextMiddleware(req: Request, res: Response, next: NextFunction): void;

// Utility Functions
// Renders an error page — signature is (res, req, options)
export function renderError(
  res: Response,
  req: Request,
  options: ErrorRenderOptions
): Response;

// Return a lightweight context object used to populate templates
export function getUserContext(req: Request): {
  userLoggedIn: boolean;
  user_id: string;
  username: string;
  full_name: string;
  role: string;
  allowed_apps: string[];
};

// Renders a template page with optional layout and data
export function renderPage(
  req: Request,
  res: Response,
  fileLocation: string,
  layout?: boolean,
  data?: Record<string, any>
): Promise<Response>;

export function proxycall(
  req: Request,
  res: Response,
  url: string,
  method?: string,
  headerOption?: Record<string, string>
): Promise<Response>;

export function sanitizeErrorDetails(details: any): string | null;

// Error utilities
export const ErrorCodes: Record<string, number>;
export const ErrorMessages: Record<number, { message: string; userMessage?: string; hint?: string }>;
export function getErrorByCode(errorCode: number, customData?: any): { errorCode: number; message: string; userMessage?: string; hint?: string } & any;
export function createErrorResponse(statusCode: number, errorCode: number, customData?: any): any;
export function logError(context: string, errorCode: number, additionalInfo?: any): void;

// Cookies & Session Management
export function getCookieOptions(): {
  maxAge: number;
  domain?: string;
  secure: boolean;
  sameSite: 'lax';
  path: string;
  httpOnly: boolean;
};

export function resolveCookieDomain(
  isDeployed: 'true' | 'false' | 'f' | string,
  domain?: string,
  isTestDev?: boolean
): string | undefined;

export function getCookieDomain(): string | undefined;

export function getCookieSecure(): boolean;

export function isAllowedOriginHostname(hostname: string, domain?: string): boolean;

export function getClearCookieOptions(): {
  domain?: string;
  secure: boolean;
  sameSite: 'lax';
  path: string;
  httpOnly: boolean;
};

export function generateDeviceToken(): string;

export function getDeviceTokenCookieOptions(): {
  maxAge: number;
  domain?: string;
  secure: boolean;
  sameSite: 'lax';
  path: string;
  httpOnly: boolean;
};

export function hashDeviceToken(token: string): string | null;

export function encryptSessionId(session_id: string): string | null;

export function decryptSessionId(encrypted_session_id: string): string | null;

export function writeAccountList(res: Response, accounts: any[], req?: Request): void;

export function upsertAccountListCookie(req: Request, res: Response, entry: { session_id: string; username: string; full_name?: string; image?: string | null }): void;

export function removeAccountFromCookie(req: Request, res: Response, session_id: string): void;

export function readAccountListFromCookie(req: Request): any[];

export function clearSessionCookies(res: Response): void;

// Security & Hashing
export function setPasswordPepper(pepper: string): void;

export function hashPassword(password: string, username: string): string;

export function verifyPassword(password: string, username: string, password_hash: string): Promise<boolean>;

// Hash an API token (SHA-256 hex) for storage/comparison
export function hashApiToken(token: string): string | null;

// Generate a cryptographically random hex string (default 32 bytes → 64 chars)
export function generateRandomHex(bytes?: number): string;

// Generate a prefixed API token (e.g. "mbk_<64 hex chars>")
export function generatePrefixedToken(prefix?: string): string;

// Version helpers
export function getLatestVersion(options?: { forceRefresh?: boolean }): Promise<string | null>;
export function checkVersion(): Promise<void>;

// Database & Backend Pools
/** A `pg.Pool` when DB_TYPE is 'postgres' (default), or a SqlitePool-shaped adapter when DB_TYPE is 'sqlite'. */
export const dblogin: Pool | {
  query(text: string | { text: string; values?: any[]; name?: string }, values?: any[]): Promise<{ rows: any[]; rowCount: number }>;
  connect(): Promise<{ query: Function; release: () => void }>;
  end(): Promise<void>;
};
export const dbType: 'postgres' | 'sqlite';
/** SQL dialect helpers for the active backend (see lib/db/dialects/). */
export const dialect: {
  name: 'postgres' | 'sqlite';
  quoteIdentifier(name: string): string;
  param(index: number): string;
  now(): string;
  boolean(value: any): string;
  supportsReturning: boolean;
  returningClause(columns: string): string;
  limitOffset(options?: { limit?: number; offset?: number }): string;
  /** `null` on SQLite, which has no table-level lock statement. */
  lockTable: ((tableSql: string, mode?: string) => string) | null;
};

export class Mutex {
  acquire(): Promise<() => void>;
}

export class SqliteClient {
  constructor(db: any, releaseLock: () => void, queryFn?: Function);
  query(queryOrText: string | { text: string; values?: any[]; name?: string }, maybeValues?: any[]): Promise<{ rows: any[]; rowCount: number; command?: string }>;
  release(): void;
}

export interface SqliteAdapterOptions {
  filePath?: string;
  dialect?: any;
  jsonColumns?: string[];
  booleanColumns?: string[];
  timestampColumns?: string[];
}

export class SqliteAdapter {
  constructor(filePathOrDb: string | any, options?: SqliteAdapterOptions);
  dialect: any;
  query(queryOrText: string | { text: string; values?: any[]; name?: string }, maybeValues?: any[]): Promise<{ rows: any[]; rowCount: number; command?: string }>;
  connect(): Promise<SqliteClient>;
  exec(sql: string): void;
  execScript(sql: string): void;
  close(): void;
  end(): Promise<void>;
}

export const SqlitePool: typeof SqliteAdapter;

export class PostgresAdapter {
  pool: Pool;
  dialect: typeof postgresDialect;
  constructor(pool: Pool, dialect?: typeof postgresDialect);
  query(configOrText: string | { text: string; values?: any[]; name?: string }, values?: any[]): Promise<{ rows: any[]; rowCount: number }>;
  connect(): Promise<PoolClient>;
  close(): Promise<void>;
  end(): Promise<void>;
}

export function translatePgToSqlite(text: string, values?: any[]): { text: string; values: any[] };

export const postgresDialect: typeof dialect;
export const sqliteDialect: typeof dialect;

export interface ApplySchemaOptions {
  silent?: boolean;
  name?: string;
}

export function applySchema(
  adapterOrPool: any,
  schemaPathOrSql: string,
  options?: ApplySchemaOptions
): Promise<{ success: boolean }>;

export interface GracefulShutdownOptions {
  signals?: string[];
  timeoutMs?: number;
  onShutdown?: () => void | Promise<void>;
}

export function registerGracefulShutdown(
  targets: any,
  options?: GracefulShutdownOptions
): () => Promise<void>;

export function closeAllConnections(): Promise<void>;

export class BaseRepository {
  db: any;
  dialect: any;
  constructor(options?: { db?: any; dialect?: any });
  execute(name: string, query: { text: string; values?: any[] }): Promise<any>;
  executeRaw(query: { text: string; values?: any[] }): Promise<any>;
  withTransaction<T>(fn: (txRepo: any) => Promise<T>): Promise<T>;
}

export function isJsonRequest(req: Request): boolean;
export function sendSuccess(res: Response, data?: any, options?: { statusCode?: number; message?: string; [key: string]: any }): Response;
export function sendError(res: Response, errorInput: any, options?: { statusCode?: number; code?: string | number; req?: Request; details?: any; errorCode?: number; [key: string]: any }): Response;
export function createErrorHandler(options?: { appName?: string; defaultPage?: string; defaultPageName?: string }): (err: any, req: Request, res: Response, next: NextFunction) => any;
export function createNotFoundHandler(options?: { appName?: string; defaultPage?: string; defaultPageName?: string }): (req: Request, res: Response) => any;
export function renderError(res: Response, req: Request, options: { code: number; error?: string; message?: string; page?: string; pagename?: string; details?: any }): any;
export function renderPage(req: Request, res: Response, fileLocation: string, layout?: boolean, data?: Record<string, any>): Promise<any>;
export function sanitizeErrorDetails(details: any): string | null;

// Configuration Constants
export const mbkautheVar: MBKAuthConfig;
export const appConfig: MBKAuthConfig;
export const cachedCookieOptions: ReturnType<typeof getCookieOptions>;
export const cachedClearCookieOptions: ReturnType<typeof getClearCookieOptions>;
export const packageJson: { version: string; [key: string]: any };
export const appVersion: string;
export const DEVICE_TRUST_DURATION_DAYS: number;
export const DEVICE_TRUST_DURATION_MS: number;

// Routers
export const authRouter: Router;
export const apiTokensRouter: Router;
export const adminApiTokensRouter: Router;
export const cliAuthRouter: Router;

// Default Export (Express Application)
declare const app: ExpressApp;
export default app;