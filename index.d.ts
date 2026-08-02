// Type definitions for mbkauthe
// Project: https://github.com/MIbnEKhalid/mbkauthe
// Definitions by: Muhammad Bin Khalid <https://github.com/MIbnEKhalid>

import { Request, Response, NextFunction, Router } from 'express';
import { Pool } from 'pg';

// Global augmentations must be at the top level, outside any declare module blocks
declare global {
  namespace Express {
    interface Request {
      user?: {
        username: string;
        role: 'SuperAdmin' | 'NormalUser' | 'Guest';
        fullname?: string;
      };
      userRole?: 'SuperAdmin' | 'NormalUser' | 'Guest';
    }

    interface Session {
      user?: {
        userId?: string;
        username: string;
        fullname?: string;
        role: 'SuperAdmin' | 'NormalUser' | 'Guest';
        sessionId?: string;
        allowedApps?: string[];
        tokenScope?: 'read-only' | 'write' | null;
      };
      preAuthUser?: {
        userId?: string;
        username: string;
        role: 'SuperAdmin' | 'NormalUser' | 'Guest';
        loginMethod?: 'password' | 'github' | 'google';
        redirectUrl?: string | null;
        allowedApps?: string[];
      };
      oauthRedirect?: string;
      oauthCsrfToken?: string;
      [key: string]: any;
    }
  }
}

declare module 'mbkauthe' {
  // Configuration Types
  export interface MBKAuthConfig {
    APP_NAME: string;
    SESSION_SECRET_KEY: string;
    Main_SECRET_TOKEN: string;
    IS_DEPLOYED: 'true' | 'false' | 'f';
    DOMAIN: string;
    /** Defaults to 'postgres'. Set to 'sqlite' to use the SQLite backend instead. */
    DB_TYPE?: 'postgres' | 'sqlite';
    /** Required when DB_TYPE is 'postgres' (default). */
    LOGIN_DB?: string;
    /** Required when DB_TYPE is 'sqlite'. Path to the SQLite database file. */
    SQLITE_PATH?: string;
    MBKAUTH_TWO_FA_ENABLE: 'true' | 'false' | 'f';
    COOKIE_EXPIRE_TIME?: number;
    DEVICE_TRUST_DURATION_DAYS?: number;
    GITHUB_LOGIN_ENABLED?: 'true' | 'false' | 'f';
    GITHUB_APP_CLIENT_ID?: string;
    GITHUB_APP_CLIENT_SECRET?: string;
    GOOGLE_LOGIN_ENABLED?: 'true' | 'false' | 'f';
    GOOGLE_CLIENT_ID?: string;
    GOOGLE_CLIENT_SECRET?: string;
    loginRedirectURL?: string;
    MAX_SESSIONS_PER_USER?: number;
    /**
     * Optional absolute base URL (no trailing slash) used to build the CLI
     * device-flow verification URL, e.g. "https://portal.mbktech.org".
     * Falls back to https://DOMAIN when IS_DEPLOYED, or the request host in dev.
     */
    CLI_AUTH_BASE_URL?: string;
    /**
     * Attach the CLI / device-flow login to the main router. Defaults to 'true'.
     * Set 'false' to disable it.
     */
    CLI_AUTH_ENABLED?: 'true' | 'false' | 'f';
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
  export type UserRole = 'SuperAdmin' | 'NormalUser' | 'Guest';

  export interface SessionUser {
    userId?: string;
    username: string;
    fullname?: string;
    role: UserRole;
    sessionId?: string;
    allowedApps?: string[];
  }

  export interface PreAuthUser {
    userId?: string;
    username: string;
    role: UserRole;
    allowedApps?: string[];
    loginMethod?: 'password' | 'github' | 'google';
    redirectUrl?: string | null;
  }

  // Database Types
  export interface DBUser {
    id: number;
    UserName: string;
    UserId?: string;
    PasswordEnc?: string;
    Role: UserRole;
    Active: boolean;
    AllowedApps: string[];

    created_at?: Date;
    updated_at?: Date;
    last_login?: Date;
  }

  export interface TwoFARecord {
    UserName: string;
    TwoFAStatus: boolean;
    TwoFASecret?: string;
  }

  export interface TrustedDevice {
    id: number;
    UserName: string;
    DeviceToken: string;
    DeviceName?: string;
    UserAgent?: string;
    IpAddress?: string;
    CreatedAt: Date;
    ExpiresAt: Date;
    LastUsed: Date;
  }

  export interface GitHubUser {
    id: number;
    user_name: string;
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
    user_name: string;
    google_id: string;
    google_email: string;
    access_token: string;
    created_at: Date;
    updated_at: Date;
  }

  // API Token Types
  export type TokenScope = 'read-only' | 'write';
  
  export interface TokenPermissions {
    scope: TokenScope;
    allowedApps: string[] | null;
  }

  export interface ApiToken {
    id: number;
    UserName: string;
    Name: string;
    TokenHash: string;
    Prefix: string;
    Permissions: TokenPermissions;
    LastUsed?: Date;
    CreatedAt: Date;
    ExpiresAt?: Date;
  }

  /** A token row as returned by the list/admin repository methods (Scope/AllowedApps derived from Permissions). */
  export interface ApiTokenRow {
    id: number;
    Name: string;
    Prefix: string;
    Scope: TokenScope;
    AllowedApps: string[] | null;
    Permissions?: TokenPermissions;
    LastUsed?: Date;
    CreatedAt?: Date;
    ExpiresAt?: Date;
    UserName?: string;
    email?: string;
    Role?: string;
    FullName?: string;
  }

  /** A token row as returned by listForUserDetail (admin user detail page). */
  export interface ApiTokenDetailRow {
    id: number;
    Name: string;
    Prefix: string;
    LastUsed?: Date;
    formatted_created: string;
    formatted_expires: string;
    is_active: boolean;
    Permissions: TokenPermissions;
  }

  // API Token Repository
  export class ApiTokenRepository {
    constructor(options?: { db?: any; dialect?: typeof dialect });
    listForUser(username: string): Promise<ApiTokenRow[]>;
    countForUser(username: string): Promise<number>;
    insert(
      username: string,
      name: string,
      tokenHash: string,
      prefix: string,
      permissions: string | TokenPermissions,
      expiresAt?: Date | string | null
    ): Promise<ApiTokenRow>;
    deleteByIdAndUsername(id: number, username: string): Promise<{ rows: { Name: string }[]; rowCount: number }>;
    findByTokenHash(tokenHash: string): Promise<ApiTokenRow[]>;
    updateLastUsedByHash(tokenHash: string): Promise<{ rowCount: number }>;
    listAll(): Promise<ApiTokenRow[]>;
    stats(): Promise<Record<string, number | string>>;
    listForUserAdmin(username: string): Promise<ApiTokenRow[]>;
    findInfoById(id: number): Promise<{ UserName: string; Name: string } | null>;
    deleteById(id: number): Promise<{ rowCount: number }>;
    deleteAllByUsername(username: string): Promise<{ rowCount: number }>;
    listForUserDetail(username: string): Promise<ApiTokenDetailRow[]>;
  }

  export const apiTokenRepository: ApiTokenRepository;

  // API token routers (mounted by host apps; page views are provided by the host)
  export const apiTokensRouter: Router;
  export const adminApiTokensRouter: Router;

  // CLI / Device-flow auth types
  export type CliAuthStatus = 'pending' | 'approved' | 'completed' | 'denied' | 'expired';

  export interface ApiTokenProfile {
    id: number;
    /** Public random key (>= 6 chars) that CLIs use instead of the serial id. */
    ProfileKey?: string | null;
    Name: string;
    Description?: string | null;
    AllowedApps?: string[] | null;
    Scope: TokenScope;
    ExpiresInDays?: number | null;
    Active?: boolean;
    CreatedAt?: Date;
    UpdatedAt?: Date;
  }

  export interface CliAuthSession {
    id: number;
    DeviceCodeHash: string;
    UserCodeHash: string;
    ClientName: string;
    ProfileId: number;
    UserName?: string | null;
    TokenId?: number | null;
    PendingToken?: string | null;
    Status: CliAuthStatus;
    ExpiresAt: Date;
    CreatedAt: Date;
    ApprovedAt?: Date | null;
  }

  export class CliAuthSessionRepository {
    constructor(options?: { db?: any; dialect?: typeof dialect });
    create(input: {
      deviceCodeHash: string;
      userCodeHash: string;
      clientName: string;
      profileId: number;
      expiresAt: Date;
    }): Promise<CliAuthSession | null>;
    findByDeviceCodeHash(deviceCodeHash: string): Promise<CliAuthSession | null>;
    findByUserCodeHash(userCodeHash: string): Promise<CliAuthSession | null>;
    markApproved(id: number, input: { userName: string; tokenId: number; pendingToken: string }): Promise<boolean>;
    markDenied(id: number): Promise<{ rowCount: number }>;
    markExpired(id: number): Promise<{ rowCount: number }>;
    expireStale(now?: Date): Promise<{ rowCount: number }>;
    completeDelivery(id: number): Promise<boolean>;
    deleteById(id: number): Promise<{ rowCount: number }>;
    getProfileById(profileId: number): Promise<ApiTokenProfile | null>;
    getActiveProfileById(profileId: number): Promise<ApiTokenProfile | null>;
    getActiveProfileByKey(profileKey: string): Promise<ApiTokenProfile | null>;
  }

  export const cliAuthSessionRepository: CliAuthSessionRepository;

  /** CLI / device-flow auth router (browser login + token polling). Mount at root. */
  export const cliAuthRouter: Router;

  // API Response Types
  export interface LoginResponse {
    success: boolean;
    message: string;
    sessionId?: string;
    twoFactorRequired?: boolean;
    redirectUrl?: string;
    errorCode?: number;
  }

  export interface LogoutResponse {
    success: boolean;
    message: string;
  }

  export interface TwoFAVerifyResponse {
    success: boolean;
    message: string;
    sessionId?: string;
    redirectUrl?: string;
  }

  export interface ErrorResponse {
    success: false;
    message: string;
    errorCode?: number;
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
    next: NextFunction
  ): void | Promise<void>;

  export function validateApiSession(
    req: Request,
    res: Response,
    next: NextFunction
  ): void | Promise<void>;

  export function checkRolePermission(
    requiredRole: UserRole | 'Any' | 'any',
    notAllowed?: UserRole
  ): AuthMiddleware;

  export function validateSessionAndRole(
    requiredRole: UserRole | 'Any' | 'any',
    notAllowed?: UserRole
  ): AuthMiddleware;

  export const sessVal: AuthMiddleware;
  export const sessRole: AuthMiddleware;

  export const strictValidateSession: AuthMiddleware;

  export function strictValidateSessionAndRole(
    requiredRole: UserRole | 'Any' | 'any',
    notAllowed?: UserRole
  ): AuthMiddleware;

  export function authenticate(token: string): AuthMiddleware;

  // Reload session user values from DB and refresh cookies.
  // Returns true when session is refreshed and valid, false if session invalidated.
  export function reloadSessionUser(req: Request, res: Response): Promise<boolean>;

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
    isuserlogin: boolean;
    username: string;
    fullname: string;
    role: string;
    allowedApps: string[];
  };

  // Renders a template page with optional layout and data
  export function renderPage(
    req: Request,
    res: Response,
    fileLocation: string,
    layout?: boolean,
    data?: Record<string, any>
  ): Promise<Response>;

  // Error utilities
  export const ErrorCodes: { [key: string]: number };
  export const ErrorMessages: { [key: number]: { message: string; userMessage?: string; hint?: string } };
  export function getErrorByCode(errorCode: number, customData?: any): { errorCode: number; message: string; userMessage?: string; hint?: string } & any;
  export function createErrorResponse(statusCode: number, errorCode: number, customData?: any): any;
  export function logError(context: string, errorCode: number, additionalInfo?: any): void;

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

  export function hashPassword(password: string, username: string): string;

  export function verifyPassword(password: string, username: string, storedHash: string): Promise<boolean>;

  // Hash an API token (SHA-256 hex) for storage/comparison
  export function hashApiToken(token: string): string | null;

  // Generate a cryptographically random hex string (default 32 bytes → 64 chars)
  export function generateRandomHex(bytes?: number): string;

  // Generate a prefixed API token (e.g. "mbk_<64 hex chars>")
  export function generatePrefixedToken(prefix?: string): string;

  export function clearSessionCookies(res: Response): void;

  export function getLatestVersion(): Promise<string>;

  // Exports
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
  export const mbkautheVar: MBKAuthConfig;
  export const cachedCookieOptions: ReturnType<typeof getCookieOptions>;
  export const cachedClearCookieOptions: ReturnType<typeof getClearCookieOptions>;
  export const packageJson: { version: string; [key: string]: any };
  export const appVersion: string;
  export const DEVICE_TRUST_DURATION_DAYS: number;
  export const DEVICE_TRUST_DURATION_MS: number;

  // Default Export (Express Router)
  const router: Router;
  export default router;
}
