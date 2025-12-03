// Type definitions for mbkauthe
// Project: https://github.com/MIbnEKhalid/mbkauthe
// Definitions by: Muhammad Bin Khalid <https://github.com/MIbnEKhalid>

import { Request, Response, NextFunction, Router } from 'express';
import { Pool } from 'pg';

declare module 'mbkauthe' {
  // Configuration Types
  export interface MBKAuthConfig {
    APP_NAME: string;
    SESSION_SECRET_KEY: string;
    Main_SECRET_TOKEN: string;
    IS_DEPLOYED: 'true' | 'false' | 'f';
    DOMAIN: string;
    LOGIN_DB: string;
    MBKAUTH_TWO_FA_ENABLE: 'true' | 'false' | 'f';
    COOKIE_EXPIRE_TIME?: number;
    DEVICE_TRUST_DURATION_DAYS?: number;
    GITHUB_LOGIN_ENABLED?: 'true' | 'false' | 'f';
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    loginRedirectURL?: string;
    EncPass?: 'true' | 'false' | 'f';
  }

  // User Types
  export type UserRole = 'SuperAdmin' | 'NormalUser' | 'Guest';

  export interface SessionUser {
    id: number;
    username: string;
    UserName: string;
    role: UserRole;
    Role: UserRole;
    sessionId: string;
    allowedApps?: string[];
  }

  export interface PreAuthUser {
    id: number;
    username: string;
    UserName?: string;
    role: UserRole;
    Role?: UserRole;
    loginMethod?: 'password' | 'github';
    redirectUrl?: string | null;
  }

  // Database Types
  export interface DBUser {
    id: number;
    UserName: string;
    Password?: string;
    PasswordEnc?: string;
    Role: UserRole;
    Active: boolean;
    AllowedApps: string[];
    SessionId?: string;
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
    access_token: string;
    created_at: Date;
    updated_at: Date;
  }

  // Request Extensions
  declare global {
    namespace Express {
      interface Request {
        user?: {
          username: string;
          UserName: string;
          role: UserRole;
          Role: UserRole;
        };
      }

      interface Session {
        user?: SessionUser;
        preAuthUser?: PreAuthUser;
        oauthRedirect?: string;
      }
    }
  }

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

  export function checkRolePermission(
    requiredRole: UserRole | 'Any' | 'any',
    notAllowed?: UserRole
  ): AuthMiddleware;

  export function validateSessionAndRole(
    requiredRole: UserRole | 'Any' | 'any',
    notAllowed?: UserRole
  ): AuthMiddleware;

  export function authenticate(token: string): AuthMiddleware;

  export function authapi(requiredRole?: UserRole[]): AuthMiddleware;

  // Utility Functions
  export function renderError(
    res: Response,
    options: ErrorRenderOptions
  ): Response;

  export function getCookieOptions(): {
    maxAge: number;
    domain?: string;
    secure: boolean;
    sameSite: 'lax';
    path: string;
    httpOnly: boolean;
  };

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

  export function clearSessionCookies(res: Response): void;

  // Exports
  export const dblogin: Pool;
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
