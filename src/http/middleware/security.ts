import type { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import { runWithRequestContext } from "../../db/pool.js";
import { getCookieOptions, getClearCookieOptions, decryptSessionId, encryptSessionId, getCookieSecure, isAllowedOriginHostname } from "../../config/cookies.js";
import { isProductionEnvironment } from "../../config/env.js";
import { isLocalOnlyUser } from "../../core/types/user.types.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { isUserAuthorizedForApp } from "../utils/appAccess.js";
import { attachSessionPermissions } from "../session/sessionPermissions.js";
import { getSessionMiddleware } from "../session/sessionConfig.js";

const hasAuthorizationHeader = (req: Request) => Boolean(req.headers?.authorization?.trim());
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (getCookieSecure()) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
}

export function corsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  if (origin && typeof origin === "string") {
    try {
      if (isAllowedOriginHostname(new URL(origin).hostname)) {
        res.header("Access-Control-Allow-Origin", origin);
        res.header("Access-Control-Allow-Credentials", "true");
        res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
      }
    } catch {}
  }
  next();
}

export async function sessionRestorationMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (hasAuthorizationHeader(req) || (req as any).session?.user) {
    return next();
  }

  const raw_session_cookie = (req as any).cookies?.session_id;
  if (!raw_session_cookie) {
    return next();
  }

  const session_id = decryptSessionId(raw_session_cookie);
  if (!session_id || typeof session_id !== "string" || !UUID_REGEX.test(session_id)) {
    res.clearCookie("session_id", getClearCookieOptions());
    return next();
  }

  try {
    const row = await authRepository.getSessionWithUserById(session_id, "restore-user-session");
    const isLocalOnly = isLocalOnlyUser(row?.is_local_only);
    if (row && (!row.expires_at || new Date(row.expires_at) > new Date()) && row.is_active && !(isLocalOnly && isProductionEnvironment()) && isUserAuthorizedForApp(row.role, row.allowed_apps)) {
      (req as any).session.user = {
        session_id: String(session_id),
        user_id: row.user_id || undefined,
        username: row.username,
        full_name: (typeof row.full_name === "string" && row.full_name.trim()) || (typeof (req as any).cookies?.full_name === "string" ? (req as any).cookies.full_name : undefined),
        role: row.role,
        allowed_apps: row.allowed_apps,
        is_local_only: isLocalOnly,
      };
      await attachSessionPermissions((req as any).session.user, row.username, row.role);
    }
  } catch (err) {
    console.error(`[mbkauthe] Session restoration error:`, err);
  }
  next();
}

export function sessionCookieSyncMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (hasAuthorizationHeader(req) || (req as any).auth?.type === "api-token") {
    return next();
  }

  const hasSessionCookie = Boolean((req as any).cookies?.session_id);
  if ((req as any).session?.user && !hasSessionCookie) {
    res.cookie("full_name", (req as any).session.user.full_name || (req as any).session.user.username, { ...getCookieOptions(), httpOnly: false });
    const encrypted = encryptSessionId((req as any).session.user.session_id);
    if (encrypted) {
      res.cookie("session_id", encrypted, getCookieOptions());
    }
  }
  next();
}

/**
 * Ensures session middleware and cookie synchronization are initialized on-demand.
 * ONLY called on protected routes (via authMiddleware) or dedicated auth endpoints (authRoutes, oauthRoutes).
 * Unprotected routes never invoke this, ensuring zero database session queries across all apps.
 */
export function ensureSession(req: Request, res: Response, next: NextFunction): void {
  if (hasAuthorizationHeader(req) || (req as any).session) {
    return next();
  }
  const initCookies = (done: () => void) => {
    if (!(req as any).cookies) {
      cookieParser()(req, res, done);
    } else {
      done();
    }
  };
  initCookies(() => {
    getSessionMiddleware()(req, res, (err: any) => {
      if (err) return next(err);
      sessionRestorationMiddleware(req, res, (err2: any) => {
        if (err2) return next(err2);
        sessionCookieSyncMiddleware(req, res, next);
      });
    });
  });
}

export async function ensureSessionAsync(req: Request, res: Response): Promise<void> {
  if (hasAuthorizationHeader(req) || (req as any).session) {
    return;
  }
  return new Promise<void>((resolve, reject) => {
    ensureSession(req, res, (err: any) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

export function requestContextMiddleware(req: Request, res: Response, next: NextFunction) {
  return runWithRequestContext(req, () => next());
}
