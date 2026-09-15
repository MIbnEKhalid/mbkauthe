import type { Request, Response, NextFunction } from "express";
import { runWithRequestContext } from "../../db/pool.js";
import { cachedCookieOptions, cachedClearCookieOptions, decryptSessionId, encryptSessionId, getCookieSecure, isAllowedOriginHostname } from "../../config/cookies.js";
import { authRepository } from "../../db/repositories/AuthRepository.js";
import { isUserAuthorizedForApp } from "../../ui/utils/appAccess.js";
import { attachSessionPermissions } from "../../core/permissions/session.js";

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
  const raw_session_cookie = (req as any).cookies?.session_id;
  if (hasAuthorizationHeader(req) || (req as any).session?.user || !raw_session_cookie) {
    return next();
  }

  const session_id = decryptSessionId(raw_session_cookie);
  if (!session_id || typeof session_id !== "string" || !UUID_REGEX.test(session_id)) {
    res.clearCookie("session_id", cachedClearCookieOptions);
    return next();
  }

  try {
    const row = await authRepository.getSessionWithUserById(session_id, "restore-user-session");
    if (row && (!row.expires_at || new Date(row.expires_at) > new Date()) && row.is_active && isUserAuthorizedForApp(row.role, row.allowed_apps)) {
      (req as any).session.user = {
        session_id: String(session_id),
        user_id: row.user_id || undefined,
        username: row.username,
        full_name: (typeof row.full_name === "string" && row.full_name.trim()) || (typeof (req as any).cookies?.full_name === "string" ? (req as any).cookies.full_name : undefined),
        role: row.role,
        allowed_apps: row.allowed_apps,
      };
      await attachSessionPermissions((req as any).session.user, row.username);
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
    res.cookie("full_name", (req as any).session.user.full_name || (req as any).session.user.username, { ...cachedCookieOptions, httpOnly: false });
    const encrypted = encryptSessionId((req as any).session.user.session_id);
    if (encrypted) {
      res.cookie("session_id", encrypted, cachedCookieOptions);
    }
  }
  next();
}

export function requestContextMiddleware(req: Request, res: Response, next: NextFunction) {
  return runWithRequestContext(req, () => next());
}
