/**
 * MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */

import session from "express-session";
import pgSession from "connect-pg-simple";
import { dblogin, dialect, dbType, runWithRequestContext } from "#pool.js";
import { mbkautheVar } from "#config.js";
import { cachedCookieOptions, decryptSessionId, encryptSessionId, cachedClearCookieOptions, getCookieDomain, getCookieSecure, isAllowedOriginHostname } from "#cookies.js";
import { AuthRepository } from "../repositories/AuthRepository.js";
import { isUserAuthorizedForApp } from "../utils/appAccess.js";
import { SqliteSessionStore } from "../session/SqliteSessionStore.js";
import { attachSessionPermissions } from "../permissionSession.js";

const PgSession = pgSession(session);

let _sessionStore = null;
export function getSessionStore() {
  if (!_sessionStore) {
    const currentDbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
    _sessionStore = currentDbType === "sqlite"
      ? new SqliteSessionStore({ db: dblogin, tableName: "mbkcore_session", createTableIfMissing: true, disableTouch: true })
      : new PgSession({
          pool: dblogin,
          tableName: "mbkcore_session",
          createTableIfMissing: true,
          disableTouch: true,
          errorLog: (err) => console.warn("[mbkauthe:session] PGStore error:", err?.message || err),
        });
  }
  return _sessionStore;
}

export const sessionConfig = new Proxy({}, {
  get(target, prop) {
    if (prop === 'store') return getSessionStore();
    if (prop === 'secret') return mbkautheVar.SESSION_SECRET_KEY || 'default-session-secret';
    if (prop === 'resave') return false;
    if (prop === 'saveUninitialized') return false;
    if (prop === 'proxy') return true;
    if (prop === 'cookie') {
      return {
        maxAge: (mbkautheVar.COOKIE_EXPIRE_TIME || 2) * 86400000,
        domain: getCookieDomain(),
        httpOnly: true,
        secure: getCookieSecure(),
        sameSite: 'lax',
        path: '/'
      };
    }
    if (prop === 'name') return 'mbkauthe.sid';
    return target[prop];
  }
});

const authRepo = new AuthRepository({ db: dblogin, dialect });
const hasAuthorizationHeader = (req) => Boolean(req.headers?.authorization?.trim());
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function securityHeadersMiddleware(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (getCookieSecure()) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
}

export function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    try {
      if (isAllowedOriginHostname(new URL(origin).hostname)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      }
    } catch {}
  }
  next();
}

export async function sessionRestorationMiddleware(req, res, next) {
  const raw_session_cookie = req.cookies?.session_id;
  if (hasAuthorizationHeader(req) || req.session.user || !raw_session_cookie) {
    return next();
  }

  const session_id = decryptSessionId(raw_session_cookie);
  if (!session_id || typeof session_id !== 'string' || !UUID_REGEX.test(session_id)) {
    res.clearCookie('session_id', cachedClearCookieOptions);
    return next();
  }

  try {
    const row = await authRepo.getSessionWithUserById(session_id, 'restore-user-session');
    if (row && (!row.expires_at || new Date(row.expires_at) > new Date()) && row.is_active && isUserAuthorizedForApp(row.role, row.allowed_apps)) {
      req.session.user = {
        session_id: String(session_id),
        user_id: row.user_id || undefined,
        username: row.username,
        full_name: (typeof row.full_name === 'string' && row.full_name.trim()) || (typeof req.cookies?.full_name === 'string' ? req.cookies.full_name : undefined),
        role: row.role,
        allowed_apps: row.allowed_apps,
      };
      await attachSessionPermissions(req.session.user, row.username);
    }
  } catch (err) {
    console.error(`[mbkauthe] Session restoration error:`, err);
  }
  next();
}

export function sessionCookieSyncMiddleware(req, res, next) {
  if (hasAuthorizationHeader(req) || req.auth?.type === 'api-token') {
    return next();
  }

  const hasSessionCookie = Boolean(req.cookies?.session_id);
  if (req.session?.user && !hasSessionCookie) {
    res.cookie("full_name", req.session.user.full_name || req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
    const encrypted = encryptSessionId(req.session.user.session_id);
    if (encrypted) {
      res.cookie("session_id", encrypted, cachedCookieOptions);
    }
  }
  next();
}

export function requestContextMiddleware(req, res, next) {
  return runWithRequestContext(req, () => next());
}