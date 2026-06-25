import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import { dblogin, runWithRequestContext } from "#pool.js";
import { mbkautheVar } from "#config.js";
import { cachedCookieOptions, decryptSessionId, encryptSessionId, cachedClearCookieOptions, getCookieDomain, getCookieSecure, isAllowedOriginHostname } from "#cookies.js";
import { AuthRepository } from "../db/AuthRepository.js";

// Session configuration
export const sessionConfig = {
  store: new PgSession({
    pool: dblogin,
    tableName: "session",
    createTableIfMissing: true,
    // Prevent connect-pg-simple from touching the session row on every request.
    // This avoids an UPDATE per request, which can significantly reduce DB load under burst traffic.
    // The session will still expire based on the cookie maxAge and the TTL stored when the session is saved.
    disableTouch: true
  }),
  secret: mbkautheVar.SESSION_SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
    // Don't set domain in development/localhost to avoid cookie issues
    domain: getCookieDomain(),
    httpOnly: true,
    // Only use secure cookies in production with HTTPS
    secure: getCookieSecure(),
    sameSite: 'lax',
    path: '/'
  },
  name: 'mbkauthe.sid'
};

const authRepo = new AuthRepository({ db: dblogin });
const hasAuthorizationHeader = (req) => typeof req.headers?.authorization === 'string' && req.headers.authorization.trim().length > 0;

// CORS middleware
export function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    try {
      const originUrl = new URL(origin);
      if (isAllowedOriginHostname(originUrl.hostname)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      }
    } catch (err) {
      // Invalid origin URL, skip CORS headers
    }
  }
  next();
}

// Session restoration middleware
export async function sessionRestorationMiddleware(req, res, next) {
  if (hasAuthorizationHeader(req)) {
    return next();
  }

  // Only restore session if not already present and sessionId cookie exists
  if (!req.session.user && req.cookies.sessionId) {
    // Decrypt the sessionId from cookie
    const sessionId = decryptSessionId(req.cookies.sessionId);

    // Early validation to avoid unnecessary processing (expect DB UUID id)
    if (!sessionId || typeof sessionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
      // Clear invalid cookie to prevent repeated attempts
      res.clearCookie('sessionId', cachedClearCookieOptions);
      return next();
    }

    try {
      // Validate session by DB primary key id and join to user
      const row = await authRepo.getSessionWithUserById(sessionId, 'restore-user-session');

      if (row) {
        // Reject expired sessions or inactive users
        if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
          // leave cookies cleared and don't restore session
        } else {
          const normalizedSessionId = String(sessionId);
          req.session.user = {
            id: row.uid,
            username: row.UserName,
            role: row.Role,
            sessionId: normalizedSessionId,
            allowedApps: row.AllowedApps,
          };

          if (typeof row.FullName === 'string' && row.FullName.trim() !== '') {
            req.session.user.fullname = row.FullName;
          } else if (req.cookies && typeof req.cookies.fullName === 'string') {
            req.session.user.fullname = req.cookies.fullName;
          }
        }
      }
    } catch (err) {
      console.error(`[mbkauthe] Session restoration error:`, err);
    }
  }
  next();
}

// Session cookie sync middleware
export function sessionCookieSyncMiddleware(req, res, next) {
  if (hasAuthorizationHeader(req) || req.auth?.type === 'api-token') {
    return next();
  }

  if (req.session && req.session.user) {
    if (!req.cookies.sessionId) {
      res.cookie("fullName", req.session.user.fullname || req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      const encryptedSessionId = encryptSessionId(req.session.user.sessionId);
      if (encryptedSessionId) {
        res.cookie("sessionId", encryptedSessionId, cachedCookieOptions);
      }
    }
  }
  next();
}

// Request context middleware (used for DB query logging)
export function requestContextMiddleware(req, res, next) {
  return runWithRequestContext(req, () => next());
}