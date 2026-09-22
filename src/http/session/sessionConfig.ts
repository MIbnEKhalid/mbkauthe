import session from "express-session";
import pgSession from "connect-pg-simple";
import { dblogin } from "../../db/pool.js";
import { mbkautheVar } from "../../config/env.js";
import { getCookieDomain, getCookieSecure } from "../../config/cookies.js";
import { SqliteSessionStore } from "./SqliteSessionStore.js";

const PgSession = pgSession(session);

export class UnifiedPgSessionStore extends PgSession {
  constructor(options?: any) {
    super(options);
  }
  get(sid: string, fn: (err?: any, session?: any) => void) {
    const query = `
      SELECT s.sess, s.expire, s.sid AS session_id, s.expire AS app_session_expires_at,
             u.username, u.user_id, u.is_active, u.is_local_only, u.role, u.allowed_apps, u.full_name, u.image
      FROM "mbkcore_session" s
      LEFT JOIN mbkcore_users u ON u.username = s.username
      WHERE s.sid = $1
      LIMIT 1
    `;
    (this as any).query(query, [sid], (err: any, data: any) => {
      if (err) {
        // Fallback to base get if custom query encounters an issue
        return super.get(sid, fn);
      }
      if (!data) return fn(null);
      try {
        const sessObj = typeof data.sess === "string" ? JSON.parse(data.sess) : data.sess;
        if (data.username && data.session_id) {
          sessObj._liveAuth = {
            session_id: String(data.session_id),
            user_id: data.user_id,
            username: data.username,
            is_active: Boolean(data.is_active),
            is_local_only: Boolean(data.is_local_only && data.is_local_only !== "0" && data.is_local_only !== "false"),
            role: data.role,
            allowed_apps: data.allowed_apps,
            full_name: data.full_name,
            image: data.image,
            expires_at: data.app_session_expires_at || data.expire,
          };
        } else {
          sessObj._liveAuth = null;
        }
        return fn(null, sessObj);
      } catch {
        return (this as any).destroy(sid, fn);
      }
    });
  }

  set(sid: string, sess: any, fn?: (err?: any) => void) {
    const maxAge = sess.cookie?.maxAge;
    const expire = typeof maxAge === "number" ? new Date(Date.now() + maxAge) : new Date(Date.now() + 86400000);
    const username = sess.user?.username ?? null;
    const sessStr = JSON.stringify(sess);

    const query = `
      INSERT INTO "mbkcore_session" (sid, sess, expire, username, last_activity)
      VALUES ($1, $2::json, $3, $4, CURRENT_TIMESTAMP)
      ON CONFLICT (sid) DO UPDATE SET
        sess = EXCLUDED.sess,
        expire = EXCLUDED.expire,
        username = COALESCE(EXCLUDED.username, "mbkcore_session".username),
        last_activity = EXCLUDED.last_activity
    `;
    (this as any).query(query, [sid, sessStr, expire, username], (err: any) => {
      if (fn) fn(err);
    });
  }

  regenerate(req: any, fn: (err?: any) => void): void {
    if (req?.session?.user) {
      (this as any).generate(req);
      fn?.();
    } else {
      (this as any).destroy(req.sessionID, (err: any) => {
        (this as any).generate(req);
        fn?.(err);
      });
    }
  }
}

let _sessionStore: any = null;
export function getSessionStore() {
  if (!_sessionStore) {
    const currentDbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
    _sessionStore = currentDbType === "sqlite"
      ? new SqliteSessionStore({ db: dblogin, tableName: "mbkcore_session", createTableIfMissing: true, disableTouch: true })
      : new UnifiedPgSessionStore({
          pool: dblogin as any,
          tableName: "mbkcore_session",
          createTableIfMissing: true,
          disableTouch: true,
          errorLog: (err: any) => console.warn("[mbkauthe:session] PGStore error:", err?.message || err),
        });
  }
  return _sessionStore;
}

export const sessionConfig: session.SessionOptions = new Proxy({} as session.SessionOptions, {
  get(target: any, prop: string | symbol) {
    if (prop === "store") return getSessionStore();
    if (prop === "secret") return mbkautheVar.SESSION_SECRET_KEY || "default-session-secret";
    if (prop === "genid") return () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
    if (prop === "resave") return false;
    if (prop === "saveUninitialized") return false;
    if (prop === "proxy") return true;
    if (prop === "cookie") {
      return {
        maxAge: (mbkautheVar.COOKIE_EXPIRE_TIME || 2) * 86400000,
        domain: getCookieDomain(),
        httpOnly: true,
        secure: getCookieSecure(),
        sameSite: "lax",
        path: "/",
      };
    }
    if (prop === "name") return "mbkauthe.sid";
    return target[prop];
  },
});

export function hasSessionCookie(req: any): boolean {
  const cookieHeader = req?.headers?.cookie;
  if (!cookieHeader || typeof cookieHeader !== "string") return false;
  const sessionCookieName = mbkautheVar.SESSION_COOKIE_NAME || "mbkauthe.sid";
  return cookieHeader.includes(sessionCookieName) || cookieHeader.includes("session_id");
}

let _sessionMiddleware: any = null;
export function getSessionMiddleware() {
  if (!_sessionMiddleware) {
    _sessionMiddleware = session(sessionConfig);
  }
  return _sessionMiddleware;
}

