import session from "express-session";
import pgSession from "connect-pg-simple";
import { dblogin } from "../../db/pool.js";
import { mbkautheVar } from "../../config/env.js";
import { getCookieDomain, getCookieSecure } from "../../config/cookies.js";
import { SqliteSessionStore } from "./SqliteSessionStore.js";

const PgSession = pgSession(session);

let _sessionStore: any = null;
export function getSessionStore() {
  if (!_sessionStore) {
    const currentDbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
    _sessionStore = currentDbType === "sqlite"
      ? new SqliteSessionStore({ db: dblogin, tableName: "mbkcore_session", createTableIfMissing: true, disableTouch: true })
      : new PgSession({
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
