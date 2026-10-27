import pkg from "pg";
import dotenv from "dotenv";
import { mbkautheVar } from "../config/env.js";
import { postgresDialect } from "./dialects/PostgresDialect.js";
import { sqliteDialect } from "./dialects/SqliteDialect.js";
import { SqlitePool } from "./adapters/SqliteAdapter.js";
import { PostgresAdapter } from "./adapters/PostgresAdapter.js";
import { wrapPoolWithRetry } from "./retry.js";
import { attachDevQueryLogger } from "./dbQueryLogger.js";
import { registerGracefulShutdown } from "./shutdown.js";

dotenv.config();
const { Pool } = pkg;

export const dbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
export const dialect = dbType === "sqlite" ? sqliteDialect : postgresDialect;

let _dbloginInstance: any = null;
let _defaultAdapterInstance: any = null;

export function getDbLogin(): any {
  if (!_dbloginInstance || _dbloginInstance.ended) {
    const currentDbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
    if (currentDbType === "sqlite") {
      const sqlitePath = process.env.SQLITE_PATH || mbkautheVar.SQLITE_PATH || "./mbkauthe.sqlite";
      _dbloginInstance = new SqlitePool(sqlitePath);
      registerGracefulShutdown(_dbloginInstance);
    } else {
      const connectionTimeoutMillis = Number(process.env.DB_CONNECTION_TIMEOUT_MS || mbkautheVar.DB_CONNECTION_TIMEOUT_MS) || 15000;
      const idleTimeoutMillis = Number(process.env.DB_IDLE_TIMEOUT_MS || mbkautheVar.DB_IDLE_TIMEOUT_MS) || 30000;
      const statement_timeout = Number(process.env.DB_STATEMENT_TIMEOUT_MS || mbkautheVar.DB_STATEMENT_TIMEOUT_MS) || 30000;
      const max = Number(process.env.DB_MAX_CONNECTIONS || mbkautheVar.DB_MAX_CONNECTIONS) || (process.env.VERCEL ? 3 : 15);

      const connectionString =
        mbkautheVar.LOGIN_DB ||
        process.env.LOGIN_DB ||
        process.env.NEON_POSTGRES ||
        process.env.DATABASE_URL ||
        process.env.POSTGRES_URL;

      const isLocalhost = connectionString?.includes("localhost") || connectionString?.includes("127.0.0.1");
      const ssl = isLocalhost
        ? false
        : (process.env.DB_SSL_REJECT_UNAUTHORIZED === "false" || !process.env.NODE_ENV || process.env.NODE_ENV === "development"
          ? { rejectUnauthorized: false }
          : { rejectUnauthorized: true });

      _dbloginInstance = new Pool({
        connectionString,
        ssl,
        max,
        idleTimeoutMillis,
        connectionTimeoutMillis,
        statement_timeout,
        keepAlive: true,
        keepAliveInitialDelayMillis: 10000,
        application_name: `${mbkautheVar.APP_NAME || "app"}-mbkauthe-app`,
      });

      _dbloginInstance.on("error", (err: any) => {
        console.error("[mbkauthe:dblogin] Idle client error:", err?.message || err);
      });

      wrapPoolWithRetry(_dbloginInstance, {
        name: `${mbkautheVar.APP_NAME || "app"}:dblogin`,
        maxRetries: Number(process.env.DB_MAX_RETRIES) || 3,
      });

      registerGracefulShutdown(_dbloginInstance);
    }

    attachDevQueryLogger(_dbloginInstance);
  }
  return _dbloginInstance;
}

export const dblogin: any = new Proxy({}, {
  get(target, prop) {
    const instance = getDbLogin();
    const val = Reflect.get(instance, prop, instance);
    return typeof val === "function" ? val.bind(instance) : val;
  },
  set(target, prop, value) {
    return Reflect.set(getDbLogin(), prop, value, getDbLogin());
  },
  has(target, prop) {
    return Reflect.has(getDbLogin(), prop);
  }
});

export function getDefaultAdapter(): any {
  const currentDbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
  const login = getDbLogin();
  if (currentDbType === "sqlite") {
    return login;
  }
  if (!_defaultAdapterInstance || _defaultAdapterInstance.pool !== login) {
    _defaultAdapterInstance = new PostgresAdapter(login, postgresDialect);
  }
  return _defaultAdapterInstance;
}

export const defaultAdapter: any = new Proxy({}, {
  get(target, prop) {
    const instance = getDefaultAdapter();
    const val = Reflect.get(instance, prop, instance);
    return typeof val === "function" ? val.bind(instance) : val;
  },
  set(target, prop, value) {
    return Reflect.set(getDefaultAdapter(), prop, value, getDefaultAdapter());
  },
  has(target, prop) {
    return Reflect.has(getDefaultAdapter(), prop);
  }
});

export { runWithRequestContext, getRequestContext, attachDevQueryLogger } from "./dbQueryLogger.js";
export default dblogin;
