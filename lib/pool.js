import pkg from "pg";
import dotenv from "dotenv";
import { mbkautheVar } from "#config.js";
import { attachDevQueryLogger, runWithRequestContext, getRequestContext } from "./utils/dbQueryLogger.js";
import { postgresDialect } from "./db/dialects/postgres.js";
import { sqliteDialect } from "./db/dialects/sqlite.js";
import { SqlitePool } from "./db/sqlitePool.js";
import { wrapPoolWithRetry } from "./db/retry.js";

dotenv.config();
const { Pool } = pkg;

export { runWithRequestContext, getRequestContext };

export const dbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
export const dialect = dbType === "sqlite" ? sqliteDialect : postgresDialect;

let _dbloginInstance = null;

export function getDbLogin() {
  if (!_dbloginInstance) {
    const currentDbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
    if (currentDbType === "sqlite") {
      _dbloginInstance = new SqlitePool(mbkautheVar.SQLITE_PATH || "./mbkauthe.sqlite");
    } else {
      const connectionTimeoutMillis = Number(process.env.DB_CONNECTION_TIMEOUT_MS || mbkautheVar.DB_CONNECTION_TIMEOUT_MS) || 15000;
      const idleTimeoutMillis = Number(process.env.DB_IDLE_TIMEOUT_MS || mbkautheVar.DB_IDLE_TIMEOUT_MS) || 30000;
      const statement_timeout = Number(process.env.DB_STATEMENT_TIMEOUT_MS || mbkautheVar.DB_STATEMENT_TIMEOUT_MS) || 30000;
      const max = Number(process.env.DB_MAX_CONNECTIONS || mbkautheVar.DB_MAX_CONNECTIONS) || 10;

      _dbloginInstance = new Pool({
        connectionString: mbkautheVar.LOGIN_DB,
        ssl: { rejectUnauthorized: true },
        max,
        idleTimeoutMillis,
        connectionTimeoutMillis,
        statement_timeout,
        keepAlive: true,
        keepAliveInitialDelayMillis: 10000,
        application_name: `${mbkautheVar.APP_NAME || "app"}-mbkauthe-app`,
      });

      _dbloginInstance.on("error", (err) => {
        console.error("[mbkauthe:dblogin] Idle client error:", err?.message || err);
      });

      wrapPoolWithRetry(_dbloginInstance, {
        name: `${mbkautheVar.APP_NAME || "app"}:dblogin`,
        maxRetries: Number(process.env.DB_MAX_RETRIES) || 3,
      });

      attachDevQueryLogger(_dbloginInstance);
    }
  }
  return _dbloginInstance;
}

export const dblogin = new Proxy({}, {
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
