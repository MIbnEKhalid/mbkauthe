import pkg from "pg";
import dotenv from "dotenv";
import { mbkautheVar } from "../config/env.js";
import { postgresDialect } from "./dialects/PostgresDialect.js";
import { sqliteDialect } from "./dialects/SqliteDialect.js";
import { SqlitePool } from "./adapters/SqliteAdapter.js";
import { wrapPoolWithRetry } from "./retry.js";
import { attachDevQueryLogger } from "./dbQueryLogger.js";

dotenv.config();
const { Pool } = pkg;

export const dbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
export const dialect = dbType === "sqlite" ? sqliteDialect : postgresDialect;

let _dbloginInstance: any = null;

export function getDbLogin(): any {
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

      _dbloginInstance.on("error", (err: any) => {
        console.error("[mbkauthe:dblogin] Idle client error:", err?.message || err);
      });

      wrapPoolWithRetry(_dbloginInstance, {
        name: `${mbkautheVar.APP_NAME || "app"}:dblogin`,
        maxRetries: Number(process.env.DB_MAX_RETRIES) || 3,
      });
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

export { runWithRequestContext, getRequestContext, attachDevQueryLogger } from "./dbQueryLogger.js";
export default dblogin;
