import pkg from "pg";
import dotenv from "dotenv";
import { mbkautheVar } from "#config.js";
import { attachDevQueryLogger, runWithRequestContext, getRequestContext } from "./utils/dbQueryLogger.js";
import { postgresDialect } from "./db/dialects/postgres.js";
import { sqliteDialect } from "./db/dialects/sqlite.js";
import { SqlitePool } from "./db/sqlitePool.js";

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
      _dbloginInstance = new Pool({
        connectionString: mbkautheVar.LOGIN_DB,
        ssl: { rejectUnauthorized: true },
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
        statement_timeout: 15000,
        keepAlive: true,
        keepAliveInitialDelayMillis: 10000,
        application_name: `${mbkautheVar.APP_NAME || "app"}-mbkauthe-app`,
      });
      _dbloginInstance.on("error", (err) => console.error("[mbkauthe:dblogin] Idle client error:", err.message));
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
