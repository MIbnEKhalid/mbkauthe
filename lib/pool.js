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

export const dblogin = dbType === "sqlite"
  ? new SqlitePool(mbkautheVar.SQLITE_PATH)
  : new Pool({
      connectionString: mbkautheVar.LOGIN_DB,
      ssl: { rejectUnauthorized: true },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
      statement_timeout: 15000,
      keepAlive: true,
      keepAliveInitialDelayMillis: 10000,
      application_name: `${mbkautheVar.APP_NAME}-mbkauthe-app`,
    });

if (dbType !== "sqlite") {
  dblogin.on("error", (err) => {
    console.error("[mbkauthe:dblogin] Idle client error:", err.message);
  });
  attachDevQueryLogger(dblogin);
}

