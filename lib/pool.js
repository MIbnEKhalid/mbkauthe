import pkg from "pg";
const { Pool } = pkg;
import { mbkautheVar } from "#config.js";
import { attachDevQueryLogger, runWithRequestContext, getRequestContext } from "./utils/dbQueryLogger.js";
import { postgresDialect } from "./db/dialects/postgres.js";
import { sqliteDialect } from "./db/dialects/sqlite.js";
import { SqlitePool } from "./db/sqlitePool.js";
import dotenv from "dotenv";
dotenv.config();

export { runWithRequestContext, getRequestContext };

export const dbType = (mbkautheVar.DB_TYPE || "postgres").toLowerCase();
export const dialect = dbType === "sqlite" ? sqliteDialect : postgresDialect;

let dblogin;

if (dbType === "sqlite") {
  dblogin = new SqlitePool(mbkautheVar.SQLITE_PATH);
} else {
  const poolConfig = {
    connectionString: mbkautheVar.LOGIN_DB,
    ssl: { rejectUnauthorized: true },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    application_name: `${mbkautheVar.APP_NAME}-mbkauthe-app`,
  };

  dblogin = new Pool(poolConfig);

  // Keep pool.js focused on pool setup; attach dev-only query logger from dedicated module.
  // Only meaningful for the pg driver's event-emitter based pool.
  attachDevQueryLogger(dblogin);
}

export { dblogin };

/*
 attachDevQueryLogger([
  { pool: dblogin, name: "loginDB" },
  { pool: dblogin1, name: "loginDB1" },
]);
*/

/*
(async () => {
  try {
    const client = await dblogin.connect();
    client.release();
    console.log(`[mbkauthe] Database connection pool established successfully.`);
  } catch (err) {
    console.error(`[mbkauthe] Database connection error (pool):`, err);
  }
})();
*/
