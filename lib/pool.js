import pkg from "pg";
const { Pool } = pkg;
import { mbkautheVar } from "#config.js";
import { attachDevQueryLogger, runWithRequestContext, getRequestContext } from "./utils/dbQueryLogger.js";
import dotenv from "dotenv";
dotenv.config();

export { runWithRequestContext, getRequestContext };

const poolConfig = {
  connectionString: mbkautheVar.LOGIN_DB,
  ssl: {
    rejectUnauthorized: true,
  },
  max: 3,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000,
};

export const dblogin = new Pool(poolConfig);

// Keep pool.js focused on pool setup; attach dev-only query logger from dedicated module.
attachDevQueryLogger(dblogin);

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
  } catch (err) {
    console.error("[mbkauthe] Database connection error (pool):", err);
  }
})();
*/