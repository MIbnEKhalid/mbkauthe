import pkg from "pg";
const { Pool } = pkg;
import { mbkautheVar } from "./config.js";

const poolConfig = {
  connectionString: mbkautheVar.LOGIN_DB,
  ssl: {
    rejectUnauthorized: true,
  },

  // Connection pool tuning for serverless/ephemeral environments (Vercel)
  // - keep max small to avoid exhausting DB connections
  // - reduce idle time so connections are returned sooner
  // - set a short connection timeout to fail fast
  max: 10,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 25000,
};

export const dblogin = new Pool(poolConfig);

(async () => {
  try {
    const client = await dblogin.connect();
    client.release();
  } catch (err) {
    console.error("[mbkauthe] Database connection error (pool):", err);
  }
})();