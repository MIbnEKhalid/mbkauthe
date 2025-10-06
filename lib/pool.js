import pkg from "pg";
const { Pool } = pkg;

import dotenv from "dotenv";
dotenv.config();

let mbkautheVar;
try {
  mbkautheVar = JSON.parse(process.env.mbkautheVar);
} catch (error) {
  throw new Error("Invalid JSON in process.env.mbkautheVar");
}
if (!mbkautheVar) {
  throw new Error("mbkautheVar is not defined");
}
const requiredKeys = ["APP_NAME", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];
requiredKeys.forEach(key => {
    if (!mbkautheVar[key]) {
        throw new Error(`mbkautheVar.${key} is required`);
    }
});
if (mbkautheVar.COOKIE_EXPIRE_TIME !== undefined) {
    const expireTime = parseFloat(mbkautheVar.COOKIE_EXPIRE_TIME);
    if (isNaN(expireTime) || expireTime <= 0) {
        throw new Error("mbkautheVar.COOKIE_EXPIRE_TIME must be a valid positive number");
    }
}

const poolConfig = {
  connectionString: mbkautheVar.LOGIN_DB,
  ssl: {
    rejectUnauthorized: true,
  },

  // Connection pool tuning for serverless/ephemeral environments (Vercel)
  // - keep max small to avoid exhausting DB connections
  // - reduce idle time so connections are returned sooner
  // - set a short connection timeout to fail fast
  max: 6,
  idleTimeoutMillis: 50000,
  connectionTimeoutMillis: 5000,
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