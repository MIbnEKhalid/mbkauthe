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
const requiredKeys = ["APP_NAME", "RECAPTCHA_Enabled", "SESSION_SECRET_KEY", "IS_DEPLOYED", "LOGIN_DB", "MBKAUTH_TWO_FA_ENABLE", "DOMAIN"];
requiredKeys.forEach(key => {
  if (!mbkautheVar[key]) {
    throw new Error(`mbkautheVar.${key} is required`);
  }
});
if (mbkautheVar.RECAPTCHA_Enabled === "true") {
  if (mbkautheVar.RECAPTCHA_SECRET_KEY === undefined) {
    throw new Error("mbkautheVar.RECAPTCHA_SECRET_KEY is required");
  }
}
if (mbkautheVar.COOKIE_EXPIRE_TIME !== undefined) {
  const expireTime = parseFloat(mbkautheVar.COOKIE_EXPIRE_TIME);
  if (isNaN(expireTime) || expireTime <= 0) {
    throw new Error("mbkautheVar.COOKIE_EXPIRE_TIME must be a valid positive number");
  }
}
if (mbkautheVar.BypassUsers !== undefined) {
  if (!Array.isArray(mbkautheVar.BypassUsers)) {
    throw new Error("mbkautheVar.BypassUsers must be a valid array");
  }
}

// PostgreSQL connection pool for pool
const poolConfig = {
  connectionString: mbkautheVar.LOGIN_DB,
  ssl: {
    rejectUnauthorized: true,
  },

};

export const dblogin = new Pool(poolConfig);

// Test connection for pool
(async () => {
  try {
    const client = await dblogin.connect();
    console.log("Connected to  PostgreSQL database (pool)!");
    client.release();
  } catch (err) {
    console.error("Database connection error (pool):", err);
  }
})();