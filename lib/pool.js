import pkg from "pg";
const { Pool } = pkg;

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

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