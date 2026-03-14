import pkg from "pg";
const { Pool } = pkg;
import { mbkautheVar } from "#config.js";
import dotenv from "dotenv";
dotenv.config();

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

if(process.env.env === 'dev') {
  // Simple counter for all DB requests made via this pool. This is intentionally
  // lightweight.
  let _dbQueryCount = 0;
  const _dbQueryLog = [];
  const _MAX_QUERY_LOG_ENTRIES = 1000;

  const _origQuery = dblogin.query.bind(dblogin);

  dblogin.query = (...args) => {
    _dbQueryCount++;

    // Track query text for debugging/metrics.
    // `pg` supports (text, values, callback) or (config, callback).
    let queryText = '';
    try {
      if (typeof args[0] === 'string') {
        queryText = args[0];
      } else if (args[0] && typeof args[0] === 'object') {
        queryText = args[0].text || '';
      }
    } catch {
      queryText = '';
    }

    if (queryText) {
      _dbQueryLog.push({
        time: new Date().toISOString(),
        query: queryText,
        values: Array.isArray(args[1]) ? args[1] : undefined
      });

      if (_dbQueryLog.length > _MAX_QUERY_LOG_ENTRIES) {
        _dbQueryLog.shift();
      }
    }

    return _origQuery(...args);
  };

  // Public helpers

  dblogin.getQueryCount = () => _dbQueryCount;
  dblogin.resetQueryCount = () => {
    _dbQueryCount = 0;
  };

  dblogin.getQueryLog = (options = {}) => {
    const { limit } = options;
    if (typeof limit === 'number') {
      return _dbQueryLog.slice(-limit);
    }
    return [..._dbQueryLog];
  };

  dblogin.resetQueryLog = () => {
    _dbQueryLog.length = 0;
  };
}

(async () => {
  try {
    const client = await dblogin.connect();
    client.release();
  } catch (err) {
    console.error("[mbkauthe] Database connection error (pool):", err);
  }
})();